#define _GNU_SOURCE
/* Root-owned fixed gateway. Only this broker owns the filesystem fanotify FD.
 * Python receives read-only descriptors only for the administrator-configured target.
 * No caller-supplied command, path, environment or executable is trusted by root. */
#include <sys/fanotify.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <grp.h>
#include <mntent.h>
#include <poll.h>
#include <signal.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <errno.h>
#include <time.h>

#define MAX_FS 128
#define MAX_PENDING 128
#ifndef DLP_PERMISSION_SECONDS
#define DLP_PERMISSION_SECONDS 30
#endif
#include "gateway_config.h"
struct message { uint64_t mask; int32_t token, pid; };
struct answer { int32_t token; uint32_t decision; };
struct pending { int fd; int32_t token; time_t since; };
static volatile sig_atomic_t stopping=0;
static time_t monotonic_seconds(void) {
    struct timespec ts;
    if (clock_gettime(CLOCK_MONOTONIC,&ts)) return 0;
    return ts.tv_sec;
}
static void stop(int sig) { (void)sig; stopping=1; }
static void die(const char *s) { perror(s); exit(1); }
static void drop(void) {
    if (setgroups(0,NULL) || setresgid(config.gid,config.gid,config.gid) || setresuid(config.uid,config.uid,config.uid) ||
        prctl(PR_SET_NO_NEW_PRIVS,1,0,0,0)) die("drop privileges");
}
static int eligible(const struct mntent *m) {
    const char *types[]={"ext2","ext3","ext4","xfs","btrfs","overlay","vfat","exfat","ntfs3",NULL};
    for (int i=0;types[i];i++) if (!strcmp(m->mnt_type,types[i])) return 1;
    return !strcmp(m->mnt_type,"tmpfs") && (!strcmp(m->mnt_dir,"/tmp") ||
        !strcmp(m->mnt_dir,"/home") || !strncmp(m->mnt_dir,"/home/",6));
}
static int target(pid_t pid, const struct stat *expected) {
    char path[64],buf[4096],exe[4096];
    /* Pin the proc directory so PID reuse cannot switch the process mid-check. */
    snprintf(path,sizeof(path),"/proc/%d",pid);
    int proc=open(path,O_PATH|O_DIRECTORY|O_CLOEXEC);
    if (proc<0) return -1;
    int selected=-1,fd=openat(proc,"status",O_RDONLY|O_CLOEXEC);
    if (fd<0) { close(proc); return -1; }
    ssize_t n=read(fd,buf,sizeof(buf)-1); close(fd);
    if (n<=0) goto done;
    buf[n]=0;
    char *uids=strstr(buf,"\nUid:\t");
    unsigned int a,b,c,d;
    if (!uids || sscanf(uids,"\nUid:\t%u\t%u\t%u\t%u",&a,&b,&c,&d)!=4) goto done;
    if (a!=config.uid || b!=config.uid || c!=config.uid || d!=config.uid) { selected=0; goto done; }
    n=readlinkat(proc,"exe",exe,sizeof(exe)-1);
    if (n<0) goto done;
    exe[n]=0;
    int index=0;
    if (strcmp(exe,config.telegram)) {
        if (!config.signal[0] || strcmp(exe,config.signal)) { selected=0; goto done; }
        index=1;
    }
    struct stat st;
    if (fstatat(proc,"exe",&st,0)) goto done;
    selected=(st.st_dev==expected[index].st_dev && st.st_ino==expected[index].st_ino)?1:-2;
done:
    close(proc); return selected;
}
static int respond(int fan,int fd,unsigned int decision) {
    struct fanotify_response r={.fd=fd,.response=decision};
    int ok=write(fan,&r,sizeof(r))==(ssize_t)sizeof(r);
    close(fd); return ok;
}
static int relay(int sock,uint64_t mask,int32_t token,pid_t pid,int fd) {
    struct message data={mask,token,pid};
    struct iovec io={&data,sizeof(data)};
    char control[CMSG_SPACE(sizeof(int))];
    struct msghdr msg={0}; msg.msg_iov=&io; msg.msg_iovlen=1;
    if (fd>=0) {
        memset(control,0,sizeof(control)); msg.msg_control=control; msg.msg_controllen=sizeof(control);
        struct cmsghdr *c=CMSG_FIRSTHDR(&msg);
        c->cmsg_level=SOL_SOCKET; c->cmsg_type=SCM_RIGHTS; c->cmsg_len=CMSG_LEN(sizeof(int));
        memcpy(CMSG_DATA(c),&fd,sizeof(fd));
    }
    return sendmsg(sock,&msg,MSG_DONTWAIT|MSG_NOSIGNAL)==(ssize_t)sizeof(data);
}
static int broker(int fan,int sock,pid_t child,const struct stat *expected) {
    struct pending pending[MAX_PENDING];
    for (int i=0;i<MAX_PENDING;i++) pending[i].fd=-1;
    int32_t token=0;
    int failed=0;
    while (!stopping && !failed) {
        for (int i=0;i<MAX_PENDING;i++) if (pending[i].fd>=0 && monotonic_seconds()-pending[i].since>=DLP_PERMISSION_SECONDS) {
            if (!respond(fan,pending[i].fd,FAN_DENY)) failed=1;
            pending[i].fd=-1;
            if (!relay(sock,0x10000000,-1,0,-1)) failed=1;
        }
        struct pollfd p[2]={{.fd=fan,.events=POLLIN},{.fd=sock,.events=POLLIN}};
        int ready=poll(p,2,1000);
        if (ready<0) { if (errno==EINTR) continue; break; }
        if (p[1].revents&(POLLHUP|POLLERR|POLLNVAL)) break;
        if (p[1].revents&POLLIN) {
            struct answer a;
            /* Fixed packets, reject truncation, invalid decisions and stale tokens. */
            ssize_t n=recv(sock,&a,sizeof(a),MSG_TRUNC);
            if (n!=(ssize_t)sizeof(a) || (a.decision!=FAN_ALLOW && a.decision!=FAN_DENY)) break;
            int found=0;
            for (int i=0;i<MAX_PENDING;i++) if (pending[i].fd>=0 && pending[i].token==a.token) {
                if (!respond(fan,pending[i].fd,a.decision)) failed=1;
                if (!failed && !relay(sock,0x40000000,a.token,(pid_t)a.decision,-1)) failed=1;
                pending[i].fd=-1; found=1; break;
            }
            /* Expired decisions are ignored; tokens never repeat within this run. */
            if (!found && (a.token<=0 || a.token>token)) break;
            if (!found && !relay(sock,0x40000000,a.token,FAN_DENY,-1)) failed=1;
        }
        if (p[0].revents&POLLIN) {
            /* Small bounded batches prevent starvation of analyzer replies. */
            struct fanotify_event_metadata batch[32];
            ssize_t bytes=read(fan,batch,sizeof(batch));
            if (bytes<0) { if (errno==EAGAIN || errno==EINTR) continue; break; }
            if (!bytes) break;
            for (struct fanotify_event_metadata *e=batch;FAN_EVENT_OK(e,bytes);e=FAN_EVENT_NEXT(e,bytes)) {
                if (e->vers!=FANOTIFY_METADATA_VERSION) { failed=1; break; }
                if (e->fd<0) {
                    if (!relay(sock,e->mask,-1,0,-1)) failed=1;
                    continue;
                }
                if (!(e->mask&FAN_OPEN_PERM)) { close(e->fd); continue; }
                int selected=target(e->pid,expected);
                if (selected!=1) {
                    if (!respond(fan,e->fd,FAN_ALLOW)) failed=1;
                    /* Unknown identity is a reported coverage gap, never a global denial. */
                    if (selected<0 && !relay(sock,selected==-2?0x08000000:0x20000000,-1,0,-1)) failed=1;
                    continue;
                }
                int slot=-1;
                for (int i=0;i<MAX_PENDING;i++) if (pending[i].fd<0) { slot=i; break; }
                if (slot<0 || token==INT32_MAX) {
                    if (!respond(fan,e->fd,FAN_DENY)) failed=1;
                    if (!relay(sock,0x10000000,-1,0,-1)) failed=1;
                    continue;
                }
                token++;
                if (!relay(sock,e->mask,token,e->pid,e->fd)) {
                    respond(fan,e->fd,FAN_DENY); failed=1; continue;
                }
                pending[slot]=(struct pending){e->fd,token,monotonic_seconds()};
            }
        }
    }
    /* Release pending operations and close the group before waiting for Python. */
    for (int i=0;i<MAX_PENDING;i++) if (pending[i].fd>=0) respond(fan,pending[i].fd,FAN_DENY);
    close(fan); close(sock); kill(child,SIGTERM);
    int status;
    for (int attempt=0;attempt<20;attempt++) {
        pid_t done=waitpid(child,&status,WNOHANG);
        if (done==child || (done<0 && errno==ECHILD)) return stopping?130:1;
        poll(NULL,0,100);
    }
    kill(child,SIGKILL);
    while (waitpid(child,&status,0)<0) if (errno!=EINTR) break;
    return stopping?130:1;
}
int main(int argc,char **argv) {
    (void)argv;
    if (argc!=1 || geteuid()!=0) {
        fprintf(stderr,"Filesystem gateway requires sudo and accepts no arguments\n"); return 2;
    }
    if (clearenv() || chdir("/")) die("environment");
    int config_lock=load_gateway_config();
    if (config_lock<0) {
        fprintf(stderr,"Invalid/protected gateway configuration or another instance is running\n"); return 2;
    }
    struct stat expected[2];
    const char *targets[]={config.telegram,config.signal};
    for (int i=0;i<2;i++) {
        if (!targets[i][0]) continue;
        if (stat(targets[i],&expected[i]) || !S_ISREG(expected[i].st_mode) ||
            expected[i].st_uid!=0 || (expected[i].st_mode&0002) ||
            ((expected[i].st_mode&0020) && expected[i].st_gid!=0)) {
            fprintf(stderr,"Expected protected messenger executable\n"); return 2;
        }
    }
    int dirs[MAX_FS],count=0;
    dev_t devices[MAX_FS]; char roots[32768]="";
    FILE *mounts=setmntent("/proc/self/mounts","r");
    if (!mounts) die("mount inventory");
    struct mntent *m;
    while ((m=getmntent(mounts))) {
        if (!eligible(m)) continue;
        int fd=open(m->mnt_dir,O_PATH|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);
        if (fd<0) die("open filesystem root");
        struct stat st; if (fstat(fd,&st)) die("filesystem identity");
        int duplicate=0;
        for (int i=0;i<count;i++) if (devices[i]==st.st_dev) duplicate=1;
        if (duplicate) { close(fd); continue; }
        if (count==MAX_FS || strchr(m->mnt_dir,'\n') || strlen(roots)+strlen(m->mnt_dir)+2>=sizeof(roots)) {
            fprintf(stderr,"Filesystem inventory exceeds limits\n"); return 2;
        }
        strcat(roots,m->mnt_dir); strcat(roots,"\n");
        devices[count]=st.st_dev; dirs[count++]=fd;
    }
    endmntent(mounts);
    if (!count) { fprintf(stderr,"No supported local filesystems\n"); return 2; }
    int fan=fanotify_init(FAN_CLASS_CONTENT|FAN_NONBLOCK|FAN_CLOEXEC,O_RDONLY|O_LARGEFILE|O_CLOEXEC);
    if (fan<0) die("fanotify_init");
    int channel[2]; if (socketpair(AF_UNIX,SOCK_SEQPACKET,0,channel)) die("worker socket");
    char pythonpath[2*DLP_PATH_LIMIT+32],policy[DLP_PATH_LIMIT+32];
    if (snprintf(pythonpath,sizeof(pythonpath),"%s/src:%s/.deps",config.project,config.project)>=(int)sizeof(pythonpath) ||
        snprintf(policy,sizeof(policy),"%s/config/policy.yaml",config.project)>=(int)sizeof(policy)) return 2;
#ifdef DLP_SYSTEM_PACKAGE
    strcpy(pythonpath,"/usr/lib/dlp-lab/src");
    strcpy(policy,"/etc/dlp-lab/system/policy.yaml");
#endif
    char number[32]; snprintf(number,sizeof(number),"%d",channel[1]);
    if (setenv("DLP_FAN_FD",number,1) || setenv("DLP_FAN_SCOPE","local_filesystems",1) ||
        setenv("DLP_FS_ROOTS",roots,1) || setenv("PATH","/usr/bin:/bin",1) ||
        setenv("HOME",config.home,1) || setenv("LANG","C.UTF-8",1) ||
        setenv("PYTHONPATH",pythonpath,1) || setenv("PYTHONNOUSERSITE","1",1) ||
        setenv("PYTHONSAFEPATH","1",1) ||
        setenv("DLP_GATEWAY_CONFIG","/etc/dlp-lab/" DLP_GATEWAY_CONFIG,1) || setenv("DLP_EXCLUDED_ROOTS",config.exclusions,1) ||
        setenv("DLP_TARGET_EXECUTABLE",config.telegram,1) ||
        setenv("DLP_SIGNAL_EXECUTABLE",config.signal,1)) die("worker environment");
    struct sigaction sa={0}; sa.sa_handler=stop; sigemptyset(&sa.sa_mask);
    if (sigaction(SIGTERM,&sa,NULL) || sigaction(SIGINT,&sa,NULL)) die("signal handler");
    signal(SIGPIPE,SIG_IGN);
    pid_t parent=getpid(), child=fork();
    if (child<0) die("fork");
    if (!child) {
        close(channel[0]); close(fan); close(config_lock);
        for (int i=0;i<count;i++) close(dirs[i]);
        drop();
        if (prctl(PR_SET_PDEATHSIG,SIGTERM)) die("parent death signal");
        if (getppid()!=parent) return 1;
        execl("/usr/bin/python3","python3","-m","dlp.cli","--policy",
              policy,"monitor",(char *)NULL);
        die("exec worker");
    }
    close(channel[1]);
    struct pollfd p={.fd=channel[0],.events=POLLIN}; char ready=0;
    if (poll(&p,1,15000)!=1 || recv(channel[0],&ready,1,MSG_TRUNC)!=1 || ready!='R') {
        fprintf(stderr,"Worker not ready; monitoring not enabled\n"); kill(child,SIGTERM); return 1;
    }
    for (int i=0;i<count;i++) {
        if (fanotify_mark(fan,FAN_MARK_ADD|FAN_MARK_FILESYSTEM,FAN_OPEN_PERM,dirs[i],".")) {
            perror("filesystem mark; monitoring aborted"); kill(child,SIGTERM); return 1;
        }
        close(dirs[i]);
    }
    if (send(channel[0],"A",1,MSG_NOSIGNAL)!=1) { kill(child,SIGTERM); return 1; }
    if (prctl(PR_SET_DUMPABLE,0) || prctl(PR_SET_NO_NEW_PRIVS,1,0,0,0)) die("broker hardening");
    return broker(fan,channel[0],child,expected);
}
