/* Unprivileged transport/identity test. No real fanotify marks or root actions. */
#define main installed_gateway_main
#include "../native/filesystem_launcher.c"
#undef main
#include <assert.h>

int main(int argc,char **argv) {
    assert(argc==2);
    config.uid=getuid(); config.gid=getgid();
    assert(strlen(TELEGRAM)<sizeof(config.telegram)); strcpy(config.telegram,TELEGRAM);
    struct stat expected; assert(!stat(TELEGRAM,&expected));
    assert(target(getpid(),&expected)==1);
    struct stat wrong=expected; wrong.st_ino++;
    assert(target(getpid(),&wrong)==-2);
    assert(target(99999999,&expected)==-1);
    /* Same executable selected as the second configured messenger. */
    struct stat both[2]={expected,expected};
    strcpy(config.signal,TELEGRAM); strcpy(config.telegram,"/not-the-running-client");
    assert(target(getpid(),both)==1);
    both[1].st_ino++; assert(target(getpid(),both)==-2);
    config.uid++; assert(target(getpid(),both)==0); config.uid--;
    strcpy(config.signal,"/not-signal-either"); assert(target(getpid(),both)==0);
    config.signal[0]=0; strcpy(config.telegram,TELEGRAM);
    int kernel[2],worker[2],result[2];
    assert(!socketpair(AF_UNIX,SOCK_SEQPACKET,0,kernel));
    assert(!socketpair(AF_UNIX,SOCK_SEQPACKET,0,worker));
    assert(!pipe(result));
    int target_fd=open(argv[1],O_RDONLY),unknown_fd=open(argv[1],O_RDONLY),late_fd=open(argv[1],O_RDONLY);
    assert(target_fd>=0 && unknown_fd>=0);
    pid_t child=fork(); assert(child>=0);
    if (!child) {
        close(kernel[0]); close(worker[0]); close(result[0]);
        struct fanotify_event_metadata e={.event_len=sizeof(e),.vers=FANOTIFY_METADATA_VERSION,
            .metadata_len=sizeof(e),.mask=FAN_OPEN_PERM,.fd=target_fd,.pid=getpid()};
        assert(write(kernel[1],&e,sizeof(e))==(ssize_t)sizeof(e));
        struct message data;
        struct iovec io={&data,sizeof(data)};
        char control[CMSG_SPACE(sizeof(int))];
        struct msghdr msg={.msg_iov=&io,.msg_iovlen=1,.msg_control=control,.msg_controllen=sizeof(control)};
        assert(recvmsg(worker[1],&msg,0)==(ssize_t)sizeof(data));
        struct cmsghdr *c=CMSG_FIRSTHDR(&msg);
        assert(c && c->cmsg_type==SCM_RIGHTS && data.token>0);
        int received; memcpy(&received,CMSG_DATA(c),sizeof(received));
        char text[6]={0}; assert(read(received,text,6)==6 && !memcmp(text,"public",6)); close(received);
        struct answer answer={data.token,FAN_DENY};
        assert(write(worker[1],&answer,sizeof(answer))==(ssize_t)sizeof(answer));
        struct fanotify_response reply;
        assert(read(kernel[1],&reply,sizeof(reply))==(ssize_t)sizeof(reply));
        assert(reply.fd==target_fd && reply.response==FAN_DENY);
        assert(read(worker[1],&data,sizeof(data))==(ssize_t)sizeof(data));
        assert(data.mask==0x40000000 && data.pid==FAN_DENY && data.token==answer.token);
        e.fd=late_fd;
        assert(write(kernel[1],&e,sizeof(e))==(ssize_t)sizeof(e));
        msg.msg_controllen=sizeof(control);
        assert(recvmsg(worker[1],&msg,0)==(ssize_t)sizeof(data));
        c=CMSG_FIRSTHDR(&msg); assert(c);
        memcpy(&received,CMSG_DATA(c),sizeof(received)); close(received);
        answer=(struct answer){data.token,FAN_ALLOW};
        /* No worker response until the broker deadline: kernel must deny. */
        assert(read(kernel[1],&reply,sizeof(reply))==(ssize_t)sizeof(reply));
        assert(reply.fd==late_fd && reply.response==FAN_DENY);
        assert(read(worker[1],&data,sizeof(data))==(ssize_t)sizeof(data));
        assert(data.mask==0x10000000);
        assert(write(worker[1],&answer,sizeof(answer))==(ssize_t)sizeof(answer));
        assert(read(worker[1],&data,sizeof(data))==(ssize_t)sizeof(data));
        assert(data.mask==0x40000000 && data.pid==FAN_DENY && data.token==answer.token);
        e.fd=unknown_fd; e.pid=99999999;
        assert(write(kernel[1],&e,sizeof(e))==(ssize_t)sizeof(e));
        assert(read(kernel[1],&reply,sizeof(reply))==(ssize_t)sizeof(reply));
        assert(reply.fd==unknown_fd && reply.response==FAN_ALLOW);
        msg.msg_controllen=sizeof(control);
        assert(recvmsg(worker[1],&msg,0)==(ssize_t)sizeof(data));
        assert(!CMSG_FIRSTHDR(&msg) && data.token==-1 && data.mask==0x20000000);
        assert(write(result[1],"Y",1)==1);
        close(worker[1]); _exit(0);
    }
    close(kernel[1]); close(worker[1]); close(result[1]);
    assert(broker(kernel[0],worker[0],child,&expected)==1);
    char ok=0; assert(read(result[0],&ok,1)==1 && ok=='Y'); close(result[0]);
    return 0;
}
