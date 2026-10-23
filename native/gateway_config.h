#ifndef DLP_GATEWAY_CONFIG_H
#define DLP_GATEWAY_CONFIG_H
#include <limits.h>
#include <sys/file.h>
#include <pwd.h>

#ifdef DLP_SYSTEM_PACKAGE
#define DLP_GATEWAY_CONFIG "system-gateway.conf"
#else
#define DLP_GATEWAY_CONFIG "gateway.conf"
#endif
#define DLP_CONFIG_LIMIT 65536
#define DLP_PATH_LIMIT 4096
struct gateway_config {
    uid_t uid;
    gid_t gid;
    char home[DLP_PATH_LIMIT], project[DLP_PATH_LIMIT], telegram[DLP_PATH_LIMIT], signal[DLP_PATH_LIMIT];
    char exclusions[32768];
};
static struct gateway_config config;

static int config_path(const char *s) {
    if (s[0]!='/' || strlen(s)>=DLP_PATH_LIMIT || strchr(s,':') || strchr(s,'\\')) return 0;
    if (strstr(s,"/../") || strstr(s,"/./") || strstr(s,"//")) return 0;
    size_t n=strlen(s);
    if (n>1 && s[n-1]=='/') return 0;
    if ((n>=3 && !strcmp(s+n-3,"/..")) || (n>=2 && !strcmp(s+n-2,"/."))) return 0;
    for (;*s;s++) if ((unsigned char)*s<32 || (unsigned char)*s==127) return 0;
    return 1;
}
static int config_id(const char *s,unsigned int *id) {
    if (!*s) return 0;
    for (const char *p=s;*p;p++) if (*p<'0' || *p>'9') return 0;
    errno=0; char *end; unsigned long value=strtoul(s,&end,10);
    if (errno || *end || value==0 || value>=UINT_MAX) return 0;
    *id=(unsigned int)value; return 1;
}
/* This parser does not execute or expand values. Duplicate/unknown keys fail. */
static int parse_config(FILE *input,struct gateway_config *out) {
    struct gateway_config next={0};
    char line[DLP_PATH_LIMIT+32]; unsigned int seen=0; size_t bytes=0; int exclusions=0;
    while (fgets(line,sizeof(line),input)) {
        size_t n=strlen(line); bytes+=n;
        if (bytes>DLP_CONFIG_LIMIT || !n || line[n-1]!='\n') return 0;
        line[--n]=0;
        if (!n || line[0]=='#') continue;
        char *value=strchr(line,'='); if (!value) return 0; *value++=0;
        unsigned int bit=0,id=0;
        if (!strcmp(line,"uid")) { bit=1; if (!config_id(value,&id)) return 0; next.uid=id; }
        else if (!strcmp(line,"gid")) { bit=2; if (!config_id(value,&id)) return 0; next.gid=id; }
        else if (!strcmp(line,"home")) { bit=4; if (!config_path(value)) return 0; strcpy(next.home,value); }
        else if (!strcmp(line,"project")) { bit=8; if (!config_path(value)) return 0; strcpy(next.project,value); }
        else if (!strcmp(line,"telegram")) { bit=16; if (!config_path(value)) return 0; strcpy(next.telegram,value); }
        else if (!strcmp(line,"signal")) { bit=32; if (!config_path(value)) return 0; strcpy(next.signal,value); }
        else if (!strcmp(line,"exclude")) {
            if (!config_path(value) || !strcmp(value,"/") || ++exclusions>32 ||
                strlen(next.exclusions)+strlen(value)+2>=sizeof(next.exclusions)) return 0;
            strcat(next.exclusions,value); strcat(next.exclusions,"\n");
        } else return 0;
        if (bit && (seen&bit)) return 0;
        seen|=bit;
    }
    if (ferror(input) || (seen&31)!=31 || (next.signal[0] && !strcmp(next.signal,next.telegram))) return 0;
#ifdef DLP_SYSTEM_PACKAGE
    if (strcmp(next.project,"/usr/lib/dlp-lab")) return 0;
#endif
    *out=next; return 1;
}
static int protected_metadata(const struct stat *st,int directory) {
    return st->st_uid==0 && !(st->st_mode&0022) &&
        (directory?S_ISDIR(st->st_mode):(S_ISREG(st->st_mode) && st->st_nlink==1));
}
/* Fixed protected directory, no symlink traversal; lock held for broker lifetime. */
static int load_gateway_config(void) {
    int etc=open("/etc",O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);
    struct stat st;
    if (etc<0 || fstat(etc,&st) || !protected_metadata(&st,1)) return -1;
    int dir=openat(etc,"dlp-lab",O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC); close(etc);
    if (dir<0 || fstat(dir,&st) || !protected_metadata(&st,1)) { if (dir>=0) close(dir); return -1; }
    int lock=openat(dir,"gateway.lock",O_RDONLY|O_NOFOLLOW|O_CLOEXEC);
    if (lock<0 || fstat(lock,&st) || !protected_metadata(&st,0) || flock(lock,LOCK_EX|LOCK_NB)) {
        if (lock>=0) close(lock);
        close(dir); return -1;
    }
    int fd=openat(dir,DLP_GATEWAY_CONFIG,O_RDONLY|O_NOFOLLOW|O_CLOEXEC); close(dir);
    if (fd<0 || fstat(fd,&st) || !protected_metadata(&st,0) || st.st_size>DLP_CONFIG_LIMIT) {
        if (fd>=0) close(fd);
        close(lock); return -1;
    }
    FILE *input=fdopen(fd,"r");
    if (!input) { close(fd); close(lock); return -1; }
    int valid=parse_config(input,&config); fclose(input);
    struct passwd *account=valid?getpwuid(config.uid):NULL;
    if (!account || account->pw_gid!=config.gid || strcmp(account->pw_dir,config.home)) {
        close(lock); return -1;
    }
    return lock;
}
#endif
