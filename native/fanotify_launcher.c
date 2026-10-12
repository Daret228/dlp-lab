#define _GNU_SOURCE
#include <sys/fanotify.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <grp.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <limits.h>

static void die(const char *s) { perror(s); exit(1); }
static unsigned int parse_id(const char *s) {
    char *end;
    errno = 0;
    unsigned long n = strtoul(s, &end, 10);
    if (errno || !*s || *end || n == 0 || n >= UINT_MAX) {
        fprintf(stderr, "UID/GID must be positive non-root numeric IDs\n");
        exit(2);
    }
    return (unsigned int)n;
}
int main(int argc, char **argv) {
#ifdef DLP_INSTALLED_GATEWAY
    // The sudo-authorized build accepts no caller-controlled root arguments.
    if (argc != 1) {
        fprintf(stderr, "Installed gateway accepts no arguments\n");
        return 2;
    }
    if (geteuid() != 0) {
        fprintf(stderr, "Installed gateway requires sudo\n");
        return 2;
    }
    if (clearenv() || chdir("/")) die("clear environment");
    char *fixed[] = {
        "fanotify-gateway", "/var/lib/dlp-lab/watch", "1000", "1000",
        "/usr/bin/python3", "-m", "dlp.cli", "--policy",
        "/home/roman/dlp-lab/config/policy.yaml", "monitor", NULL
    };
    argv = fixed;
    argc = 10;
#endif
    if (argc < 5) {
        fprintf(stderr, "Usage: %s WATCH_DIR UID GID COMMAND [ARGS...]\n", argv[0]);
        return 2;
    }
    uid_t uid = parse_id(argv[2]);
    gid_t gid = parse_id(argv[3]);
    int dir = open(argv[1], O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (dir < 0) die("watch directory");
    struct stat st;
    if (fstat(dir, &st)) die("fstat directory");
    if (st.st_uid != uid || (st.st_mode & 0022)) {
        fprintf(stderr, "Use a dedicated directory owned by UID, not group/world writable\n");
        return 2;
    }
    int fan = fanotify_init(FAN_CLASS_CONTENT | FAN_NONBLOCK, O_RDONLY | O_LARGEFILE | O_CLOEXEC);
    if (fan < 0) die("fanotify_init (requires CAP_SYS_ADMIN and permitted syscall)");
    if (fanotify_mark(fan, FAN_MARK_ADD | FAN_MARK_ONLYDIR,
                     FAN_OPEN_PERM | FAN_EVENT_ON_CHILD, dir, ".")) die("fanotify_mark");
    close(dir);
    // The only intentionally inherited capability is this fanotify group FD.
    if (setgroups(0, NULL) || setresgid(gid, gid, gid) || setresuid(uid, uid, uid)) die("drop privileges");
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)) die("no_new_privs");
    if (getuid() != uid || geteuid() != uid || getgid() != gid || getegid() != gid) {
        fprintf(stderr, "Identity mismatch after privilege drop\n");
        return 1;
    }
    char value[32];
    snprintf(value, sizeof(value), "%d", fan);
    if (setenv("DLP_FAN_FD", value, 1)) die("setenv");
#ifdef DLP_INSTALLED_GATEWAY
    if (setenv("PATH", "/usr/bin:/bin", 1) ||
        setenv("HOME", "/home/roman", 1) ||
        setenv("LANG", "C.UTF-8", 1) ||
        setenv("PYTHONPATH", "/home/roman/dlp-lab/src:/home/roman/dlp-lab/.deps", 1))
        die("worker environment");
#endif
    execvp(argv[4], &argv[4]);
    die("exec worker");
}
