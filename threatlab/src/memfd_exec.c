/*
 * memfd_exec — create a memfd, copy /usr/bin/sleep into it, fexecve.
 * Result: /proc/PID/exe -> /memfd:payload (memory-only execution).
 * Triggers spyproc module's memfd detection (threat 2.6).
 */
#define _GNU_SOURCE
#include <sys/mman.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>

int main(void) {
    int fd = memfd_create("payload", 0);
    if (fd < 0) { perror("memfd_create"); return 1; }

    int src = open("/usr/bin/sleep", O_RDONLY);
    if (src < 0) { perror("open sleep"); return 1; }

    char buf[8192];
    ssize_t n;
    while ((n = read(src, buf, sizeof(buf))) > 0)
        write(fd, buf, n);
    close(src);

    lseek(fd, 0, SEEK_SET);

    char *argv[] = { "payload", "86400", NULL };
    char *envp[] = { NULL };
    fexecve(fd, argv, envp);
    perror("fexecve");
    return 1;
}
