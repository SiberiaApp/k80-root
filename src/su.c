#include <unistd.h>
#include <stdio.h>
#include <string.h>

int main(int argc, char **argv) {
    if (setuid(0) != 0) {
        perror("setuid");
        return 1;
    }
    setgid(0);  // best-effort: uid=0 时通常能成功

    if (argc > 2 && strcmp(argv[1], "-c") == 0) {
        execl("/system/bin/sh", "sh", "-c", argv[2], NULL);
    } else if (argc > 1) {
        execvp(argv[1], argv + 1);
    } else {
        execl("/system/bin/sh", "sh", NULL);
    }

    perror("exec");
    return 1;
}
