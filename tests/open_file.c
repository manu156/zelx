#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/fanotify.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

int main(int argc, char **argv) {
    if (argc == 3 && !strcmp(argv[1], "--wait")) {
        char token;
        if (read(STDIN_FILENO, &token, 1) != 1) return 2;
        argv++; argc--;
    }
    if (argc != 2) return 2;
    const char *path = getenv("ZELX_TEST_SOCKET");
    if (path) {
        struct sockaddr_un address = {.sun_family = AF_UNIX};
        if (strlen(path) >= sizeof(address.sun_path) || strlen(argv[1]) >= PATH_MAX) return 2;
        strcpy(address.sun_path, path);
        int sock = socket(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0);
        if (sock < 0 || connect(sock, (struct sockaddr *)&address, sizeof(address))) return 2;
        struct { int32_t pid; char path[PATH_MAX]; } request = {.pid = getpid()};
        strcpy(request.path, argv[1]);
        if (send(sock, &request, sizeof(request), 0) != sizeof(request)) return 2;
        uint32_t response;
        ssize_t n = recv(sock, &response, sizeof(response), 0); close(sock);
        /* Transport closure simulates kernel fail-open after daemon death. */
        if (n == sizeof(response)) {
            /* FAN_DENY rejects the requesting open with EPERM (fanotify(7)). */
            if (response == FAN_DENY) return EPERM;
            if (response != FAN_ALLOW) return 2;
        }
    }
    int fd = open(argv[1], O_RDONLY | O_CLOEXEC);
    if (fd < 0) return errno;
    close(fd); return 0;
}
