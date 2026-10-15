/* Test-only fanotify transport. LD_PRELOAD overrides only init/mark; the daemon
 * still reads metadata, writes real fanotify_response structures, resolves
 * procfs identities, and owns/closes event fds. This does NOT test kernel hooks. */
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <poll.h>
#include <pthread.h>
#include <stdint.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/fanotify.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <sys/syscall.h>
#include <unistd.h>

struct request { int32_t pid; char path[PATH_MAX]; };
struct pending { int fd, client; };
static int listener, transport;
static atomic_int group = -1;
static pthread_t broker_thread;
static struct pending pending[256];
static struct { dev_t device; ino_t inode; } ignored[16];
static size_t ignored_count;
static pthread_mutex_t ignored_lock = PTHREAD_MUTEX_INITIALIZER;
int close(int fd) {
    if (fd == group) {
        group = -1;
        shutdown(fd, SHUT_WR);
        pthread_join(broker_thread, NULL);
    }
    return (int)syscall(SYS_close, fd);
}
static void *broker(void *unused) {
    (void)unused;
    int next_event_fd = 64;
    for (size_t i = 0; i < 256; i++) pending[i].client = -1;
    struct pollfd p[2] = {{listener, POLLIN, 0}, {transport, POLLIN, 0}};
    for (;;) {
        int rc = poll(p, 2, -1);
        if (rc < 0) { if (errno == EINTR) continue; break; }
        if (p[1].revents & (POLLIN | POLLHUP)) {
            struct fanotify_response response;
            ssize_t n = recv(transport, &response, sizeof(response), 0);
            if (n <= 0) break;
            for (size_t i = 0; i < 256; i++) if (pending[i].client >= 0 && pending[i].fd == response.fd) {
                uint32_t answer = response.response;
                send(pending[i].client, &answer, sizeof(answer), MSG_NOSIGNAL);
                close(pending[i].client); pending[i].client = -1; break;
            }
        }
        if (p[0].revents & POLLIN) {
            int client = accept4(listener, NULL, NULL, SOCK_CLOEXEC);
            if (client < 0) continue;
            struct request request;
            ssize_t n = recv(client, &request, sizeof(request), MSG_WAITALL);
            if (n != sizeof(request) || !memchr(request.path, 0, PATH_MAX)) { close(client); continue; }
            struct stat info;
            int skip = 0;
            if (stat(request.path, &info) == 0) {
                pthread_mutex_lock(&ignored_lock);
                for (size_t i = 0; i < ignored_count; i++)
                    if (ignored[i].device == info.st_dev && ignored[i].inode == info.st_ino) skip = 1;
                pthread_mutex_unlock(&ignored_lock);
            }
            if (skip) {
                uint32_t answer = FAN_ALLOW;
                send(client, &answer, sizeof(answer), MSG_NOSIGNAL);
                close(client); continue;
            }
            /* Real fanotify descriptors are ordinary open files. O_PATH hid
             * the process-wide SQLite lock loss caused by closing one. */
            int fd = open(request.path, O_RDONLY | O_CLOEXEC);
            if (fd < 0) { close(client); continue; }
            int unique = fcntl(fd, F_DUPFD_CLOEXEC, next_event_fd);
            close(fd);
            if (unique < 0) { close(client); continue; }
            fd = unique; next_event_fd = fd + 1;
            size_t slot;
            for (slot = 0; slot < 256 && pending[slot].client >= 0; slot++) {}
            if (slot == 256) { close(fd); close(client); continue; }
            pending[slot] = (struct pending){fd, client};
            struct fanotify_event_metadata m = {.event_len = sizeof(m), .vers = FANOTIFY_METADATA_VERSION,
                .metadata_len = FAN_EVENT_METADATA_LEN, .mask = FAN_OPEN_PERM, .fd = fd, .pid = request.pid};
            if (send(transport, &m, sizeof(m), MSG_NOSIGNAL) != sizeof(m)) break;
        }
    }
    uint32_t allow = FAN_ALLOW;
    for (size_t i = 0; i < 256; i++) if (pending[i].client >= 0) {
        send(pending[i].client, &allow, sizeof(allow), MSG_NOSIGNAL); close(pending[i].client);
    }
    close(listener); close(transport); return NULL;
}
int fanotify_init(unsigned int flags, unsigned int event_f_flags) {
    (void)flags; (void)event_f_flags;
    const char *path = getenv("ZELX_TEST_SOCKET");
    if (!path) { errno = EPERM; return -1; }
    listener = socket(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0);
    if (listener < 0) return -1;
    struct sockaddr_un address = {.sun_family = AF_UNIX};
    if (strlen(path) >= sizeof(address.sun_path)) { close(listener); errno = ENAMETOOLONG; return -1; }
    strcpy(address.sun_path, path);
    if (bind(listener, (struct sockaddr *)&address, sizeof(address)) || listen(listener, 32)) { close(listener); return -1; }
    int pair[2];
    if (socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0, pair)) return -1;
    transport = pair[1];
    int current = fcntl(pair[0], F_GETFL);
    fcntl(pair[0], F_SETFL, current | O_NONBLOCK);
    int error = pthread_create(&broker_thread, NULL, broker, NULL);
    if (error) { errno = error; return -1; }
    group = pair[0];
    return pair[0];
}
int fanotify_mark(int fanotify_fd, unsigned int flags, uint64_t mask, int dirfd, const char *pathname) {
    (void)fanotify_fd; (void)mask; (void)dirfd;
    if (flags & FAN_MARK_IGNORED_MASK) {
        struct stat info;
        if (stat(pathname, &info)) return -1;
        pthread_mutex_lock(&ignored_lock);
        if (ignored_count == 16) {
            pthread_mutex_unlock(&ignored_lock);
            errno = ENOSPC; return -1;
        }
        ignored[ignored_count].device = info.st_dev;
        ignored[ignored_count++].inode = info.st_ino;
        pthread_mutex_unlock(&ignored_lock);
    }
    return 0;
}
