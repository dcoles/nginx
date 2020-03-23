#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <errno.h>

#include <sys/types.h>
#include <sys/un.h>
#include <sys/socket.h>
#include <pthread.h>

#define NGX_FUZZER_CONF_PATH NGX_CONF_PREFIX "/nginx-fuzzer.conf"
#define SOCKET_PATH "nginx.sock"

static const char *argv[] = {"nginx", "-c", NGX_FUZZER_CONF_PATH, NULL};

extern int _main(int argc, char *const argv[]);

static void *run_main(void *_) {
    _main(sizeof(argv)/sizeof(char *) - 1, (char **)argv);
    return NULL;
}

__attribute__((constructor)) static void init(void) {
    int err;

    // Cleanup stale socket
    unlink(SOCKET_PATH);

    // Run Nginx in new thread
    pthread_t thread;
    err = pthread_create(&thread, NULL, run_main, NULL);
    if (err != 0) {
        fprintf(stderr, "Failed to create main thread: %s (%d)\n", strerror(err), err);
        exit(1);
    }

    // Ignore signals in the main thread
    sigset_t set;
    sigfillset(&set);
    err = pthread_sigmask(SIG_BLOCK, &set, NULL);
    if (err != 0) {
        fprintf(stderr, "Failed to block signals on main thread: %s (%d)\n", strerror(err), err);
        exit(1);
    }
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    int sfd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (sfd == -1) {
        fprintf(stderr, "Failed to create socket: %s, (%d)\n", strerror(errno), errno);
        exit(1);
    }

    struct sockaddr_un claddr;
    memset(&claddr, 0, sizeof(struct sockaddr_un));
    claddr.sun_family = AF_UNIX;
    snprintf(claddr.sun_path, sizeof(claddr.sun_path), "%s", SOCKET_PATH);

    if (connect(sfd, (struct sockaddr *) &claddr, sizeof(struct sockaddr_un)) == -1) {
        fprintf(stderr, "Failed to connect socket %s: %s, (%d)\n", SOCKET_PATH, strerror(errno), errno);
        exit(1);
    }

    if (send(sfd, data, size, 0) != (ssize_t) size) {
        fprintf(stderr, "Failed to send %zu bytes: %s (%d)\n", size, strerror(errno), errno);
        exit(1);
    }

    close(sfd);
    return 0;  // Non-zero return values are reserved for future use.
}

__attribute__((destructor)) static void cleanup(void) {
    unlink((const char *) SOCKET_PATH);
}
