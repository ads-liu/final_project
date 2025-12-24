// src/net.c
#include "net.h"

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

/*
 * Create a TCP listening socket bound to the given IP and port.
 *
 * Parameters:
 *   ip      - Dotted-decimal string (e.g. "127.0.0.1"), or NULL to bind to INADDR_ANY.
 *   port    - TCP port to listen on.
 *   backlog - listen() backlog size (maximum length of the pending connection queue).
 *
 * Behavior:
 *   - Creates an IPv4 stream socket.
 *   - Enables SO_REUSEADDR so the port can be reused quickly after restart.
 *   - Binds to the given address and starts listening.
 *
 * Return:
 *   >=0  file descriptor of the listening socket on success.
 *   -1   on error (and prints a message with perror).
 */
int net_listen(const char *ip, uint16_t port, int backlog) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        perror("socket");
        return -1;
    }

    // Allow reuse of local address to avoid "Address already in use" after restart
    int on = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family      = AF_INET;
    addr.sin_port        = htons(port);
    // If ip is NULL, bind on all interfaces (0.0.0.0)
    addr.sin_addr.s_addr = ip ? inet_addr(ip) : htonl(INADDR_ANY);

    if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("bind");
        close(fd);
        return -1;
    }

    if (listen(fd, backlog) < 0) {
        perror("listen");
        close(fd);
        return -1;
    }

    return fd;
}

/*
 * Accept a new incoming TCP connection.
 *
 * Parameters:
 *   listen_fd - File descriptor of a listening socket returned by net_listen().
 *
 * Return:
 *   >=0  new connected socket descriptor on success.
 *   -1   on error.
 *
 * Note:
 *   - This variant ignores client address information (addr is NULL).
 */
int net_accept(int listen_fd) {
    return accept(listen_fd, NULL, NULL);
}

/*
 * Connect to a remote TCP server.
 *
 * Parameters:
 *   ip   - Server IPv4 address in dotted-decimal notation (e.g. "127.0.0.1").
 *   port - Server TCP port.
 *
 * Return:
 *   >=0  connected socket descriptor on success.
 *   -1   on failure.
 */
int net_connect(const char *ip, uint16_t port) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return -1;

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family      = AF_INET;
    addr.sin_port        = htons(port);
    addr.sin_addr.s_addr = inet_addr(ip);

    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        close(fd);
        return -1;
    }

    return fd;
}

/*
 * Close a socket if it is valid (fd >= 0).
 *
 * This is just a small helper to avoid closing invalid descriptors.
 */
void net_close(int fd) {
    if (fd >= 0) close(fd);
}