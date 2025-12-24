#ifndef NET_H
#define NET_H

#include <stdint.h>
#include <sys/types.h>

typedef struct {
    int fd;                 // Socket file descriptor
} net_conn_t;

// Create a server-side listening socket, return fd or -1 on error
int net_listen(const char *ip, uint16_t port, int backlog);

// Accept a connection, return new fd or -1 on error
int net_accept(int listen_fd);

// Create a client-side connection, return fd or -1 on error
int net_connect(const char *ip, uint16_t port);

// Close a socket
void net_close(int fd);

#endif // NET_H
