#ifndef LWMSG_CLIENT_H
#define LWMSG_CLIENT_H

#include <stdint.h>
#include <stdbool.h>
#include <openssl/ssl.h>
#include "lwmp.h"
#include "netwrap.h"

#define INPUT_LINE_MAX 4096
#define RECV_BUF_SIZE (LWMP_MAX_PDU_SIZE * 4)

enum client_state
{
    ST_DISCONNECTED,
    ST_CONNECTED
};

typedef struct client_ctx
{
    conn connection;
    net_fns nfns;
    SSL_CTX* ssl_ctx;
    int epoll_fd;
    enum client_state state;
    bool use_tls;
    char username[UNAMESIZE];
    unsigned char recv_buf[RECV_BUF_SIZE];
    uint32_t recv_len;
    char stdin_buf[INPUT_LINE_MAX];
    uint32_t stdin_len;
    bool running;
} client_ctx;

#endif
