//
// Created by gf-senka on 6/7/2026.
//

#ifndef LWMSG_NETWRAP_H
#define LWMSG_NETWRAP_H
#include <stdbool.h>
#include <stdint.h>
#include <openssl/ssl.h>
#define ERROR (-1)
#define ACCPT_DONE 0
#define ACCPT_IN_PROGRESS 1

#define EBLOCK (-2)

typedef struct conn
{
    int32_t sock_fd;
    SSL* ssl;
}conn;

typedef struct net_fns
{
    int32_t(*accept_fn)(conn* c, SSL_CTX* ssl_ctx);
    int32_t(*connect_fn)(conn* c, SSL_CTX* ssl_ctx, uint32_t be_inet4addr, uint16_t le_port);
    int64_t(*send_fn)(conn* c, void* buf, uint64_t len);
    int64_t(*recv_fn)(conn* c, void* buf, uint64_t len);
    uint32_t(*avail_data_fn)(conn* c);
    void(*disconnect_fn)(conn* c);
}net_fns;


int32_t server_start_tcp(uint32_t be_inet4addr, uint16_t le_port, uint16_t backlog, bool nonblock, int32_t reuse_port);

// Plain TCP networking function wrappers:
int32_t accept_tcp(conn* c, SSL_CTX* ssl_ctx);

int32_t connect_tcp(conn* c, SSL_CTX* ssl_ctx, uint32_t be_inet4addr, uint16_t le_port);

int64_t send_tcp(conn* c, void* buf, uint64_t len);

int64_t recv_tcp(conn* c, void* buf, uint64_t len);

uint32_t avail_data_tcp(conn* c);

void disconnect_tcp(conn* c);


// TLS networking function wrappers:
int32_t accept_tls(conn* c, SSL_CTX* ssl_ctx);

int32_t connect_tls(conn* c, SSL_CTX* ssl_ctx, uint32_t be_inet4addr, uint16_t le_port);

int64_t send_tls(conn* c, void* buf, uint64_t len);

int64_t recv_tls(conn* c, void* buf, uint64_t len);

uint32_t avail_data_tls(conn* c);

void disconnect_tls(conn* c);

#endif //LWMSG_NETWRAP_H
