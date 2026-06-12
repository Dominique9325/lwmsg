//
// Created by gf-senka on 6/7/2026.
//

#ifndef LWMSG_SOCKETWRAP_H
#define LWMSG_SOCKETWRAP_H
#include <stdbool.h>
#include <stdint.h>
#include <openssl/ssl.h>
#define ERROR (-1)

typedef struct conn
{
    union
    {
        int32_t sock_fd;
        struct
        {
            int32_t sock_fd;
            SSL* ssl;
        }with_tls;
    };
}conn;

typedef struct net_fns
{
    conn(*accept_fn)(conn* c);
    conn(*connect_fn)(uint32_t be_inet4addr, uint16_t le_port);
    uint64_t(*send_fn)(conn* c, void* buf, uint64_t len);
    uint64_t(*recv_fn)(conn* c, void* buf, uint64_t len);
    void(*disconnect_fn)(conn* c);
}net_fns;

int32_t server_start_tcp(uint32_t be_inet4addr, uint16_t le_port, uint16_t backlog);

#endif //LWMSG_SOCKETWRAP_H
