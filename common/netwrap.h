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


typedef struct conn
{
    int32_t sock_fd;
    SSL* ssl;
}conn;

typedef struct net_fns
{
    int32_t(*accept_fn)(conn* c);
    int32_t(*connect_fn)(uint32_t be_inet4addr, uint16_t le_port);
    uint64_t(*send_fn)(conn* c, void* buf, uint64_t len);
    uint64_t(*recv_fn)(conn* c, void* buf, uint64_t len);
    void(*disconnect_fn)(conn* c, uint8_t c_state);
}net_fns;

int32_t server_start_tcp(uint32_t be_inet4addr, uint16_t le_port, uint16_t backlog, bool nonblock);

#endif //LWMSG_NETWRAP_H
