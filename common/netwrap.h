//
// Created by gf-senka on 6/7/2026.
//

#ifndef LWMSG_SOCKETWRAP_H
#define LWMSG_SOCKETWRAP_H
#include <stdbool.h>
#include <stdint.h>
#define ERROR -1

int32_t server_start_tcp(uint32_t inet4addr, uint16_t port, uint8_t backlog);

#endif //LWMSG_SOCKETWRAP_H
