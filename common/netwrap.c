//
// Created by gf-senka on 6/7/2026.
//

#include "netwrap.h"

#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>

int32_t server_start_tcp(uint32_t be_inet4addr, uint16_t le_port, uint8_t backlog)
{
    int32_t sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sock == ERROR)
        goto error;

    struct sockaddr_in addr = {.sin_addr.s_addr = be_inet4addr, .sin_port = htons(le_port), .sin_family = AF_INET};
    int res = bind(sock, (struct sockaddr*)&addr, sizeof(addr));
    if (res == ERROR)
        goto error;

    res = listen(sock, backlog);
    if (res == ERROR)
        goto error;

    return sock;

    error:
    close(sock);
    return ERROR;
}