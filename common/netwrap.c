//
// Created by gf-senka on 6/7/2026.
//

#include "netwrap.h"

#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <errno.h>
#define IP4DOT(be_addr) be_addr >> 24, be_addr >> 16 & 0xFF, be_addr >> 8 & 0xFF, be_addr & 0xFF

int32_t server_start_tcp(uint32_t be_inet4addr, uint16_t le_port, uint16_t backlog, bool nonblock)
{
    int32_t sock = socket(AF_INET, SOCK_STREAM | (nonblock ? SOCK_NONBLOCK : 0), IPPROTO_TCP);
    if (sock == ERROR)
        return ERROR;

    struct sockaddr_in addr = {.sin_addr.s_addr = be_inet4addr, .sin_port = htons(le_port), .sin_family = AF_INET};
    int res = bind(sock, (struct sockaddr*)&addr, sizeof(addr));
    if (res == ERROR)
    {
        int32_t err = errno;
        if (err == EADDRNOTAVAIL)
        {
            fprintf(stderr, "Error: %u.%u.%u.%u is not a valid interface.\n", IP4DOT(addr.sin_addr.s_addr));
            goto error;
        }
        else if (err == EADDRINUSE)
        {
            uint16_t new_port = le_port + 1;
            do
            {
                addr.sin_port = htons(new_port++);
                res = bind(sock, (struct sockaddr*)&addr, sizeof(addr));
            }while (res == ERROR && errno == EADDRINUSE && new_port < UINT16_MAX);

            if (res == ERROR)
            {
                fprintf(stderr, "Error: Original port %u is already in use, failed to find a suitable replacement.\n", le_port);
                goto error;
            }

            printf("Warning: Original port %u is already in use, switched to using port %u.\n", le_port, new_port - 1);
        }
        else
        {
            fprintf(stderr, "Error: Failed to bind to interface %u.%u.%u.%u:%u. Reason: %s",  IP4DOT(be_inet4addr), le_port, strerror(err));
            goto error;
        }
    }

    listen(sock, backlog);
    return sock;

    error:
    close(sock);
    return ERROR;
}