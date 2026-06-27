//
// Created by dominik on 4/23/26.
//

#include "client.h"
#include "clrecv.h"
#include "clnet.h"
#include "clio.h"

#include <stdio.h>
#include <unistd.h>
#include <sys/epoll.h>
#include <errno.h>
#include <signal.h>
#include <getopt.h>

int main(int argc, char** argv)
{
    client_ctx ctx = {0};
    ctx.connection.sock_fd = ERROR;
    ctx.connection.ssl = NULL;
    ctx.running = true;
    ctx.state = ST_DISCONNECTED;

    const char* ca_path = NULL;

    static struct option long_options[] = {
        {"tls",  no_argument,       0, 't'},
        {"ca",   required_argument, 0, 'c'},
        {"help", no_argument,       0, 'h'},
        {0, 0, 0, 0}
    };

    int32_t opt;
    while ((opt = getopt_long(argc, argv, "tc:h", long_options, NULL)) != -1)
    {
        switch (opt)
        {
            case 't': ctx.use_tls = true; break;
            case 'c': ca_path = optarg; break;
            case 'h':
                printf("Usage: lwmsg-client [--tls] [--ca <path>]\n");
                return 0;
            default: return 1;
        }
    }

    if (ctx.use_tls)
    {
        ctx.ssl_ctx = setup_client_ssl_ctx(ca_path);
        if (!ctx.ssl_ctx)
        {
            fprintf(stderr, "Failed to initialize TLS.\n");
            return 1;
        }
    }

    signal(SIGPIPE, SIG_IGN);

    ctx.epoll_fd = epoll_create1(0);
    if (ctx.epoll_fd < 0)
    {
        perror("epoll_create1");
        return 1;
    }

    struct epoll_event ev_stdin = {.events = EPOLLIN, .data.fd = STDIN_FILENO};
    epoll_ctl(ctx.epoll_fd, EPOLL_CTL_ADD, STDIN_FILENO, &ev_stdin);

    printf("lwmsg client%s. Type 'help' for commands.\n", ctx.use_tls ? " (TLS)" : "");
    clio_init(&ctx);

    struct epoll_event events[4];
    while (ctx.running)
    {
        int32_t nev = epoll_wait(ctx.epoll_fd, events, 4, -1);
        if (nev == -1)
        {
            if (errno == EINTR) continue;
            break;
        }

        for (int32_t i = 0; i < nev; i++)
        {
            if (events[i].data.fd == STDIN_FILENO)
                clio_on_stdin();
            else
                handle_socket_data(&ctx);
        }
    }

    clio_shutdown();

    close_all_transfers(&ctx);
    if (ctx.state == ST_CONNECTED)
    {
        epoll_ctl(ctx.epoll_fd, EPOLL_CTL_DEL, ctx.connection.sock_fd, NULL);
        ctx.nfns.disconnect_fn(&ctx.connection);
    }
    close(ctx.epoll_fd);
    if (ctx.ssl_ctx) SSL_CTX_free(ctx.ssl_ctx);

    printf("Exiting.\n");
    return 0;
}
