#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <poll.h>
#include <unistd.h>
#include <pthread.h>
#include <fcntl.h>
#include <arpa/inet.h>
#include <errno.h>
#include "servcfg.h"
#include "thrdctx.h"
#include "netwrap.h"

int main(int argc, char** argv)
{
    char* cfg_path = getopt(argc, argv, "c:") != -1 ? optarg : "config.json"; // TBR: If I need more CLI args.
    load_cfg(cfg_path);
    in_addr_t server_main_if = inet_addr(g_server_cfg->gen_interface);

    if (server_main_if == INADDR_NONE)
    {
        fprintf(stderr, "Error: '%s' is an invalid interface, shutting down.\n", g_server_cfg->gen_interface);
        return ERROR;
    }

    int32_t reg_sock_fd = server_start_tcp(server_main_if, g_server_cfg->reg_port, 128);
    if (reg_sock_fd == ERROR)
    {
        int32_t err = errno;
    }
    reg_thrd_ctx rt_ctx;

    pthread_t reg_thread;
    pthread_t acceptor_thread;
    pthread_t worker_threads[g_server_cfg->nr_worker_threads];

    int32_t ctrl_sock = server_start_tcp(INADDR_LOOPBACK, g_server_cfg->ctrl_port, 1);
    fcntl(ctrl_sock, F_SETFL, O_NONBLOCK);
    struct pollfd ctrl_pfd = {.fd = ctrl_sock, .events = POLLIN, .revents = 0};

    free(g_server_cfg);
    //save_cfg("config.json", &cfg);
    //printf("cert_store: %s\n", cfg.cert_chain_path);
    return 0;
}
