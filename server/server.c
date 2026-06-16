#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/eventfd.h>
#include <netinet/in.h>
#include <poll.h>
#include <unistd.h>
#include <pthread.h>
#include <fcntl.h>
#include <arpa/inet.h>
#include <sys/sysinfo.h>
#include <errno.h>
#include "zlog.h"
#include "servcfg.h"
#include "thrdctx.h"
#include "netwrap.h"
#include "xalloc.h"

int main(int argc, char** argv)
{
    char* cfg_path = getopt(argc, argv, "c:") != -1 ? optarg : "config.json"; // TBR: If I need more CLI args.
    load_cfg(cfg_path);

    if (dzlog_init(g_server_cfg->zlog_config_path, "lwmsg"))
    {
        fprintf(stderr, "Fatal error: Failed to locate a valid zlog configuration file.\n");
        return ERROR;
    }
    zlog_put_mdc("thr_id", "main");
    zlog_category_t* zct = zlog_get_category("lwmsg");
    zlog_level_switch(zct, ZLOG_LEVEL_DEBUG);

    in_addr_t server_main_if = inet_addr(g_server_cfg->gen_interface);
    if (server_main_if == INADDR_NONE)
    {
        dzlog_fatal("'%s' is an invalid interface, shutting down.", g_server_cfg->gen_interface);
        zlog_fini();
        return ERROR;
    }

    sqlite3* sql_regthrd_rw_conn = NULL;
    if (sqlite3_open(g_server_cfg->db_file_path, &sql_regthrd_rw_conn))
    {
        dzlog_fatal("Invalid path to database file.");
        zlog_fini();
        return ERROR;
    }

    uint8_t num_worker_threads = g_server_cfg->autoconf_nr_threads ? get_nprocs() : g_server_cfg->nr_worker_threads;
    dzlog_info("Server will use %hhu worker threads.", num_worker_threads);
    eventfd_t ev_reg_allow_changed = eventfd(0, EFD_NONBLOCK);
    if (ev_reg_allow_changed == ERROR)
    {
        dzlog_fatal("Failed to create event %s", STR(ev_reg_allow_changed));
        sqlite3_close(sql_regthrd_rw_conn);
        sqlite3_shutdown();
        zlog_fini();
        return ERROR;
    }

    reg_thrd_ctx* rt_ctx = NULL;
    reg_ctx_init(&rt_ctx);
    accpt_thrd_ctx* at_ctx;
    worker_thrd_ctx* wt_ctx[num_worker_threads];

    worker_ctx_init(wt_ctx, num_worker_threads);
    accpt_ctx_init(&at_ctx);
    int32_t ctrl_sock_fd = server_start_tcp(INADDR_LOOPBACK, g_server_cfg->ctrl_port, 1, false);
    //fcntl(ctrl_sock_fd, F_SETFL, O_NONBLOCK);
    struct pollfd ctrl_pfd = {.fd = ctrl_sock_fd, .events = POLLIN, .revents = 0};

    free(g_server_cfg);
    //save_cfg("config.json", &cfg);
    //printf("cert_store: %s\n", cfg.cert_chain_path);
    return 0;
}
