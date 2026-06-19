#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <poll.h>
#include <errno.h>
#include <unistd.h>
#include <pthread.h>
#include <arpa/inet.h>
#include <sys/sysinfo.h>
#include "ipblock.h"
#include "zlog.h"
#include "servcfg.h"
#include "thrdctx.h"
#include "netwrap.h"
#include "registration.h"

int main(int argc, char** argv)
{
    int32_t prog_retval = ERROR;
    char* cfg_path = getopt(argc, argv, "c:") != -1 ? optarg : "config.json"; // TBR: If I need more CLI args.
    load_cfg(cfg_path);
    SSL_CTX* ssl_ctx = NULL;

    if (dzlog_init(g_server_cfg->zlog_config_path, "lwmsg"))
    {
        fprintf(stderr, "Fatal error: Failed to locate a valid zlog configuration file.\n");
        goto zlog_init_fail;
    }
    zlog_put_mdc("thrd_id", "main");
    zlog_category_t* zct = zlog_get_category("lwmsg");
    zlog_level_switch(zct, ZLOG_LEVEL_DEBUG);
    setup_tls(&ssl_ctx);
    load_netfns();

    if (g_server_cfg->use_tls && !ssl_ctx)
        goto cfg_init_fail;

    in_addr_t server_main_if = inet_addr(g_server_cfg->gen_interface);
    if (!is_if_valid(server_main_if))
    {
        dzlog_fatal("'%s' is an invalid interface, shutting down.", g_server_cfg->gen_interface);
        goto cfg_init_fail;
    }

    uint8_t num_worker_threads = g_server_cfg->autoconf_nr_threads ? get_nprocs() : g_server_cfg->nr_worker_threads;
    dzlog_info("Server will use %hhu worker threads.", num_worker_threads);

    reg_thrd_ctx* rt_ctx = NULL;
    striped_htable* whitelist = htable_create(IPBL_TBL_SIZE_POW2, IPBL_TBL_RESIZE_POW2,
                                              IPBL_TBL_THRES_LDFAC, IPBL_TBL_BKT_PER_LOCK_POW2, ip_cmp);
    bool res = reg_ctx_init(&rt_ctx, ssl_ctx, whitelist);
    if (!res)
    {
        dzlog_fatal("Registration thread initialization failed. Aborting.");
        goto reg_thrd_init_fail;
    }


    whitelist_rec* wr = whitelist_rec_create(inet_addr("127.0.0.1"));
    htable_add(whitelist, &wr->nd);
    pthread_t reg_thrd;
    int32_t tr_lnch_res = pthread_create(&reg_thrd, NULL, reg_thrd_routine, rt_ctx);
     if (tr_lnch_res)
     {
         dzlog_fatal("Failed to start registration thread. Cause: %s", strerror(errno));
         goto reg_thrd_init_fail;
     }

    sleep(10);
    eventfd_t evvv = 43;
    //__atomic_store_n(&g_server_cfg->allow_regisrations, false, memory_order_seq_cst);
    //write(rt_ctx->flg_shutdown, &evvv, sizeof(eventfd_t));
    // sleep(5);
    // //__atomic_store_n(&g_server_cfg->allow_regisrations, true, memory_order_seq_cst);
    // write(rt_ctx->flg_reg_changed, &evvv, sizeof(eventfd_t));
    void* retval;
    pthread_join(reg_thrd, &retval);

    // accpt_thrd_ctx* at_ctx;
    // worker_thrd_ctx* wt_ctx[num_worker_threads];

    // worker_ctx_init(wt_ctx, num_worker_threads);
    // accpt_ctx_init(&at_ctx);
    // int32_t ctrl_sock_fd = server_start_tcp(INADDR_LOOPBACK, g_server_cfg->ctrl_port, 1, false);
    //fcntl(ctrl_sock_fd, F_SETFL, O_NONBLOCK);
    // struct pollfd ctrl_pfd = {.fd = ctrl_sock_fd, .events = POLLIN, .revents = 0};
    prog_retval = 0;
    reg_thrd_init_fail:
    reg_ctx_free(&rt_ctx);
    htable_delete(whitelist);
    dzlog_notice("Shutting down server.");
    cfg_init_fail:
    zlog_fini();
    if (ssl_ctx)
        SSL_CTX_free(ssl_ctx);
    zlog_init_fail:
    save_cfg(cfg_path);
    free(g_server_cfg);
    return prog_retval;
}
