#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <poll.h>
#include <errno.h>
#include <unistd.h>
#include <pthread.h>
#include <signal.h>
#include <arpa/inet.h>
#include <sys/sysinfo.h>
#include "ipblock.h"
#include "zlog.h"
#include "servcfg.h"
#include "thrdctx.h"
#include "netwrap.h"
#include "registration.h"
#include "worker.h"
#include "xalloc.h"

int main(int argc, char** argv)
{
    signal(SIGPIPE, SIG_IGN);
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

    int32_t shutdown_efd = eventfd(0, EFD_NONBLOCK);
    if (shutdown_efd == ERROR)
    {
        dzlog_fatal("Failed to create flg_ev_shutdown");
        goto cfg_init_fail;
    }

    uint8_t num_worker_threads = g_server_cfg->autoconf_nr_threads ? get_nprocs() : g_server_cfg->nr_worker_threads;
    dzlog_info("Server will use %hhu worker threads.", num_worker_threads);

    reg_thrd_ctx* rt_ctx = NULL;
    striped_htable* whitelist = htable_create(IPBL_TBL_SIZE_POW2, IPBL_TBL_RESIZE_POW2,
                                              IPBL_TBL_THRES_LDFAC, IPBL_TBL_BKT_PER_LOCK_POW2, ip_cmp);

    striped_htable* std_ipblock_tbl = htable_create(IPBL_TBL_SIZE_POW2, IPBL_TBL_RESIZE_POW2,
                                                    IPBL_TBL_THRES_LDFAC, IPBL_TBL_BKT_PER_LOCK_POW2, ip_cmp);

    striped_htable* client_tbl = htable_create(g_server_cfg->cl_htable_size_pow2,
                                               g_server_cfg->cl_htable_expansion_pow2,
                                               g_server_cfg->cl_htable_loadfactor_exp_thres,
                                               g_server_cfg->cl_htable_locks_pow2,
                                               std_client_cmp);

    bool res = reg_ctx_init(&rt_ctx, ssl_ctx, whitelist, shutdown_efd);
    if (!res)
    {
        dzlog_fatal("Registration thread context init failed. Aborting.");
        goto reg_thrd_ctx_init_fail;
    }

    worker_thrd_ctx* wt_ctx;
    uint8_t wrk_init_cnt = worker_ctx_init(&wt_ctx, num_worker_threads, ssl_ctx, client_tbl,
                                            std_ipblock_tbl, whitelist, shutdown_efd);
    if (wrk_init_cnt < num_worker_threads)
    {
        dzlog_fatal("Worker context init failed. Stopped at %hhu out of %hhu worker contexts.", wrk_init_cnt, num_worker_threads);
        goto wrk_thrd_ctx_init_fail;
    }

    whitelist_rec* wr = whitelist_rec_create(inet_addr("127.0.0.1"));
    htable_add(whitelist, &wr->nd);

    pthread_t reg_thrd;
    int32_t tr_lnch_res = pthread_create(&reg_thrd, NULL, reg_thrd_routine, rt_ctx);
    pthread_t* wrk_thrds = (pthread_t*)xmalloc(num_worker_threads * sizeof(pthread_t));
    uint8_t i;
    for (i = 0; i < num_worker_threads; i++)
    {
        if (pthread_create(&wrk_thrds[i], NULL, worker_thrd_routine, &wt_ctx[i]))
            break;
    }

    if (!coord_thrd_startup_sync(!tr_lnch_res && i == num_worker_threads))
    {
        dzlog_fatal("Failed to launch all threads. Aborting.");
        goto thrd_startup_failed;
    }



    sleep(10);
    //__atomic_store_n(&g_server_cfg->allow_regisrations, false, __ATOMIC_SEQ_CST);
    //eventfd_write(shutdown_efd, 1);
    // sleep(5);
    // //__atomic_store_n(&g_server_cfg->allow_regisrations, true, __ATOMIC_SEQ_CST);
    // write(rt_ctx->flg_reg_changed, &evvv, sizeof(eventfd_t));
    prog_retval = 0;

    thrd_startup_failed:
    if (!tr_lnch_res)
        pthread_join(reg_thrd, NULL);
    for (uint8_t j = 0; j < i; j++)
        pthread_join(wrk_thrds[j], NULL);
    free(wrk_thrds);

    wrk_thrd_ctx_init_fail:
    worker_ctx_free(&wt_ctx, wrk_init_cnt);
    htable_delete(client_tbl);
    htable_delete(std_ipblock_tbl);

    reg_thrd_ctx_init_fail:
    reg_ctx_free(&rt_ctx);
    htable_delete(whitelist);
    close(shutdown_efd);
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
