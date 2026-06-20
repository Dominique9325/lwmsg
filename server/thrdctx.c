//
// Created by gf-senka on 6/7/2026.
//
#include <errno.h>
#include <unistd.h>
#include "thrdctx.h"
#include "servcfg.h"
#include "xalloc.h"
#include "zlog.h"
#include "ipblock.h"

pthread_mutex_t sync_lock = PTHREAD_MUTEX_INITIALIZER;
pthread_cond_t sync_cond = PTHREAD_COND_INITIALIZER;
uint8_t thrd_startup_state = STS_NONE;

bool reg_ctx_init(reg_thrd_ctx** reg_ctx, SSL_CTX* ssl_ctx, striped_htable* ip_whitelist_tbl, int32_t shutdown_efd)
{
    bool init_ok = true;
    sqlite3 *dbc = NULL;
    int32_t ret_code = sqlite3_open_v2(g_server_cfg->db_file_path, &dbc, SQLITE_OPEN_READWRITE | SQLITE_OPEN_NOMUTEX,
                                       NULL);
    if (ret_code != SQLITE_OK)
    {
        dzlog_fatal("Failed to open database for R/W. Cause: %s", sqlite3_errmsg(dbc));
        if (dbc)
            sqlite3_close(dbc);
        dbc = NULL;
        init_ok = false;
    }
    striped_htable *reg_ipbtable = htable_create(IPBL_TBL_SIZE_POW2, IPBL_TBL_RESIZE_POW2,
                                                 IPBL_TBL_THRES_LDFAC, IPBL_TBL_BKT_PER_LOCK_POW2, ip_cmp);

    int32_t regch_efd = eventfd(0, EFD_NONBLOCK);
    if (regch_efd == -1)
    {
        dzlog_fatal("Failed to create eventfd ev_reg_change. Cause: %s", strerror(errno));
        init_ok = false;
    }

    reg_thrd_ctx temp = {
        .db_rw_handle = dbc,
        .ssl_ctx = ssl_ctx,
        .flg_reg_changed = regch_efd,
        .flg_shutdown = shutdown_efd,
        .reg_ipblock_tbl = reg_ipbtable,
        .ip_whitelist_tbl = ip_whitelist_tbl
    };

    *reg_ctx = (reg_thrd_ctx *) xmalloc(sizeof(reg_thrd_ctx));
    memcpy(*reg_ctx, &temp, sizeof(temp));
    if (ssl_ctx)
        SSL_CTX_up_ref(ssl_ctx);
    return init_ok;
}

void reg_ctx_free(reg_thrd_ctx** reg_ctx)
{
    reg_thrd_ctx *rt_ctx = *reg_ctx;

    rt_ctx->ip_whitelist_tbl = NULL;

    if (rt_ctx->reg_ipblock_tbl)
    {
        htable_delete(rt_ctx->reg_ipblock_tbl);
        rt_ctx->reg_ipblock_tbl = NULL;
    }

    if (rt_ctx->db_rw_handle)
    {
        sqlite3_close_v2(rt_ctx->db_rw_handle);
        rt_ctx->db_rw_handle = NULL;
    }

    if (rt_ctx->flg_reg_changed != ERROR)
        close(rt_ctx->flg_reg_changed);

    if (rt_ctx->ssl_ctx)
    {
        SSL_CTX_free(rt_ctx->ssl_ctx);
        rt_ctx->ssl_ctx = NULL;
    }

    free(*reg_ctx);
    *reg_ctx = NULL;
}

uint8_t worker_ctx_init(worker_thrd_ctx** w_ctx, uint8_t n, SSL_CTX* ssl_ctx, striped_htable* client_tbl,
                        striped_htable* std_ipblock_tbl, striped_htable* ip_whitelist_tbl, int32_t shutdown_efd)
{
    worker_thrd_ctx *wt_ctx = (worker_thrd_ctx*)xcalloc(n, sizeof(worker_thrd_ctx));
    *w_ctx = wt_ctx;
    uint8_t i;
    for (i = 0; i < n; i++)
    {
        wt_ctx[i].client_tbl = client_tbl;
        int32_t retcode = sqlite3_open_v2(g_server_cfg->db_file_path, &wt_ctx[i].db_rdonly_handle,
                                          SQLITE_OPEN_READONLY | SQLITE_OPEN_NOMUTEX, NULL);
        if (retcode != SQLITE_OK)
        {
            dzlog_fatal("Failed to open the database for reading.");
            if (wt_ctx[i].db_rdonly_handle)
            {
                sqlite3_close_v2(wt_ctx[i].db_rdonly_handle);
                wt_ctx[i].db_rdonly_handle = NULL;
            }
            break;
        }

        wt_ctx[i].flg_shutdown = shutdown_efd;
        wt_ctx[i].std_ipblock_tbl = std_ipblock_tbl;
        wt_ctx[i].ip_whitelist_tbl = ip_whitelist_tbl;
        wt_ctx[i].thrd_id = i;
        wt_ctx[i].ssl_ctx = ssl_ctx;
        if (ssl_ctx)
            SSL_CTX_up_ref(ssl_ctx);
    }

    return i;
}

void worker_ctx_free(worker_thrd_ctx** w_ctx, uint8_t n)
{
    for (uint8_t i = 0; i < n; i++)
    {
        if ((*w_ctx)[i].db_rdonly_handle)
        {
            sqlite3_close_v2((*w_ctx)[i].db_rdonly_handle);
            (*w_ctx)[i].db_rdonly_handle = NULL;
        }

        if ((*w_ctx)[i].ssl_ctx)
        {
            SSL_CTX_free((*w_ctx)[i].ssl_ctx);
            (*w_ctx)[i].ssl_ctx = NULL;
        }

        (*w_ctx)[i].flg_shutdown = ERROR;
        (*w_ctx)[i].client_tbl = NULL;
        (*w_ctx)[i].std_ipblock_tbl = NULL;
        (*w_ctx)[i].ip_whitelist_tbl = NULL;
    }

    free(*w_ctx);
    *w_ctx = NULL;
}

bool thrd_startup_sync()
{
    pthread_mutex_lock(&sync_lock);
    while (thrd_startup_state == STS_NONE) // NOLINT Note: warning is a false positive, value is updated in main().
        pthread_cond_wait(&sync_cond, &sync_lock);
    bool startup_ok = thrd_startup_state == STS_OK ? true : false;
    pthread_mutex_unlock(&sync_lock);
    return startup_ok;
}

bool coord_thrd_startup_sync(bool ok_cond)
{
    pthread_mutex_lock(&sync_lock);
    if (ok_cond)
        thrd_startup_state = STS_OK;
    else
        thrd_startup_state = STS_NOK;
    pthread_cond_broadcast(&sync_cond);
    pthread_mutex_unlock(&sync_lock);
    return ok_cond;
}