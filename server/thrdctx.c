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

bool reg_ctx_init(reg_thrd_ctx** reg_ctx, SSL_CTX* ssl_ctx, striped_htable* ip_whitelist_tbl)
{
    bool init_ok = true;
    sqlite3* dbc = NULL;
    int32_t ret_code = sqlite3_open_v2(g_server_cfg->db_file_path, &dbc, SQLITE_OPEN_READWRITE | SQLITE_OPEN_NOMUTEX, NULL);
    if (ret_code != SQLITE_OK)
    {
        dzlog_fatal("Failed to open database for R/W. Cause: %s", sqlite3_errmsg(dbc));
        if (dbc)
            sqlite3_close(dbc);
        dbc = NULL;
        init_ok = false;
    }
    striped_htable* reg_ipbtable = htable_create(IPBL_TBL_SIZE_POW2, IPBL_TBL_RESIZE_POW2,
                                                IPBL_TBL_THRES_LDFAC, IPBL_TBL_BKT_PER_LOCK_POW2, ip_cmp);

    int32_t regch_efd = eventfd(0, EFD_NONBLOCK);
    if (regch_efd == -1)
    {
        dzlog_fatal("Failed to create eventfd ev_reg_change. Cause: %s", strerror(errno));
        init_ok = false;
    }

    int32_t shtdn_efd = eventfd(0, EFD_NONBLOCK);
    if (shtdn_efd == -1)
    {
        dzlog_fatal("Failed to create eventfd ev_shutdown. Cause: %s", strerror(errno));
        init_ok = false;
    }
    reg_thrd_ctx temp = {.db_rw_handle = dbc,
                         .ssl_ctx = ssl_ctx,
                         .flg_reg_changed = regch_efd,
                         .flg_shutdown = shtdn_efd,
                         .reg_ipblock_tbl = reg_ipbtable,
                         .ip_whitelist_tbl = ip_whitelist_tbl};

    *reg_ctx = (reg_thrd_ctx*)xmalloc(sizeof(reg_thrd_ctx));
    memcpy(*reg_ctx, &temp, sizeof(temp));
    if (ssl_ctx)
        SSL_CTX_up_ref(ssl_ctx);
    return init_ok;
}

void reg_ctx_free(reg_thrd_ctx** reg_ctx)
{
    reg_thrd_ctx* rt_ctx = *reg_ctx;

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

    if (rt_ctx->flg_shutdown != ERROR)
        close(rt_ctx->flg_shutdown);

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

uint8_t worker_ctx_init(worker_thrd_ctx** w_ctx, uint8_t n)
{
    return false;
}

void worker_ctx_free(worker_thrd_ctx** w_ctx, uint8_t n)
{
    ;
}