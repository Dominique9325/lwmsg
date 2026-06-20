//
// Created by gf-senka on 6/7/2026.
//

#ifndef LWMSG_THRDCTX_H
#define LWMSG_THRDCTX_H

#include <stdint.h>
#include <sqlite3.h>
#include <openssl/ssl.h>
#include <sys/eventfd.h>
#include <pthread.h>
#include <stdbool.h>
#include "thrdmsg_mpscq.h"
#include "htable.h"

enum thrd_st_state
{
    STS_NONE,
    STS_OK,
    STS_NOK,
};

extern pthread_mutex_t sync_lock;
extern pthread_cond_t sync_cond;
extern uint8_t thrd_startup_state;

typedef struct reg_thrd_ctx
{
    sqlite3* db_rw_handle;
    SSL_CTX* ssl_ctx;
    striped_htable* reg_ipblock_tbl;
    striped_htable* ip_whitelist_tbl;
    int32_t flg_reg_changed;
    int32_t flg_shutdown;
}reg_thrd_ctx;

typedef struct __attribute__((aligned(64))) worker_thrd_ctx
{
    sqlite3* db_rdonly_handle;
    SSL_CTX* ssl_ctx;
    striped_htable* client_tbl;
    striped_htable* std_ipblock_tbl;
    striped_htable* ip_whitelist_tbl;
    int32_t flg_shutdown;
    uint8_t thrd_id;
}worker_thrd_ctx;

bool reg_ctx_init(reg_thrd_ctx** reg_ctx, SSL_CTX* ssl_ctx, striped_htable* ip_whitelist_tbl, int32_t shutdown_efd);

void reg_ctx_free(reg_thrd_ctx** reg_ctx);

uint8_t worker_ctx_init(worker_thrd_ctx** w_ctx, uint8_t n, SSL_CTX* ssl_ctx, striped_htable* client_tbl,
                        striped_htable* std_ipblock_tbl, striped_htable* ip_whitelist_tbl, int32_t shutdown_efd);

void worker_ctx_free(worker_thrd_ctx** w_ctx, uint8_t n);

bool thrd_startup_sync();

bool coord_thrd_startup_sync(bool ok_cond);

#endif //LWMSG_THRDCTX_H
