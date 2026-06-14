//
// Created by gf-senka on 6/7/2026.
//

#ifndef LWMSG_THRDCTX_H
#define LWMSG_THRDCTX_H

#include <stdint.h>
#include <sqlite3.h>
#include <openssl/ssl.h>
#include <sys/eventfd.h>
#include <stdbool.h>
#include "htable.h"

typedef struct reg_thrd_ctx
{
    sqlite3* db_rw_handle;
    SSL_CTX* ssl_ctx;
    striped_htable* reg_ipblock_tbl;
    int32_t flg_reg_changed;
}reg_thrd_ctx;

typedef struct accpt_thrd_ctx
{
    int a;
}accpt_thrd_ctx;

typedef struct worker_thrd_ctx
{
    sqlite3* db_rdonly_handle;
    SSL_CTX* ssl_ctx;
    uint8_t thrd_id;
}worker_thrd_ctx;

uint8_t reg_ctx_init(reg_thrd_ctx** reg_ctx);

void reg_ctx_free(reg_thrd_ctx** reg_ctx);

uint8_t accpt_ctx_init(accpt_thrd_ctx** accpt_ctx);

void accpt_ctx_free(accpt_thrd_ctx** accpt_ctx);

uint8_t worker_ctx_init(worker_thrd_ctx** w_ctx, uint8_t n);

void worker_ctx_free(worker_thrd_ctx** w_ctx, uint8_t n);

#endif //LWMSG_THRDCTX_H
