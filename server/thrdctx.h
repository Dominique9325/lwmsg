//
// Created by gf-senka on 6/7/2026.
//

#ifndef LWMSG_THRDCTX_H
#define LWMSG_THRDCTX_H

#include <stdint.h>
#include <sqlite3.h>
#include <openssl/ssl.h>

typedef struct reg_thrd_ctx
{
    sqlite3* db_rw_handle;
    SSL_CTX* ssl_ctx;

    uint8_t thrd_id;
}reg_thrd_ctx;

#endif //LWMSG_THRDCTX_H
