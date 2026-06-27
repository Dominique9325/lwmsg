#ifndef LWMSG_CLIENT_H
#define LWMSG_CLIENT_H

#include <stdint.h>
#include <stdbool.h>
#include <openssl/ssl.h>
#include "lwmp.h"
#include "netwrap.h"

#define INPUT_LINE_MAX 4096
#define RECV_BUF_SIZE (LWMP_MAX_PDU_SIZE * 4)
#define USER_CACHE_MAX 256
#define AWAIT_RESP_TIMEOUT_MS 10000

enum client_state
{
    ST_DISCONNECTED,
    ST_CONNECTED
};

#define MAX_ACTIVE_TRANSFERS 8

typedef struct file_transfer
{
    bool active;
    FILE* fp;
    uint64_t expected_size;
    uint64_t received;
    char sender[UNAMESIZE + 1];
    char filename[OPTDATA_LEN + 1];
} file_transfer;

typedef struct client_ctx
{
    conn connection;
    net_fns nfns;
    SSL_CTX* ssl_ctx;
    int epoll_fd;
    enum client_state state;
    bool use_tls;
    char username[UNAMESIZE];
    char server_host[256];
    unsigned char recv_buf[RECV_BUF_SIZE];
    uint32_t recv_len;
    bool running;
    bool awaiting_resp;
    uint32_t last_resp_code;
    bool sending_chunks;
    bool transfer_error;
    file_transfer transfers[MAX_ACTIVE_TRANSFERS];
    char user_cache[USER_CACHE_MAX][UNAMESIZE + 1];
    int32_t user_cache_count;
} client_ctx;

#endif
