//
// Created by dominik on 6/8/26.
//

#ifndef LWMSG_CLHANDLE_H
#define LWMSG_CLHANDLE_H
#include <stdint.h>
#include <openssl/ssl.h>
#include <stdatomic.h>
#include <netinet/in.h>
#include "netwrap.h"
#define TMPBUF_SIZE 2048
#define UNAMESIZE 32

enum client_state
{
    CONN_OK,
    TLS_HANDSHAKING,
    TLS_OK,
    TLS_FAILED,
    EXPECTING_DATA,
    DISCONNECTED
};

typedef struct client
{
    conn connection;
    struct sockaddr peer_name;
    uint8_t cl_state;
    char tmpbuf_recv[TMPBUF_SIZE];
    char tmbuf_send[TMPBUF_SIZE];
    char padding[7];
}client;

typedef struct user
{
    client* conn_handle;
    struct user* next;
    uint8_t thr_id;
    _Atomic uint8_t is_disconnected;
    char username[UNAMESIZE];
}user;

#endif //LWMSG_CLHANDLE_H
