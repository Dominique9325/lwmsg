//
// Created by dominik on 6/8/26.
//

#ifndef LWMSG_CLHANDLE_H
#define LWMSG_CLHANDLE_H
#include <stdint.h>
#include <openssl/ssl.h>
#include <stdatomic.h>
#include <netinet/in.h>
#include <time.h>
#include "netwrap.h"
#include "htable.h"

#define TMPBUF_SIZE 2048
#define UNAMESIZE 32
#define DEF_CL_ARR_SIZE 128

enum client_state
{
    ACCEPTING,
    ACCEPTED,
    AUTHENTICATING,
    AUTHENTICATED
};

typedef struct user
{
    node* next;
    uint8_t thr_id;
    ATOMIC uint8_t is_disconnected;
    char username[UNAMESIZE];
}user;

typedef struct client
{
    conn connection;
    user usr;
    struct timespec auth_deadline;
    void* tmpbuf_recv;
    void* tmbuf_send;
    socklen_t peer_name_size;
    struct sockaddr peer_name;
    uint8_t cl_state;
}client;

typedef struct client_arr
{
    client* clients;
    uint64_t num_clients;
    uint64_t num_slots;
}client_arr;

void client_add(client_arr* arr, client* cl);

void client_remove(client_arr* arr, client* cl);

#endif //LWMSG_CLHANDLE_H
