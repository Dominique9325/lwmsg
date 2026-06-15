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
#define REG_MAXPERM_TIME 4 // 4 s
#define INVAL_TH_IND (-1)

enum epoll_type
{
    EP_LISTENER,
    EP_EVENT,
    EP_CLIENT
};

typedef struct epoll_ctx
{
    uint64_t type;
    int32_t fd;
}epoll_ctx;

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
    uint64_t ep_type; // MUST BE THE FIRST ELEMENT BECAUSE OF TYPE PUN
    conn connection;
    user usr;
    int64_t timerheap_index;
    struct timespec auth_deadline;
    void* tmpbuf_recv;
    void* tmbuf_send;
    in_addr_t peer_name;
    uint8_t cl_state;
}client;

typedef struct client_arr
{
    client* clients;
    uint64_t num_clients;
    uint64_t num_slots;
}client_arr;

typedef struct client_node
{
    client cl;
    struct client_node* next;
}client_node;

typedef client_node client_list;

client_list* list_create();

void list_add(client_list* list, client_node* cl);

void list_remove(client_list* list, client_node* cl);

void list_delete(client_list* list);

client* client_add(client_arr* arr, client* cl);

void client_remove(client_arr* arr, client* cl);

#endif //LWMSG_CLHANDLE_H
