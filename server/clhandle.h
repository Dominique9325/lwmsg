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
#include "thrdmsg_mpscq.h"
#include "lwmp.h"
#include "netwrap.h"
#include "htable.h"
#include "util.h"

#define TMPBUF_SIZE 4096
#define INVAL_TH_IND (-1)

enum epoll_type
{
    EP_LISTENER,
    EP_EVENT,
    EP_CLIENT,
    EP_QUEUE
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
    AUTHENTICATED,
    REGISTERED
};

typedef struct curr_recv_msg
{
    buffer recvbuf;
    uint32_t expected_msg_size;
    uint16_t msg_id;
    uint16_t msg_type;
}curr_recv_msg;

typedef struct client
{
    uint64_t ep_type; // MUST BE THE FIRST ELEMENT BECAUSE OF TYPE PUNNING
    conn connection;
    int64_t timerheap_index;
    struct timespec auth_deadline;
    union
    {
        buffer tmpbuf_recv;
        curr_recv_msg temp_recv_storage;
    };
    in_addr_t peer_name;
    uint8_t cl_state;
}client;

typedef client reg_client;

typedef struct std_client
{
    client cl; // MUST BE THE FIRST ELEMENT BECAUSE OF TYPE PUNNING
    mpsc_msg_queue pending_userdata_queue;
    mpsc_msg_queue pending_ctrl_queue;
    mpsc_msg_node* temp_send_storage;
    node next;
    ATOMIC bool is_disconnected;
    char username[UNAMESIZE];
    uint8_t owner_thrd_id;
}std_client;

typedef struct reg_client_node
{
    reg_client cl;
    struct reg_client_node* next;
}reg_client_node;

typedef reg_client_node reg_client_list;

reg_client_list* list_create();

void list_add(reg_client_list* list, reg_client_node* cl);

void list_remove(reg_client_list* list, reg_client_node* cl);

void list_delete(reg_client_list* list);

int32_t std_client_cmp(const void* cla, const void* clb, uint32_t lena, uint32_t lenb);

#endif //LWMSG_CLHANDLE_H
