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
#define DEF_STDCL_DCONARR_SIZE 256


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
    // shared states (reg client and std client)
    INIT,
    ACCEPTING,
    ACCEPTED,
    DISCONNECTED,

    // reg client only
    REGISTERED,

    // std client only
    AUTHENTICATED
};

extern ATOMIC uint64_t curr_msg_id;

typedef struct curr_recv_msg
{
    buffer recvbuf;
    uint64_t expected_msg_size;
    uint64_t total_msg_data_recved;
    uint32_t msg_id;
    uint32_t msg_type;
    char dest_uname[UNAMESIZE];
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
    ATOMIC uint8_t cl_state;
}client;

typedef client reg_client;

typedef struct std_client
{
    client cl; // MUST BE THE FIRST ELEMENT BECAUSE OF TYPE PUNNING
    mpsc_msg_queue pending_userdata_queue;
    mpsc_msg_queue pending_ctrl_queue;
    mpsc_msg_node* temp_send_storage;
    node nd;
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

void auth_send_resp(client* cl, net_fns* nfn, uint32_t resp_type);

std_client* create_std_client(in_addr_t peer_name, int32_t clsock, uint8_t owner_thrd_id);

bool is_not_disconnected(node* nd);

#endif //LWMSG_CLHANDLE_H
