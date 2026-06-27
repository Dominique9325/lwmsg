//
// Created by dominik on 6/19/26.
//

#ifndef LWMSG_THRDMSG_MPSCQ_H
#define LWMSG_THRDMSG_MPSCQ_H
#include <stdbool.h>
#include "lwmp.h"

enum msgq_mode
{
    MODE_SPSC,
    MODE_MPSC
};

typedef struct mpsc_msg_node
{
    struct mpsc_msg_node* next;
    struct mpsc_msg_node* prev;
    void* buf;
    uint32_t buf_size;
    uint32_t buf_offset;
    char subject_name[UNAMESIZE];
}mpsc_msg_node;

typedef struct mpsc_msg_queue
{
    uint64_t ep_type;
    mpsc_msg_node head;
    mpsc_msg_node* tail;
    pthread_mutex_t lock;
    int32_t eventfd;
    uint8_t qmode;
}mpsc_msg_queue;

bool mpscq_create(mpsc_msg_queue* dest, uint8_t queue_mode);

void mpscq_enqueue(mpsc_msg_queue* mpscq, mpsc_msg_node* msg);

mpsc_msg_node* mpscq_dequeue(mpsc_msg_queue* mpscq);

void mpscq_destroy(mpsc_msg_queue* mpscq);

void mpscq_flush_msgs_with_subject(mpsc_msg_queue* mpscq, char* subject);

int32_t mpscq_get_efd(mpsc_msg_queue* mpscq);

mpsc_msg_node* msg_node_create(void* buf, uint64_t buf_size, char* subject_name);

#endif //LWMSG_THRDMSG_MPSCQ_H
