//
// Created by dominik on 6/19/26.
//

#include <sys/eventfd.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <stdbool.h>
#include "thrdmsg_mpscq.h"
#include "clhandle.h"
#include "zlog.h"
#include "xalloc.h"



bool mpscq_create(mpsc_msg_queue* dest, uint8_t queue_mode)
{
    mpsc_msg_queue temp = {.qmode = queue_mode, .tail = NULL, .head = {0}, .ep_type = EP_QUEUE};
    *dest = temp;

    if (queue_mode == MODE_MPSC)
    {
        dest->eventfd = eventfd(0, EFD_SEMAPHORE | EFD_NONBLOCK);
        if (dest->eventfd == -1)
            return false;

        if (pthread_mutex_init(&dest->lock, NULL))
        {
            close(dest->eventfd);
            return false;
        }
    }
    return true;
}

void mpscq_enqueue(mpsc_msg_queue* mpscq, mpsc_msg_node* msg)
{
    if (!msg)
        return;
    if (mpscq->qmode == MODE_MPSC)
        pthread_mutex_lock(&mpscq->lock);

    msg->prev = NULL;
    if (!mpscq->head.next)
    {
        mpscq->tail = msg;
        mpscq->head.next = msg;
        msg->next = NULL;
    }
    else
    {
        msg->next = mpscq->head.next;
        mpscq->head.next->prev = msg;
        mpscq->head.next = msg;
    }

    if (mpscq->qmode == MODE_MPSC)
    {
        eventfd_write(mpscq->eventfd, 1);
        pthread_mutex_unlock(&mpscq->lock);
    }
}

mpsc_msg_node* mpscq_dequeue(mpsc_msg_queue* mpscq)
{
    if (mpscq->qmode == MODE_MPSC)
        pthread_mutex_lock(&mpscq->lock);

    if (!mpscq->tail)
    {
        if (mpscq->qmode == MODE_MPSC)
        {
            pthread_mutex_unlock(&mpscq->lock);
            dzlog_debug("This should not happen.");
        }
        return NULL;
    }

    if (mpscq->qmode == MODE_MPSC)
    {
        eventfd_t efdt;
        eventfd_read(mpscq->eventfd, &efdt);
    }

    mpsc_msg_node* temp = mpscq->tail;
    if (!mpscq->tail->prev)
    {
        mpscq->head.next = NULL;
        mpscq->tail = NULL;
    }
    else
    {
        mpscq->tail->prev->next = NULL;
        mpscq->tail = mpscq->tail->prev;
    }

    temp->prev = NULL;
    if (mpscq->qmode == MODE_MPSC)
        pthread_mutex_unlock(&mpscq->lock);
    return temp;
}

// Note: Only to be called when one is absolutely sure nobody will use the queue anymore.
void mpscq_destroy(mpsc_msg_queue* mpscq)
{
    if (mpscq->qmode == MODE_MPSC)
        pthread_mutex_lock(&mpscq->lock);
    mpsc_msg_node* temp = mpscq->head.next;
    mpsc_msg_node* temp2 = NULL;
    while (temp)
    {
        temp2 = temp;
        temp = temp->next;
        free(temp2->buf);
        free(temp2);
    }

    if (mpscq->qmode == MODE_MPSC)
    {
        close(mpscq->eventfd);
        pthread_mutex_unlock(&mpscq->lock);
        pthread_mutex_destroy(&mpscq->lock);
    }
}

void mpscq_flush_msgs_with_subject(mpsc_msg_queue* mpscq, char* subject)
{
    if (mpscq->qmode == MODE_SPSC)
        return;

    pthread_mutex_lock(&mpscq->lock);
    mpsc_msg_node* mnode = mpscq->head.next;
    mpsc_msg_node* temp = NULL;
    while (mnode)
    {
        int32_t cmpres = strncmp(mnode->subject_name, subject, UNAMESIZE);
        if (cmpres)
        {
            mnode = mnode->next;
            continue;
        }

        if (mpscq->tail == mnode)
            mpscq->tail = mnode->prev;

        if (mnode->prev)
        {
            mnode->prev->next = mnode->next;
        }
        else
        {
            mpscq->head.next = mnode->next;
        }

        if (mnode->next)
        {
            mnode->next->prev = mnode->prev;
        }

        temp = mnode;
        mnode = mnode->next;
        temp->next = NULL;
        temp->prev = NULL;
        free(temp->buf);
        free(temp);
        eventfd_t efdval;
        eventfd_read(mpscq->eventfd, &efdval);
    }
    pthread_mutex_unlock(&mpscq->lock);
}

int32_t mpscq_get_efd(mpsc_msg_queue* mpscq)
{
    return mpscq->eventfd;
}

mpsc_msg_node* msg_node_create(void* buf, uint64_t buf_size, char* subject_name)
{
    mpsc_msg_node* msg = (mpsc_msg_node*)xmalloc(sizeof(mpsc_msg_node));
    *msg = (mpsc_msg_node){
        .buf = xmalloc(buf_size),
        .buf_size = buf_size,
        .buf_offset = 0,
        .prev = NULL,
        .next = NULL
    };

    if (subject_name)
        strncpy(msg->subject_name, subject_name, UNAMESIZE);
    else
        msg->subject_name[0] = '\0';

    if (buf)
        memcpy(msg->buf, buf, buf_size);
    return msg;
}