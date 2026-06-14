//
// Created by dominik on 6/13/26.
//
#include <assert.h>
#include "xalloc.h"
#include "zlog.h"
#include "cltimerheap.h"
#define MIN(h, a, b) h[a]->auth_deadline.tv_sec < h[b]->auth_deadline.tv_sec ? a : \
                     (h[a]->auth_deadline.tv_sec != h[b]->auth_deadline.tv_sec ? b : \
                     (h[a]->auth_deadline.tv_nsec < h[b]->auth_deadline.tv_nsec ? a : b))

static void swap(client** a, client**b)
{
    client* temp = *a;
    *a = *b;
    *b = temp;
}

static bool cl_timerheap_resize(cl_timerheap* heap)
{
    uint64_t new_num_slots = heap->num_slots << 1;
    if (new_num_slots < heap->num_slots)
    {
        dzlog_error("Timerheap resize overflow.");
        return false;
    }

    client** temp = xrealloc(heap->clients, new_num_slots * sizeof(client*));
    heap->clients = temp;
    memset(&heap->clients[heap->num_slots], 0, new_num_slots - heap->num_slots);
    heap->num_slots = new_num_slots;
    return true;
}

bool cl_timerheap_add(cl_timerheap* heap, client* cl)
{
    assert(heap && heap->clients && heap->num_slots && cl);

    if (heap->num_clients == heap->num_slots)
    {
        if (!cl_timerheap_resize(heap))
            return false;
    }

    uint64_t index = heap->num_clients++;
    heap->clients[index] = cl;

    while (index > 0 && MIN(heap->clients, index, (index - 1) / 2) == index)
    {
        swap(&heap->clients[index], &heap->clients[(index - 1) / 2]);
        index = (index - 1) / 2;
    }
    return true;
}

client* cl_timerheap_pop(cl_timerheap* heap)
{
    assert(heap && heap->clients && heap->num_slots);

    if (!heap->num_clients)
        return NULL;

    client* popped = heap->clients[0];
    uint64_t max_index = --heap->num_clients;
    swap(&heap->clients[0], &heap->clients[max_index]);
    uint64_t index = 0;
    uint64_t new_index = 0;

    while (true)
    {
        uint64_t lchild_index = 2 * index + 1;
        uint64_t rchild_index = 2 * index + 2;
        client* lchild = NULL;
        client* rchild = NULL;


        if (lchild_index <= max_index)
            lchild = heap->clients[lchild_index];

        if (rchild_index <= max_index)
            rchild = heap->clients[rchild_index];

        if (!lchild && !rchild)
            break;
        else if (!rchild)
            new_index = lchild_index;
        else
            new_index = MIN(heap->clients, lchild_index, rchild_index);

        if (MIN(heap->clients, index, new_index) == new_index)
        {
            swap(&heap->clients[index], &heap->clients[new_index]);
            index = new_index;
        }
        else break;
    }

    return popped;
}