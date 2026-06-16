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
    uint32_t a_idx = (*a)->timerheap_index;
    uint32_t b_idx = (*b)->timerheap_index;
    client* temp = *a;
    *a = *b;
    *b = temp;
    (*a)->timerheap_index = a_idx;
    (*b)->timerheap_index = b_idx;
}

static bool cl_timerheap_resize(cl_timerheap* heap)
{
    uint32_t new_num_slots = heap->num_slots << 1;
    if (new_num_slots < heap->num_slots)
    {
        dzlog_error("Timerheap resize overflow.");
        return false;
    }

    client** temp = xrealloc(heap->clients, new_num_slots * sizeof(client*));
    heap->clients = temp;
    memset(&heap->clients[heap->num_slots], 0, (new_num_slots - heap->num_slots) * sizeof(client*));
    heap->num_slots = new_num_slots;
    return true;
}

static void cl_timerheap_heapify_up(cl_timerheap* heap, uint32_t index)
{
    while (index > 0 && MIN(heap->clients, index, (index - 1) / 2) == index)
    {
        swap(&heap->clients[index], &heap->clients[(index - 1) / 2]);
        index = (index - 1) / 2;
    }
}

static void cl_timerheap_heapify_down(cl_timerheap* heap, uint32_t index)
{
    uint32_t max_index = heap->num_clients - 1;
    uint32_t new_index = 0;

    while (true)
    {
        uint32_t lchild_index = 2 * index + 1;
        uint32_t rchild_index = 2 * index + 2;
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
}


bool cl_timerheap_add(cl_timerheap* heap, client* cl)
{
    assert(heap && heap->clients && heap->num_slots && cl);

    if (heap->num_clients == heap->num_slots)
    {
        if (!cl_timerheap_resize(heap))
            return false;
    }

    uint32_t index = heap->num_clients++;
    heap->clients[index] = cl;
    cl->timerheap_index = index;
    cl_timerheap_heapify_up(heap, index);
    return true;
}

client* cl_timerheap_peek(cl_timerheap* heap)
{
    assert(heap && heap->clients && heap->num_slots);

    if (heap->num_clients)
        return heap->clients[0];

    return NULL;
}

client* cl_timerheap_pop(cl_timerheap* heap)
{
    assert(heap && heap->clients && heap->num_slots);

    if (!heap->num_clients)
        return NULL;

    client* popped = heap->clients[0];
    uint32_t max_index = --heap->num_clients;
    if (!heap->num_clients)
    {
        popped->timerheap_index = INVAL_TH_IND;
        return popped;
    }

    swap(&heap->clients[0], &heap->clients[max_index]);
    popped->timerheap_index = INVAL_TH_IND;
    cl_timerheap_heapify_down(heap, 0);
    return popped;
}

void cl_timerheap_remove(cl_timerheap* heap, client* cl)
{
    assert(heap && cl && heap->clients && heap->num_slots);
    if (!heap->num_clients || cl->timerheap_index == INVAL_TH_IND)
        return;
    uint32_t index = cl->timerheap_index;
    heap->num_clients--;
    if (!heap->num_clients || index == heap->num_clients)
    {
        cl->timerheap_index = INVAL_TH_IND;
        return;
    }

    swap(&heap->clients[index], &heap->clients[heap->num_clients]);
    cl->timerheap_index = INVAL_TH_IND;

    if (!index)
    {
        cl_timerheap_heapify_down(heap, index);
        return;
    }

    uint32_t parent_index = (index - 1) / 2;

    if (MIN(heap->clients, index, parent_index) == index)
        cl_timerheap_heapify_up(heap, index);
    else
        cl_timerheap_heapify_down(heap, index);
}