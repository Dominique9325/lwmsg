//
// Created by dominik on 6/13/26.
//

#ifndef LWMSG_CLTIMERHEAP_H
#define LWMSG_CLTIMERHEAP_H
#include "clhandle.h"

typedef struct cl_timerheap
{
    client** clients;
    uint64_t num_clients;
    uint64_t num_slots;
}cl_timerheap;

bool cl_timerheap_add(cl_timerheap* heap, client* cl);

client* cl_timerheap_pop(cl_timerheap* heap);

#endif //LWMSG_CLTIMERHEAP_H
