//
// Created by dominik on 6/13/26.
//

#ifndef LWMSG_CLTIMERHEAP_H
#define LWMSG_CLTIMERHEAP_H
#include <stdbool.h>
#include "clhandle.h"

#define DEF_CLTH_SIZE 256

#define CLTH_EMPTY (-1)
#define CLTH_TIMEOUT (-2)
#define CLTH_NOT_APPLICABLE (-3)


#define CLTH_REG_MAXPERM_TIME 4 // 4 s
#define CLTH_AUTH_MAXPERM_TIME 4 // 4 s

typedef struct cl_timerheap
{
    client** clients;
    uint64_t num_clients;
    uint64_t num_slots;
}cl_timerheap;

bool cl_timerheap_add(cl_timerheap* heap, client* cl);

client* cl_timerheap_peek(cl_timerheap* heap);

int64_t cl_timerheap_compute_root_timediff(cl_timerheap* heap, int64_t max_perm_timediff);

client* cl_timerheap_pop(cl_timerheap* heap);

void cl_timerheap_remove(cl_timerheap* heap, client* cl);

#endif //LWMSG_CLTIMERHEAP_H
