//
// Created by dominik on 6/8/26.
//

#include "clhandle.h"
#include "xalloc.h"

void client_add(client_arr* arr, client* cl)
{
    if (arr->num_clients == arr->num_slots)
    {
        arr->num_slots <<= 1ULL;
        arr->clients = xrealloc(arr->clients, arr->num_slots * sizeof(client));
    }

    client* dest = &arr->clients[arr->num_clients++];
    memcpy(dest, cl, sizeof(client));
}

void client_remove(client_arr* arr, client* cl)
{
    client tmp = arr->clients[arr->num_clients - 1];
    arr->clients[arr->num_clients - 1] = *cl;
    *cl = tmp;
    arr->num_clients--;
}