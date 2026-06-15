//
// Created by dominik on 6/8/26.
//

#include "clhandle.h"
#include "xalloc.h"

client_list* list_create()
{
    client_list* list = (client_list*)xcalloc(1, sizeof(client_list));
    return list;
}

void list_add(client_list* list, client_node* cl)
{
    if (!list->next)
    {
        list->next = cl;
        return;
    }

    cl->next = list->next;
    list->next = cl;
}

void list_remove(client_list* list, client_node* cl)
{
    if (!list->next || !cl)
        return;

    client_node* curr = list->next;
    client_node* prev = NULL;

    while (curr && cl != curr)
    {
        prev = curr;
        curr = curr->next;
    }

    if (!curr)
        return;

    if (!prev)
        list->next = cl->next;
    else
        prev->next = cl->next;

    cl->next = NULL;
}

client* client_add(client_arr* arr, client* cl)
{
    if (arr->num_clients == arr->num_slots)
    {
        arr->num_slots <<= 1ULL;
        arr->clients = xrealloc(arr->clients, arr->num_slots * sizeof(client));
    }

    client* dest = &arr->clients[arr->num_clients++];
    *dest = *cl;
    return dest;
}

void client_remove(client_arr* arr, client* cl)
{
    client tmp = arr->clients[arr->num_clients - 1];
    arr->clients[arr->num_clients - 1] = *cl;
    *cl = tmp;
    arr->num_clients--;
}