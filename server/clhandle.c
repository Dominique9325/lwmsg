//
// Created by dominik on 6/8/26.
//

#include "clhandle.h"
#include "xalloc.h"

uint64_t curr_msg_id = 0;

reg_client_list* list_create()
{
    reg_client_list* list = (reg_client_list*)xcalloc(1, sizeof(reg_client_list));
    return list;
}

void list_add(reg_client_list* list, reg_client_node* cl)
{
    cl->next = NULL;

    if (!list->next)
    {
        list->next = cl;
        return;
    }

    cl->next = list->next;
    list->next = cl;
}

void list_remove(reg_client_list* list, reg_client_node* cl)
{
    if (!list->next || !cl)
        return;

    reg_client_node* curr = list->next;
    reg_client_node* prev = NULL;

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

int32_t std_client_cmp(const void* cla, const void* clb, uint32_t lena, uint32_t lenb)
{
    const char* unamea = (const char*)cla;
    const char* unameb = (const char*)clb;
    int32_t res = strncmp(unamea, unameb, lena < lenb ? lena : lenb);
    return res;
}

void req_send_resp(client* cl, net_fns* nfn, uint32_t resp_type)
{
    auth_resp resp = {.resp_code = htonl(resp_type)};
    nfn->send_fn(&cl->connection, &resp, sizeof(resp));
}