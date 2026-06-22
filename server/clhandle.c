//
// Created by dominik on 6/8/26.
//

#include "clhandle.h"

#include "cltimerheap.h"
#include "servcfg.h"
#include "xalloc.h"

ATOMIC uint64_t curr_msg_id = 1;

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

void auth_send_resp(client* cl, net_fns* nfn, uint32_t resp_type)
{
    auth_resp resp = {.resp_code = htonl(resp_type)};
    nfn->send_fn(&cl->connection, &resp, sizeof(resp));
}

static void free_std_client(node* nd)
{
    net_fns* nfn = &g_server_cfg->networking_functions;
    std_client* stdc = container_of(std_client, nd, nd);
    nfn->disconnect_fn(&stdc->cl.connection);
    free(stdc->cl.temp_recv_storage.recvbuf.buf);
    mpscq_destroy(&stdc->pending_userdata_queue);
    mpscq_destroy(&stdc->pending_ctrl_queue);
    free(stdc->temp_send_storage->buf);
    free(stdc->temp_send_storage);
    free(stdc);
}

std_client* create_std_client(in_addr_t peer_name, int32_t clsock, uint8_t owner_thrd_id)
{
    std_client* stdc = (std_client*)xmalloc(sizeof(std_client));
    in_addr_t* ppeer_name = &stdc->cl.peer_name;
    *stdc = (std_client){
        .cl = {
            .connection = {.sock_fd = clsock, .ssl = NULL},
            .cl_state = INIT,
            .peer_name = peer_name,
            .ep_type = EP_CLIENT,
            .timerheap_index = INVAL_TH_IND,
            .auth_deadline = {.tv_nsec = 0, .tv_sec = 0},
            .temp_recv_storage = {
                .recvbuf = {
                    .buf = xmalloc(MAX_RECV_PDU_SIZE),
                    .buf_size = MAX_RECV_PDU_SIZE,
                    .buf_data_offset = 0
                },
                .expected_msg_size = 0,
                .total_msg_data_recved = 0,
                .msg_id = 0,
                .msg_type = MT_NONE,
                .dest_uname = {0}
            }
        },
        .nd = {
            .key = ppeer_name,
            .key_size = sizeof(in_addr_t),
            .next = NULL,
            .ref_cnt = 1,
            .free_fn = free_std_client
        },
        .owner_thrd_id = owner_thrd_id,
        .temp_send_storage = NULL
    };

    return stdc;
}

bool is_not_disconnected(node* nd)
{
    std_client* stdcl = container_of(std_client, nd, nd);
    return __atomic_load_n(&stdcl->cl.cl_state, __ATOMIC_SEQ_CST) != DISCONNECTED;
}