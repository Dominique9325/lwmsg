//
// Created by dominik on 6/18/26.
//

#include <sys/epoll.h>
#include <unistd.h>
#include "thrdctx.h"
#include "worker.h"
#include <errno.h>
#include <endian.h>
#include <arpa/inet.h>
#include "clhandle.h"
#include "cltimerheap.h"
#include "dbops.h"
#include "ipblock.h"
#include "xalloc.h"
#include "zlog.h"
#include "servcfg.h"

#define THRDNAME_LEN 16
#define MAX_REVENTS 1024
#define WORKER_BACKLOG 1024
#define min(a, b) ((a) < (b) ? (a) : (b))

typedef struct stdcl_containers
{
    striped_htable* std_cl_table;
    dummy_node* preauth_list;
    cl_timerheap* clth;
    node_arr* dconn_clients;
}stdcl_containers;

static void cleanup_std_client(stdcl_containers* cont, node* client_node, int32_t epollfd)
{
    std_client* stdc = container_of(std_client, nd, client_node);
    uint8_t clstate = __atomic_load_n(&stdc->cl.cl_state, __ATOMIC_SEQ_CST);
    net_fns* nfn = &g_server_cfg->networking_functions;

    switch (clstate)
    {
        case AUTHENTICATED:
            __atomic_store_n(&stdc->cl.cl_state, DISCONNECTED, __ATOMIC_SEQ_CST);
            epoll_ctl(epollfd, EPOLL_CTL_DEL, stdc->pending_userdata_queue.eventfd, NULL);
            epoll_ctl(epollfd, EPOLL_CTL_DEL, stdc->cl.connection.sock_fd, NULL);
            node_arr_add(cont->dconn_clients, client_node);
            break;

        case ACCEPTED:
            cl_timerheap_remove(cont->clth, &stdc->cl);

        case ACCEPTING:
            intrusive_list_remove(cont->preauth_list, client_node);
            epoll_ctl(epollfd, EPOLL_CTL_DEL, stdc->cl.connection.sock_fd, NULL);
            nfn->disconnect_fn(&stdc->cl.connection);

        case INIT:
            if (stdc->cl.connection.sock_fd != ERROR)
                close(stdc->cl.connection.sock_fd);
            free(stdc->cl.temp_recv_storage.recvbuf.buf);
            free(stdc);
            break;

        default: break;
    }
}

static void wt_handle_shutdown(stdcl_containers* cont, sqlite3_stmt* stmt, int32_t listenerfd, int32_t epollfd)
{
    sqlite3_finalize(stmt);
    epoll_ctl(epollfd, EPOLL_CTL_DEL, listenerfd, NULL);
    close(listenerfd);
    free(cont->clth->clients);
    dummy_node* list = cont->preauth_list->next;
    node* temp = NULL;

    while (list)
    {
        temp = list;
        list = list->next;
        cleanup_std_client(cont, temp, epollfd);
    }

    free(cont->preauth_list);
    node_arr_sweep(cont->std_cl_table, cont->dconn_clients);
    free(cont->dconn_clients->nodes);
    close(epollfd);
}

static void wt_handle_new_connections(worker_thrd_ctx* wt_ctx, stdcl_containers* cont, int32_t listenerfd, int32_t epollfd)
{
    net_fns* nfn = &g_server_cfg->networking_functions;

    while (true)
    {
        struct sockaddr_in saddr;
        socklen_t slen = sizeof(saddr);
        int32_t clsock = accept(listenerfd, (struct sockaddr*)&saddr, &slen);
        if (clsock == ERROR)
        {
            int32_t err = errno;
            if (err == EAGAIN)
                break;

            char errbuf[256] = {0};
            strerror_r(err, errbuf, 256);
            dzlog_fatal("Listener socket error: %s", errbuf);
            break;
        }

        if (__atomic_load_n(&g_server_cfg->use_ip_whitelist, __ATOMIC_SEQ_CST) &&
            !htable_get(wt_ctx->ip_whitelist_tbl, &saddr.sin_addr.s_addr, sizeof(in_addr_t), false))
        {
            dzlog_notice("Rejected connection attempt from non-whitelisted peer. IP: %u.%u.%u.%u", IP4DOT(saddr.sin_addr.s_addr));
            close(clsock);
            continue;
        }

        node* std_ipbr_node = htable_get(wt_ctx->std_ipblock_tbl, &saddr.sin_addr.s_addr, sizeof(in_addr_t), true);
        if (std_ipbr_node)
        {
            std_ipb_rec* std_ipbr = container_of(std_ipb_rec, nd, std_ipbr_node);
            uint8_t rec_status = chk_std_block(std_ipbr);
            if (rec_status == RS_BLOCKED)
            {
                dzlog_notice("Rejected connection attempt from blocked peer. IP: %u.%u.%u.%u", IP4DOT(saddr.sin_addr.s_addr));
                close(clsock);
                node_put(std_ipbr_node);
                continue;
            }
            else if (rec_status == RS_EXPIRED)
            {
                dzlog_info("Removing expired standard blocking record. IP: %u.%u.%u.%u", IP4DOT(saddr.sin_addr.s_addr));
                htable_remove(wt_ctx->std_ipblock_tbl, std_ipbr_node->key, std_ipbr_node->key_size);
            }

            node_put(std_ipbr_node);
        }

        std_client* stdc = create_std_client(saddr.sin_addr.s_addr, clsock, wt_ctx->thrd_id);
        int32_t ares = nfn->accept_fn(&stdc->cl.connection, wt_ctx->ssl_ctx);

        if (ares == ACCPT_DONE)
        {
            __atomic_store_n(&stdc->cl.cl_state, ACCEPTED, __ATOMIC_SEQ_CST);
            cl_timerheap_add(cont->clth, &stdc->cl, CLTH_AUTH_MAXPERM_TIME);
        }
        else if (ares == ERROR)
        {
            cleanup_std_client(cont, &stdc->nd, epollfd);
            continue;
        }
        else
        {
            __atomic_store_n(&stdc->cl.cl_state, ACCEPTING, __ATOMIC_SEQ_CST);
        }

        intrusive_list_add(cont->preauth_list, &stdc->nd);
        struct epoll_event ev_cl = {.data.ptr = stdc, .events = EPOLLIN};
        epoll_ctl(epollfd, EPOLL_CTL_ADD, stdc->cl.connection.sock_fd, &ev_cl);
    }
}

static void wt_handle_accepting(stdcl_containers* cont, worker_thrd_ctx* wt_ctx, std_client* stdcl, int32_t epollfd)
{
    net_fns* nfn = &g_server_cfg->networking_functions;

    int32_t ares = nfn->accept_fn(&stdcl->cl.connection, wt_ctx->ssl_ctx);
    if (ares == ERROR)
    {
        cleanup_std_client(cont, &stdcl->nd, epollfd);
    }
    else if (ares == ACCPT_DONE)
        __atomic_store_n(&stdcl->cl.cl_state, ACCEPTED, __ATOMIC_SEQ_CST);
}

static void wt_handle_authentication(worker_thrd_ctx* wt_ctx, stdcl_containers* cont, std_client* stdcl,
                                     sqlite3_stmt* fetch_stmt, int32_t epollfd)
{
    net_fns* nfn = &g_server_cfg->networking_functions;
    curr_recv_msg* recv_storage = &stdcl->cl.temp_recv_storage;
    buffer* recvbuf = &recv_storage->recvbuf;
    do
    {
        int64_t data_recved = nfn->recv_fn(&stdcl->cl.connection, recvbuf->buf + recvbuf->buf_data_offset,
                                           sizeof(auth_req_group) - recvbuf->buf_data_offset);
        if (data_recved == ERROR)
        {
            cleanup_std_client(cont, &stdcl->nd, epollfd);
            return;
        }
        if (data_recved == EBLOCK)
            return;

        recvbuf->buf_data_offset += data_recved;
    }while (recvbuf->buf_data_offset < sizeof(auth_req_group));

    auth_req_group* auth_req = (auth_req_group*)recvbuf->buf;
    uint32_t resp_code = AUTH_RESP_OK;

    if (ntohl(auth_req->request_type) != REQ_AUTHENTICATION)
    {
        resp_code = AUTH_RESP_INVAL_REQ;
    }
    else if (htable_get(cont->std_cl_table, auth_req->username, strnlen(auth_req->username, UNAMESIZE), false))
    {
        resp_code = AUTH_RESP_DUPLICATE;
    }
    else
    {
        bool auth_res = validate_auth(wt_ctx->db_rdonly_handle, fetch_stmt, auth_req);
        if (!auth_res)
            resp_code = AUTH_RESP_INVAL_PARAM;
    }

    if (resp_code != AUTH_RESP_OK)
    {
        node* std_ipbr_node = htable_get(wt_ctx->std_ipblock_tbl, &stdcl->cl.peer_name, sizeof(in_addr_t), true);
        if (std_ipbr_node)
        {
            std_ipb_rec* std_ipbr = container_of(std_ipb_rec, nd, std_ipbr_node);
            __atomic_fetch_add(&std_ipbr->failed_auths, 1, __ATOMIC_SEQ_CST);
            node_put(std_ipbr_node);
        }
        else
        {
            std_ipb_rec* std_ipbr = std_ipb_rec_create(stdcl->cl.peer_name, false);
            bool res = htable_add(wt_ctx->std_ipblock_tbl, &std_ipbr->nd);
            if (!res)
                std_ipbr->nd.free_fn(&std_ipbr->nd);
        }

        auth_send_resp(&stdcl->cl, nfn, resp_code);
        cleanup_std_client(cont, &stdcl->nd, epollfd);
        return;
    }

    mpscq_create(&stdcl->pending_userdata_queue, MODE_MPSC);
    mpscq_create(&stdcl->pending_ctrl_queue, MODE_SPSC);
    struct epoll_event ev_queue = {.events = EPOLLIN, .data.ptr = &stdcl->pending_userdata_queue};
    epoll_ctl(epollfd, EPOLL_CTL_ADD, stdcl->pending_userdata_queue.eventfd, &ev_queue);
    cl_timerheap_remove(cont->clth, &stdcl->cl);
    intrusive_list_remove(cont->preauth_list, &stdcl->nd);
    uint32_t unamelen = strnlen(auth_req->username, UNAMESIZE);
    strncpy(stdcl->username, auth_req->username, UNAMESIZE);
    normalize_string(stdcl->username);
    stdcl->nd.key_size = unamelen;
    bool res = htable_add(cont->std_cl_table, &stdcl->nd);

    if (!res)
    {
        mpscq_destroy(&stdcl->pending_ctrl_queue);
        mpscq_destroy(&stdcl->pending_userdata_queue);
        auth_send_resp(&stdcl->cl, nfn, AUTH_RESP_DUPLICATE);
        cleanup_std_client(cont, &stdcl->nd, epollfd);
        return;
    }

    auth_send_resp(&stdcl->cl, nfn, resp_code);
    __atomic_store_n(&stdcl->cl.cl_state, AUTHENTICATED, __ATOMIC_SEQ_CST);
    recvbuf->buf_data_offset = 0;
}

static void wt_serve_response(stdcl_containers* cont, std_client* stdcl, mpsc_msg_node* msg,
                              struct epoll_event* ev_cl, int32_t epollfd)
{
    net_fns* nfn = &g_server_cfg->networking_functions;
    if (stdcl->temp_send_storage)
    {
        mpscq_enqueue(&stdcl->pending_ctrl_queue, msg);
    }
    else
    {
        stdcl->temp_send_storage = msg;
        do
        {
            int64_t data_sent = nfn->send_fn(&stdcl->cl.connection, msg->buf + msg->buf_offset,
                msg->buf_size - msg->buf_offset);

            if (data_sent == ERROR)
            {
                cleanup_std_client(cont, &stdcl->nd, epollfd);
                return;
            }
            else if (data_sent == EBLOCK)
            {
                ev_cl->events |= EPOLLOUT;
                epoll_ctl(epollfd, EPOLL_CTL_MOD, stdcl->cl.connection.sock_fd, ev_cl);
                return;
            }

            stdcl->temp_send_storage->buf_offset += data_sent;
        }while (stdcl->temp_send_storage->buf_offset < stdcl->temp_send_storage->buf_size);

        free(stdcl->temp_send_storage->buf);
        free(stdcl->temp_send_storage);
        stdcl->temp_send_storage = NULL;
    }
}

static uint64_t handle_request(lwmp_pdu* pdu, stdcl_containers* cont, void** reqbuf)
{
    uint32_t req_type = ntohl(pdu->request.req_type);
    uint64_t reqsize;
    switch (req_type)
    {
        case REQ_USER_LIST:
            reqsize = htable_copy_all_keys(cont->std_cl_table, reqbuf, node_copy_username);
            return reqsize;

        default: return 0;
    }
}

static bool wt_handle_inbound_data(std_client* stdcl, stdcl_containers* cont, struct epoll_event* ev_cl, int32_t epollfd)
{
    if (__atomic_load_n(&stdcl->cl.cl_state, __ATOMIC_SEQ_CST) == DISCONNECTED)
        return false;

    curr_recv_msg* tmp_rcv_st = &stdcl->cl.temp_recv_storage;
    buffer* recvbuf = &tmp_rcv_st->recvbuf;
    net_fns* nfn = &g_server_cfg->networking_functions;

    if (tmp_rcv_st->is_desynced)
    {
        do
        {
            uint32_t offset = recvbuf->buf_data_offset;
            int64_t recved_data = nfn->recv_fn(&stdcl->cl.connection, recvbuf->buf + offset, recvbuf->buf_size - offset);
            if (recved_data == ERROR)
            {
                cleanup_std_client(cont, &stdcl->nd, epollfd);
                return true;
            }
            else if (recved_data == EBLOCK)
                break;

            recvbuf->buf_data_offset += recved_data;
            if (recvbuf->buf_data_offset == recvbuf->buf_size)
                break;

        }while (true);

        uint64_t new_offset = lwmp_stream_resync(recvbuf->buf, recvbuf->buf_data_offset);
        recvbuf->buf_data_offset = new_offset;
        if (new_offset)
        {
            dzlog_info("Managed to resync client %s's data stream.", stdcl->username);
            tmp_rcv_st->is_desynced = false;
        }
        else
        {
            dzlog_info("Failed to resync client %s's data stream.", stdcl->username);
            return true;
        }
    }

    if (!tmp_rcv_st->not_msg_init_pdu)
    {


        while (recvbuf->buf_data_offset < LWMP_HDR_SIZE)
        {
            int64_t recved_data = nfn->recv_fn(&stdcl->cl.connection, recvbuf->buf + recvbuf->buf_data_offset, LWMP_HDR_SIZE - recvbuf->buf_data_offset);
            if (recved_data == ERROR)
            {
                cleanup_std_client(cont, &stdcl->nd, epollfd);
                return false;
            }

            if (recved_data == EBLOCK)
                return true;

            recvbuf->buf_data_offset += recved_data;
        }

        if (!tmp_rcv_st->msg_type && !tmp_rcv_st->expected_msg_size)
        {
            lwmp_pdu* pdu = (lwmp_pdu*)recvbuf->buf;
            tmp_rcv_st->msg_type = pdu->msg_type;
            if (tmp_rcv_st->msg_type != MT_REQ)
            {
                memcpy(tmp_rcv_st->dest_uname, pdu->subject_uname, UNAMESIZE);
                tmp_rcv_st->dest_uname[UNAMESIZE - 1] = '\0';
            }

            tmp_rcv_st->expected_msg_size = be64toh(pdu->total_msg_size);
            tmp_rcv_st->total_msg_data_recved = 0;
        }

        while (recvbuf->buf_data_offset < min(lwmp_hdr_size + tmp_rcv_st->expected_msg_size, recvbuf->buf_size))
        {
            int64_t recved_data = nfn->recv_fn(&stdcl->cl.connection, recvbuf->buf + recvbuf->buf_data_offset,
               min(tmp_rcv_st->expected_msg_size - tmp_rcv_st->total_msg_data_recved, recvbuf->buf_size - recvbuf->buf_data_offset));

            if (recved_data == ERROR)
            {
                cleanup_std_client(cont, &stdcl->nd, epollfd);
                return false;
            }
            else if (recved_data == EBLOCK)
                return true;

            recvbuf->buf_data_offset += recved_data;
            tmp_rcv_st->total_msg_data_recved += recved_data;
        }

        if (tmp_rcv_st->total_msg_data_recved == tmp_rcv_st->expected_msg_size || recvbuf->buf_data_offset == recvbuf->buf_size)
        {
            hdr_validation_fns hvfns = {
                .subj_valid_fn = validate_recipient,
                .req_valid_fn = validate_request,
                .allow_file_transfers = __atomic_load_n(&g_server_cfg->allow_file_transfers, __ATOMIC_SEQ_CST),
                .max_filesize_b = __atomic_load_n(&g_server_cfg->max_filesize_b, __ATOMIC_SEQ_CST)
            };
            uint8_t hdr_val_res = lwmp_validate_hdrs((lwmp_pdu*)recvbuf->buf, cont->std_cl_table, tmp_rcv_st->dest_uname, &hvfns);
            if (hdr_val_res != HV_OK)
            {
                uint32_t resp = htonl(resp_codes[hdr_val_res]);
                mpsc_msg_node* msg = msg_node_create(NULL, lwmp_hdr_size, NULL);
                lwmp_prepare_response((lwmp_pdu*)msg->buf, MT_INFO, &resp, sizeof(resp), NULL);
                wt_serve_response(cont, stdcl, msg, ev_cl, epollfd);
                uint64_t offset = offsetof(curr_recv_msg, expected_msg_size);
                memset((void*)tmp_rcv_st + offset, 0, sizeof(curr_recv_msg) - offset);
                recvbuf->buf_data_offset = 0;
                return true;
            }
            else if (tmp_rcv_st->msg_type == MT_REQ)
            {
                void* reqbuf;
                uint64_t reqsize = handle_request((lwmp_pdu*)recvbuf->buf, cont, &reqbuf);
                mpsc_msg_node* msg;
                if (!reqsize)
                {
                    char* resptext = "Failed to process request.";
                    uint32_t resp_code = htonl(RESP_INVAL_REQ);
                    uint8_t resptext_len = strlen(resptext) + 1;
                    msg = msg_node_create(NULL, lwmp_hdr_size + resptext_len, NULL);
                    lwmp_prepare_response((lwmp_pdu*)msg->buf, MT_INFO, &resp_code, sizeof(resp_code), resptext);
                }
                else
                {
                    uint32_t resp_code = htonl(RESP_OK);
                    msg = msg_node_create(NULL, lwmp_hdr_size + reqsize, NULL);
                    lwmp_prepare_response((lwmp_pdu*)msg->buf, MT_REQ, &resp_code, sizeof(resp_code), NULL);
                    memcpy(msg->buf + lwmp_hdr_size, reqbuf, reqsize);
                    free(reqbuf);
                    ((lwmp_pdu*)msg->buf)->total_msg_size = htobe64(reqsize);
                    ((lwmp_pdu*)msg->buf)->crc32 = htonl(crc32(msg->buf, offsetof(lwmp_pdu, crc32)));
                }
                wt_serve_response(cont, stdcl, msg, ev_cl, epollfd);
            }
            else
            {
                node* stdclnode = htable_get_cond(cont->std_cl_table, tmp_rcv_st->dest_uname, strlen(tmp_rcv_st->dest_uname), is_not_disconnected);
                if (!stdclnode)
                {
                    char text[256];
                    snprintf(text, 256, "Unable to reach recipient %s.", tmp_rcv_st->dest_uname);
                    uint32_t resp_code = htonl(RESP_DCONN_SUBJ);
                    mpsc_msg_node* msg = msg_node_create(NULL, lwmp_hdr_size + strlen(text) + 1, NULL);
                    lwmp_prepare_response((lwmp_pdu*)msg->buf, MT_INFO, &resp_code, sizeof(resp_code), text);
                    wt_serve_response(cont, stdcl, msg, ev_cl, epollfd);
                    uint64_t offset = offsetof(curr_recv_msg, expected_msg_size);
                    memset((void*)tmp_rcv_st + offset, 0, sizeof(curr_recv_msg) - offset);
                    recvbuf->buf_data_offset = 0;
                    return true;
                }
                mpsc_msg_node* msg = msg_node_create(recvbuf->buf, recvbuf->buf_data_offset, stdcl->username);
                strncpy(((lwmp_pdu*)msg->buf)->subject_uname, stdcl->username, UNAMESIZE);
                ((lwmp_pdu*)msg->buf)->crc32 = htonl(crc32(msg->buf, offsetof(lwmp_pdu, crc32)));
                std_client* rcpt = container_of(std_client, nd, stdclnode);
                mpscq_enqueue(&rcpt->pending_userdata_queue, msg);
                node_put(stdclnode);
                recvbuf->buf_data_offset = 0;
            }

            if (tmp_rcv_st->total_msg_data_recved == tmp_rcv_st->expected_msg_size)
            {
                uint64_t offset = offsetof(curr_recv_msg, expected_msg_size);
                memset((void*)tmp_rcv_st + offset, 0, sizeof(curr_recv_msg) - offset);
                recvbuf->buf_data_offset = 0;
            }
            else
                tmp_rcv_st->not_msg_init_pdu = true;
        }
        return true;
    }


    while (tmp_rcv_st->total_msg_data_recved < tmp_rcv_st->expected_msg_size && recvbuf->buf_data_offset < recvbuf->buf_size)
    {
        uint32_t offset = recvbuf->buf_data_offset;
        uint64_t dataleft = tmp_rcv_st->expected_msg_size - tmp_rcv_st->total_msg_data_recved;
        int64_t recved_data = nfn->recv_fn(&stdcl->cl.connection, recvbuf->buf + offset, min(dataleft, recvbuf->buf_size - offset));
        if (recved_data == ERROR)
        {
            cleanup_std_client(cont, &stdcl->nd, epollfd);
            return false;
        }
        else if (recved_data == EBLOCK)
            return true;

        recvbuf->buf_data_offset += recved_data;
        tmp_rcv_st->total_msg_data_recved += recved_data;
    }

    node* rcpt_node = htable_get_cond(cont->std_cl_table, tmp_rcv_st->dest_uname, strlen(tmp_rcv_st->dest_uname), is_not_disconnected);
    if (!rcpt_node)
    {
        char text[256];
        snprintf(text, 256, "Unable to reach recipient %s.", tmp_rcv_st->dest_uname);
        uint32_t resp_code = htonl(RESP_DCONN_SUBJ);
        mpsc_msg_node* msg = msg_node_create(NULL, lwmp_hdr_size + strlen(text) + 1, NULL);
        lwmp_prepare_response((lwmp_pdu*)msg->buf, MT_INFO, &resp_code, sizeof(resp_code), text);
        wt_serve_response(cont, stdcl, msg, ev_cl, epollfd);
        uint64_t offset = offsetof(curr_recv_msg, expected_msg_size);
        memset((void*)tmp_rcv_st + offset, 0, sizeof(curr_recv_msg) - offset);
        recvbuf->buf_data_offset = 0;
        tmp_rcv_st->is_desynced = true;
        return true;
    }

    std_client* rcpt = container_of(std_client, nd, rcpt_node);
    mpsc_msg_node* msg = msg_node_create(NULL, LWMP_CHUNK_HDR_SIZE + recvbuf->buf_data_offset, stdcl->username);
    lwmp_prepare_chunk((lwmp_chunk*)msg->buf, recvbuf->buf_data_offset, tmp_rcv_st->dest_uname, recvbuf->buf);
    mpscq_enqueue(&rcpt->pending_userdata_queue, msg);
    node_put(rcpt_node);
    recvbuf->buf_data_offset = 0;

    if (tmp_rcv_st->expected_msg_size == tmp_rcv_st->total_msg_data_recved)
    {
        uint64_t offset = offsetof(curr_recv_msg, expected_msg_size);
        memset((void*)tmp_rcv_st + offset, 0, sizeof(curr_recv_msg) - offset);
        recvbuf->buf_data_offset = 0;
    }

    return true;
}

static int64_t send_one_msg(stdcl_containers* cont, std_client* stdcl, int32_t epollfd)
{
    net_fns* nfn = &g_server_cfg->networking_functions;
    mpsc_msg_node* tss = stdcl->temp_send_storage;
    while (tss->buf_offset < tss->buf_size)
    {
        int64_t data_sent = nfn->send_fn(&stdcl->cl.connection, tss->buf + tss->buf_offset, tss->buf_size - tss->buf_offset);
        if (data_sent == ERROR)
        {
            cleanup_std_client(cont, &stdcl->nd, epollfd);
            return ERROR;
        }
        else if (data_sent == EBLOCK)
            return EBLOCK;

        tss->buf_offset += data_sent;
    }

    int64_t total_data = tss->buf_offset;
    free(tss->buf);
    free(tss);
    stdcl->temp_send_storage = NULL;
    return total_data;
}

static void notify_about_disconnect(std_client* stdcl)
{
    char buf[128];
    snprintf(buf, 128, "Sender %s has disconnected, the latest message may have been partially delivered.", stdcl->temp_send_storage->subject_name);
    mpsc_msg_node* info_msg = msg_node_create(NULL, lwmp_hdr_size + strlen(buf) + 1, NULL);
    uint32_t opt = htonl(RESP_DCONN_SUBJ);
    lwmp_prepare_response((lwmp_pdu*)info_msg->buf, MT_INFO, &opt, sizeof(opt), buf);
    mpscq_enqueue(&stdcl->pending_ctrl_queue, info_msg);
}

static void wt_handle_outbound_data(std_client* stdcl, stdcl_containers* cont, struct epoll_event* ev_cl, int32_t epollfd)
{
    if (__atomic_load_n(&stdcl->cl.cl_state, __ATOMIC_SEQ_CST) == DISCONNECTED)
        return;


    if (stdcl->temp_send_storage)
    {
        if (stdcl->temp_send_storage->subject_name[0] != '\0')
        {
            node* nd = htable_get_cond(cont->std_cl_table, stdcl->temp_send_storage->subject_name, strlen(stdcl->temp_send_storage->subject_name), is_not_disconnected);
            if (!nd)
                notify_about_disconnect(stdcl);
            else
                node_put(nd);
        }

        int64_t res = send_one_msg(cont, stdcl, epollfd);
        if (res < 0)
            return;
    }

    while (true)
    {
        mpsc_msg_node* msg = mpscq_dequeue(&stdcl->pending_ctrl_queue);
        if (!msg)
            break;

        stdcl->temp_send_storage = msg;
        int64_t res = send_one_msg(cont, stdcl, epollfd);
        if (res < 0)
            return;
    }

    ev_cl->events &= ~EPOLLOUT;
    epoll_ctl(epollfd, EPOLL_CTL_MOD, stdcl->cl.connection.sock_fd, ev_cl);
}

static void wt_handle_queued_messages(std_client* stdcl, stdcl_containers* cont, struct epoll_event* ev_cl, int32_t epollfd)
{
    if (__atomic_load_n(&stdcl->cl.cl_state, __ATOMIC_SEQ_CST) == DISCONNECTED)
        return;

    if (stdcl->temp_send_storage)
    {
        if (stdcl->temp_send_storage->subject_name[0] != '\0')
        {
            node* nd = htable_get_cond(cont->std_cl_table, stdcl->temp_send_storage->subject_name, strlen(stdcl->temp_send_storage->subject_name), is_not_disconnected);
            if (!nd)
                notify_about_disconnect(stdcl);
            else
                node_put(nd);
        }

        int64_t res = send_one_msg(cont, stdcl, epollfd);
        if (res < 0)
        {
            if (res == EBLOCK)
            {
                ev_cl->events |= EPOLLOUT;
                epoll_ctl(epollfd, EPOLL_CTL_MOD, stdcl->cl.connection.sock_fd, ev_cl);
            }
            return;
        }
    }

    while (true)
    {
        mpsc_msg_node* msg = mpscq_dequeue(&stdcl->pending_ctrl_queue);
        if (!msg)
            break;

        stdcl->temp_send_storage = msg;
        int64_t res = send_one_msg(cont, stdcl, epollfd);
        if (res < 0)
        {
            if (res == EBLOCK)
            {
                ev_cl->events |= EPOLLOUT;
                epoll_ctl(epollfd, EPOLL_CTL_MOD, stdcl->cl.connection.sock_fd, ev_cl);
            }
            return;
        }
    }

    mpsc_msg_node* msg = mpscq_dequeue(&stdcl->pending_userdata_queue);
    if (!msg)
        return;

    stdcl->temp_send_storage = msg;
    int64_t res = send_one_msg(cont, stdcl, epollfd);
    if (res == EBLOCK)
    {
        ev_cl->events |= EPOLLOUT;
        epoll_ctl(epollfd, EPOLL_CTL_MOD, stdcl->cl.connection.sock_fd, ev_cl);
    }

}

static void wt_handle_clientevent(worker_thrd_ctx* wt_ctx, stdcl_containers* cont, struct epoll_event* ev_cl,
                                  sqlite3_stmt* fetch_stmt, int32_t epollfd)
{
    std_client* stdcl = (std_client*)ev_cl->data.ptr;

    if (ev_cl->events & (EPOLLHUP | EPOLLERR))
    {
        cleanup_std_client(cont, &stdcl->nd, epollfd);
        return;
    }


    uint8_t clstate = __atomic_load_n(&stdcl->cl.cl_state, __ATOMIC_SEQ_CST);
    bool not_disconnected = true;

    if (ev_cl->events & EPOLLIN)
    {
        if (clstate == ACCEPTING)
        {
            wt_handle_accepting(cont, wt_ctx, stdcl, epollfd);
            return;
        }
        else if (clstate == ACCEPTED)
        {
            wt_handle_authentication(wt_ctx, cont, stdcl, fetch_stmt, epollfd);
            return;
        }
        else if (clstate == AUTHENTICATED)
        {
            not_disconnected = wt_handle_inbound_data(stdcl, cont, ev_cl, epollfd);
        }
    }

    if (ev_cl->events & EPOLLOUT && not_disconnected)
    {
        wt_handle_outbound_data(stdcl, cont, ev_cl, epollfd);
    }
}

static int64_t handle_clth_timeout(stdcl_containers* cont, int32_t epollfd)
{
    net_fns* nfn = &g_server_cfg->networking_functions;
    while (true)
    {
        int64_t timediff = cl_timerheap_compute_root_timediff(cont->clth, ACCEPTED);
        client* cl = NULL;

        switch (timediff)
        {
            case CLTH_NOT_APPLICABLE:
                cl_timerheap_pop(cont->clth);
                break;

            case CLTH_TIMEOUT:
                cl = cl_timerheap_pop(cont->clth);
                auth_send_resp(cl, nfn, AUTH_RESP_TIMEOUT);
                cleanup_std_client(cont, &(container_of(std_client, cl, cl))->nd, epollfd);
                break;

            case CLTH_EMPTY:
                return -1;

            default:
                return timediff;

        }
    }
}

void* worker_thrd_routine(void* worker_thread_ctx)
{
    if (!thrd_startup_sync())
        pthread_exit(NULL);

    worker_thrd_ctx* wt_ctx = (worker_thrd_ctx*)worker_thread_ctx;
    char thrdname[THRDNAME_LEN];
    snprintf(thrdname, THRDNAME_LEN, "worker %hhu", wt_ctx->thrd_id);
    zlog_put_mdc("thrd_id", thrdname);

    int32_t listenerfd = server_start_tcp(inet_addr(g_server_cfg->gen_interface),
                                          g_server_cfg->gen_port, WORKER_BACKLOG, true, true);
    if (listenerfd == ERROR)
    {
        dzlog_fatal("Failed to start up listener socket.");
        pthread_exit(NULL);
    }

    epoll_ctx ec_listener = {.fd = listenerfd, .type = EP_LISTENER};
    struct epoll_event ev_listener = {.data.ptr = &ec_listener, .events = EPOLLIN};

    int32_t epollfd = epoll_create1(0);
    if (epollfd == ERROR)
    {
        dzlog_fatal("Failed to create epoll instance.");
        close(listenerfd);
        pthread_exit(NULL);
    }

    epoll_ctx ec_flg_shutdown = {.fd = wt_ctx->flg_shutdown, .type = EP_EVENT};
    struct epoll_event ev_flg_shutdown = {.data.ptr = &ec_flg_shutdown, .events = EPOLLIN};
    int32_t eres = epoll_ctl(epollfd, EPOLL_CTL_ADD, ec_flg_shutdown.fd, &ev_flg_shutdown);
    if (eres == ERROR)
    {
        dzlog_fatal("Failed to add flg_shutdown to epoll instance.");
        close(epollfd);
        close(listenerfd);
        pthread_exit(NULL);
    }

    sqlite3_stmt* auth_stmt;
    int32_t qres = sqlite3_prepare_v2(wt_ctx->db_rdonly_handle, FETCH_QUERY, -1, &auth_stmt, NULL);
    if (qres != SQLITE_OK)
    {
        dzlog_fatal("Failed to prepare SQL statement for authentication. Cause: %s", sqlite3_errmsg(wt_ctx->db_rdonly_handle));
        epoll_ctl(epollfd, EPOLL_CTL_DEL, wt_ctx->flg_shutdown, NULL);
        close(epollfd);
        close(listenerfd);
        pthread_exit(NULL);
    }

    epoll_ctl(epollfd, EPOLL_CTL_ADD, listenerfd, &ev_listener);

    node_arr dconn_clients = {.nodes = (node**)xmalloc(DEF_STDCL_DCONARR_SIZE * sizeof(node*)), .size = DEF_STDCL_DCONARR_SIZE, .elem_cnt = 0};
    node* preauth_client_list = intrusive_list_create();
    cl_timerheap std_clth = {.clients = (client**)xcalloc(DEF_CLTH_SIZE, sizeof(client*)), .num_slots = DEF_CLTH_SIZE, .num_clients = 0};

    stdcl_containers cont = {.preauth_list = preauth_client_list,
                             .clth = &std_clth,
                             .dconn_clients = &dconn_clients,
                             .std_cl_table = wt_ctx->client_tbl};

    struct epoll_event revents[MAX_REVENTS];

    dzlog_info("Worker no. %hhu started.", wt_ctx->thrd_id);
    while (true)
    {
        int64_t waittime = handle_clth_timeout(&cont, epollfd);
        int32_t num_revents = epoll_wait(epollfd, revents, MAX_REVENTS, (int32_t)waittime);
        for (int32_t i = 0; i < num_revents; i++)
        {
            epoll_ctx* ectx = (epoll_ctx*)revents[i].data.ptr;
            switch (ectx->type)
            {
                case EP_LISTENER:
                    wt_handle_new_connections(wt_ctx, &cont, listenerfd, epollfd);
                    break;

                case EP_CLIENT:
                    wt_handle_clientevent(wt_ctx, &cont, &revents[i], auth_stmt, epollfd);
                    break;

                case EP_EVENT:
                    wt_handle_shutdown(&cont, auth_stmt, listenerfd, epollfd);
                    dzlog_warn("Worker %hhu shutting down.", wt_ctx->thrd_id);
                    pthread_exit(NULL);

                case EP_QUEUE:
                    wt_handle_queued_messages(container_of(std_client, pending_userdata_queue, revents[i].data.ptr),
                                              &cont, &revents[i], epollfd);
                    break;

                default: break;
            }
        }
        node_arr_sweep(cont.std_cl_table, cont.dconn_clients);
    }

}
