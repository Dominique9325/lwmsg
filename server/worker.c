//
// Created by dominik on 6/18/26.
//

#include <sys/epoll.h>
#include <unistd.h>
#include "thrdctx.h"
#include "worker.h"
#include <errno.h>
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
            if (errno == EAGAIN)
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

static void wt_handle_clientevent(worker_thrd_ctx* wt_ctx, stdcl_containers* cont,  struct epoll_event* ev_cl, int32_t epollfd)
{
    std_client* stdcl = (std_client*)ev_cl->data.ptr;
    net_fns* nfn = &g_server_cfg->networking_functions;

    if (ev_cl->events & (EPOLLHUP | EPOLLERR))
    {
        if (ev_cl->events & EPOLLHUP && __atomic_load_n(&stdcl->cl.cl_state, __ATOMIC_SEQ_CST) >= AUTHENTICATED)
        {
            uint64_t remaining_data = nfn->avail_data_fn(&stdcl->cl.connection);
            curr_recv_msg* crm = &stdcl->cl.temp_recv_storage;

            uint32_t pdu_size_left = crm->recvbuf.buf_size - crm->recvbuf.buf_data_offset;
            node* dst_cl_nd = htable_get_cond(cont->std_cl_table, crm->dest_uname, UNAMESIZE, is_not_disconnected);
            if (!crm->msg_id || crm->msg_type == MT_REQ || remaining_data > pdu_size_left || !dst_cl_nd ||
                crm->total_msg_data_recved + remaining_data < crm->expected_msg_size)
            {
                if (dst_cl_nd)
                    node_put(dst_cl_nd);
                cleanup_std_client(cont, &stdcl->nd, epollfd);
                return;
            }


            std_client* dest_stdcl = container_of(std_client, nd, dst_cl_nd);
            uint32_t buf_offset = stdcl->cl.temp_recv_storage.recvbuf.buf_data_offset;
            int64_t data_recved = nfn->recv_fn(&stdcl->cl.connection, stdcl->cl.temp_recv_storage.recvbuf.buf + buf_offset, pdu_size_left);
            crm->recvbuf.buf_data_offset += data_recved;
            mpsc_msg_node* msg = msg_node_create(crm->recvbuf.buf, crm->recvbuf.buf_data_offset);
            mpscq_enqueue(&dest_stdcl->pending_userdata_queue, msg);
            node_put(dst_cl_nd);
        }

        cleanup_std_client(cont, &stdcl->nd, epollfd);
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
        dzlog_fatal("Failed to prepare SQL statement for registration. Cause: %s", sqlite3_errmsg(wt_ctx->db_rdonly_handle));
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
                    wt_handle_clientevent();
                    break;

                case EP_EVENT:
                    wt_handle_shutdown(&cont, auth_stmt, listenerfd, epollfd);
                    dzlog_warn("Worker %hhu shutting down.", wt_ctx->thrd_id);
                    pthread_exit(NULL);
                    break;

                case EP_QUEUE:
                    wt_handle_queued_messages();
                    break;

                default: break;
            }
        }
        node_arr_sweep(cont.std_cl_table, cont.dconn_clients);
    }

}
