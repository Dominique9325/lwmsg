//
// Created by dominik on 6/12/26.
//

#include <stdio.h>
#include <sys/socket.h>
#include <sys/epoll.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include "zlog.h"
#include "registration.h"
#include "netwrap.h"
#include "servcfg.h"
#include "thrdctx.h"
#include "clhandle.h"
#include "cltimerheap.h"
#include "misc.h"
#include "xalloc.h"
#include "ipblock.h"
#include "dbops.h"


#define MAX_REVENTS 1024

static void cleanup_reg_client(reg_client_list* list, cl_timerheap* clth, reg_client_node* pcln, int32_t epollfd, net_fns* nfn)
{
    epoll_ctl(epollfd, EPOLL_CTL_DEL, pcln->cl.connection.sock_fd, NULL);
    nfn->disconnect_fn(&pcln->cl.connection);

    if (pcln->cl.tmpbuf_recv.buf)
        free(pcln->cl.tmpbuf_recv.buf);

    cl_timerheap_remove(clth, &pcln->cl);
    list_remove(list, pcln);
    free(pcln);
}

static void handle_flg_reg_changed(epoll_ctx* p_ec_reg_changed, epoll_ctx* p_ec_listener,
                                   struct epoll_event* p_ev_listener, int32_t epollfd)
{
    eventfd_t temp;
    read(p_ec_reg_changed->fd, &temp, 8);
    uint8_t flg_reg = __atomic_load_n(&g_server_cfg->allow_registrations, memory_order_seq_cst);

    if (flg_reg && p_ec_listener->fd == -1)
    {
        p_ec_listener->fd = server_start_tcp(inet_addr(g_server_cfg->gen_interface), g_server_cfg->reg_port, 128, true, false);
        p_ev_listener->data.ptr = p_ec_listener;
        epoll_ctl(epollfd, EPOLL_CTL_ADD, p_ec_listener->fd, p_ev_listener);
    }
    else if (!flg_reg && p_ec_listener->fd != -1)
    {
        epoll_ctl(epollfd, EPOLL_CTL_DEL, p_ec_listener->fd, NULL);
        close(p_ec_listener->fd);
        p_ec_listener->fd = -1;
    }
}

static void handle_shutdown(reg_client_list* list, cl_timerheap* clth, int32_t epollfd, net_fns* nfn, int32_t flg_reg_ch,
                            int32_t flg_shutdown, sqlite3_stmt* reg_stmt, sqlite3_stmt* del_stmt, int32_t listener_sock_fd)
{
    sqlite3_finalize(reg_stmt);
    sqlite3_finalize(del_stmt);
    free(clth->clients);

    epoll_ctl(epollfd, EPOLL_CTL_DEL, flg_shutdown, NULL);
    epoll_ctl(epollfd, EPOLL_CTL_DEL, flg_reg_ch, NULL);
    epoll_ctl(epollfd, EPOLL_CTL_DEL, listener_sock_fd, NULL);
    if (listener_sock_fd != ERROR)
        close(listener_sock_fd);

    reg_client_node* curr = list->next;
    reg_client_node* prev = NULL;
    while (curr)
    {
        epoll_ctl(epollfd, EPOLL_CTL_DEL, curr->cl.connection.sock_fd, NULL);
        nfn->disconnect_fn(&curr->cl.connection);
        if (curr->cl.tmpbuf_recv.buf)
        {
            free(curr->cl.tmpbuf_recv.buf);
            curr->cl.tmpbuf_recv.buf = NULL;
        }
        prev = curr;
        curr = curr->next;
        free(prev);
    }
    free(list);
    close(epollfd);
    dzlog_warn("Registration thread shutting down.");
}

static void track_new_client(reg_client_list* list, cl_timerheap* clth, reg_client* cl, uint8_t acceptres, int32_t epollfd)
{
    reg_client_node* cln = (reg_client_node*)xmalloc(sizeof(reg_client_node));
    memcpy(&cln->cl, cl, sizeof(*cl));
    cln->cl.tmpbuf_recv.buf = (char*)xmalloc(sizeof(auth_req_group));
    cln->cl.tmpbuf_recv.buf_size = sizeof(auth_req_group);
    cln->cl.timerheap_index = INVAL_TH_IND;
    fcntl(cln->cl.connection.sock_fd, F_SETFL, O_NONBLOCK);
    list_add(list, cln);
    dzlog_info("%u.%u.%u.%u connected.", IP4DOT(cln->cl.peer_name));
    struct epoll_event cl_epev = {.events = EPOLLIN | EPOLLOUT, .data.ptr = cln};

    if (acceptres == ACCPT_DONE)
    {
        __atomic_store_n(&cln->cl.cl_state, ACCEPTED, memory_order_seq_cst);
        clock_gettime(CLOCK_MONOTONIC, &cln->cl.auth_deadline);
        cln->cl.auth_deadline.tv_sec += CLTH_REG_MAXPERM_TIME;
        cl_timerheap_add(clth, &cln->cl);
        cl_epev.events &= ~EPOLLOUT;
    }
    epoll_ctl(epollfd, EPOLL_CTL_ADD, cln->cl.connection.sock_fd, &cl_epev);
}

static void handle_new_connections(reg_client_list* list, cl_timerheap* clth, reg_thrd_ctx* rt_ctx,
                                   epoll_ctx* p_ec_listener, int32_t epollfd, net_fns* nfn)
{
    while (true)
    {
        struct sockaddr_in saddr;
        socklen_t slen = sizeof(saddr);
        int32_t clsock = accept(p_ec_listener->fd, (struct sockaddr*)&saddr, &slen);
        reg_client cl = {
            .cl_state = ACCEPTING,
            .connection.sock_fd = clsock,
            .ep_type = EP_CLIENT,
            .peer_name = saddr.sin_addr.s_addr,
            .connection.ssl = NULL
        };

        if (clsock == ERROR)
        {
            int32_t errn = errno;
            if (errn != EAGAIN)
            {
                char errbuf[256] = {0};
                strerror_r(errn, errbuf, 256);
                dzlog_error("Registration listener socket error. Cause: %s", errbuf);
                epoll_ctl(epollfd, EPOLL_CTL_DEL, p_ec_listener->fd, NULL);
                close(p_ec_listener->fd);
                p_ec_listener->fd = -1;
            }
            break;
        }

        if (__atomic_load_n(&g_server_cfg->use_ip_whitelist, memory_order_seq_cst) && !htable_get(rt_ctx->ip_whitelist_tbl, &saddr.sin_addr.s_addr, sizeof(in_addr_t), false))
        {
            dzlog_notice("Disconnected peer not present on the whitelist. IP: %u.%u.%u.%u", IP4DOT(saddr.sin_addr.s_addr));
            close(clsock);
            continue;
        }

        node* ripbr_node = htable_get(rt_ctx->reg_ipblock_tbl, &saddr.sin_addr.s_addr, sizeof(saddr.sin_addr.s_addr), true);
        if (ripbr_node)
        {
            reg_ipb_rec* ripbr = node_container_of(reg_ipb_rec, nd, ripbr_node);
            uint8_t blk_status = chk_reg_block(ripbr);

            if (blk_status == BLOCKED)
            {
                node_put(ripbr_node);
                dzlog_notice("Blocked peer attempted to connect. IP: %u.%u.%u.%u", IP4DOT(saddr.sin_addr.s_addr));
                close(clsock);
                continue;
            }
            else if (blk_status == REC_EXPIRED)
            {
                dzlog_info("Removing expired registration blocking record. IP: %u.%u.%u.%u", IP4DOT(saddr.sin_addr.s_addr));
                htable_remove(rt_ctx->reg_ipblock_tbl, ripbr_node->key, ripbr_node->key_size);
            }

            node_put(ripbr_node);
        }

        int32_t cres = nfn->accept_fn(&cl.connection, rt_ctx->ssl_ctx);
        if (cres == ERROR)
        {
            close(clsock);
            continue;
        }

        track_new_client(list, clth, &cl, cres, epollfd);
    }
}

static void manage_reg_ipbr(reg_thrd_ctx* rt_ctx, reg_client_node* pcln, uint8_t ripb_reason)
{
    node* ripbr_node = htable_get(rt_ctx->reg_ipblock_tbl, &pcln->cl.peer_name, sizeof(pcln->cl.peer_name), true);
    if (!ripbr_node)
    {
        reg_ipb_rec* ripbr = reg_ipb_rec_create(pcln->cl.peer_name, ripb_reason);
        htable_add(rt_ctx->reg_ipblock_tbl, &ripbr->nd);
        dzlog_debug("RIPB_REASON = %hhu", ripb_reason);
    }
    else
    {
        reg_ipb_rec* ripbr = node_container_of(reg_ipb_rec, nd, ripbr_node);
        if (ripb_reason == RSN_REGSUCC)
        {
            ripbr->succ_regs++;
            dzlog_info("%u.%u.%u.%u successfully processed request.", IP4DOT(pcln->cl.peer_name));
        }
        else
        {
            ripbr->failed_regs++;
            dzlog_info("%u.%u.%u.%u invalid request parameters.", IP4DOT(pcln->cl.peer_name));
        }
        node_put(ripbr_node);
    }
}

static void reg_handle_disconnect(reg_client_list* list, cl_timerheap* clth, reg_thrd_ctx* rt_ctx,
                                  struct epoll_event* revent, net_fns* nfn, reg_client_node* pcln,
                                  sqlite3_stmt* reg_stmt, sqlite3_stmt* del_stmt, int32_t epollfd)
{
    if (revent->events & EPOLLIN)
    {
        uint32_t avail_data = nfn->avail_data_fn(&pcln->cl.connection);
        uint32_t offset = pcln->cl.tmpbuf_recv.buf_data_offset;
        if (offset + avail_data == sizeof(auth_req_group))
        {
            nfn->recv_fn(&pcln->cl.connection, pcln->cl.tmpbuf_recv.buf + offset, avail_data);
            auth_req_group* req = (auth_req_group*)pcln->cl.tmpbuf_recv.buf;
            uint32_t request_type = ntohl(req->request_type);
            sqlite3_stmt* request_stmt = NULL;
            if (request_type == REQ_DELETION)
                request_stmt = del_stmt;
            else if (request_type == REQ_REGISTRATION)
                request_stmt = reg_stmt;

            bool result = false;
            if (request_stmt)
                result = process_reg_req(rt_ctx->db_rw_handle, request_stmt, req);

            if (result)
                dzlog_info("Processed post-mortem request for %u.%u.%u.%u.", IP4DOT(pcln->cl.peer_name));
        }

    }
    dzlog_info("%u.%u.%u.%u disconnected.", IP4DOT(pcln->cl.peer_name));
    cleanup_reg_client(list, clth, pcln, epollfd, nfn);
}

static void handle_client_event(reg_client_list* list, cl_timerheap* clth, struct epoll_event* revent,
                        reg_thrd_ctx* rt_ctx, net_fns* nfn, sqlite3_stmt* reg_stmt, sqlite3_stmt* del_stmt,
                        int32_t epollfd)
{
    reg_client_node* pcln = (reg_client_node*)revent->data.ptr;

    if (revent->events & (EPOLLHUP | EPOLLERR))
    {
        reg_handle_disconnect(list, clth, rt_ctx, revent, nfn, pcln, reg_stmt, del_stmt, epollfd);
        return;
    }

    if (__atomic_load_n(&pcln->cl.cl_state, memory_order_seq_cst) == ACCEPTING)
    {
        int32_t ares = nfn->accept_fn(&pcln->cl.connection, rt_ctx->ssl_ctx);
        if (ares == ERROR)
        {
            dzlog_info("%u.%u.%u.%u failed to connect.", IP4DOT(pcln->cl.peer_name));
            cleanup_reg_client(list, clth, pcln, epollfd, nfn);
            return;
        }
        else if (ares == ACCPT_DONE)
        {
            __atomic_store_n(&pcln->cl.cl_state, ACCEPTED, memory_order_seq_cst);
            struct epoll_event ev_cl = {.data.ptr = pcln, .events = EPOLLIN};
            epoll_ctl(epollfd, EPOLL_CTL_MOD, pcln->cl.connection.sock_fd, &ev_cl);
        }
    }
    else
    {
        uint32_t curr_data_len = pcln->cl.tmpbuf_recv.buf_data_offset;
        if (curr_data_len < sizeof(auth_req_group))
        {
            int32_t data_recved = (int32_t)nfn->recv_fn(&pcln->cl.connection, pcln->cl.tmpbuf_recv.buf + curr_data_len,
                                                        sizeof(auth_req_group) - curr_data_len);

            if (data_recved < 1)
            {
                if (data_recved == EBLOCK)
                    return;

                cleanup_reg_client(list, clth, pcln, epollfd, nfn);
                return;
            }
            pcln->cl.tmpbuf_recv.buf_data_offset += data_recved;
            if (pcln->cl.tmpbuf_recv.buf_data_offset == sizeof(auth_req_group))
            {
                auth_req_group* req = (auth_req_group*)pcln->cl.tmpbuf_recv.buf;
                req->request_type = ntohl(req->request_type);
                sqlite3_stmt* request_stmt = NULL;
                switch (req->request_type)
                {
                    case REQ_REGISTRATION:
                        request_stmt = reg_stmt;
                        break;
                    case REQ_DELETION:
                        request_stmt = del_stmt;
                        break;
                    default: break;
                }

                bool request_result = false;
                if (!request_stmt)
                    dzlog_notice("Invalid request from %u.%u.%u.%u", IP4DOT(pcln->cl.peer_name));
                else
                    request_result = process_reg_req(rt_ctx->db_rw_handle, request_stmt, req);


                uint8_t ripb_reason = request_result ? RSN_REGSUCC : RSN_REGFAIL;
                if (request_stmt == reg_stmt || !request_result)
                    manage_reg_ipbr(rt_ctx, pcln, ripb_reason);

                uint32_t resp_code = request_result ? AUTH_RESP_OK : (request_stmt ? AUTH_RESP_INVAL_PARAM : AUTH_RESP_INVAL_REQ);
                req_send_resp(&pcln->cl, nfn, resp_code);
                cleanup_reg_client(list, clth, pcln, epollfd, nfn);
            }
        }
    }
}

static int64_t handle_clth_timeout(reg_client_list* list, cl_timerheap* clth, int32_t epollfd, net_fns* nfn)
{
    while (true)
    {
        int64_t timediff = cl_timerheap_compute_root_timediff(clth, ACCEPTED);
        reg_client* cl = NULL;

        switch (timediff)
        {
            case CLTH_NOT_APPLICABLE:
                cl_timerheap_pop(clth);
                break;

            case CLTH_TIMEOUT:
                cl = cl_timerheap_pop(clth);
                req_send_resp(cl, nfn, AUTH_RESP_TIMEOUT);
                cleanup_reg_client(list, clth, (reg_client_node*)cl, epollfd, nfn);
                break;

            case CLTH_EMPTY:
                return -1;

            default:
                return timediff;

        }
    }
}

void* reg_thrd_routine(void* reg_thread_ctx)
{
    if (!thrd_startup_sync())
        pthread_exit(NULL);

    zlog_put_mdc("thrd_id", "reg");
    net_fns* nfn = &g_server_cfg->networking_functions;
    reg_thrd_ctx* rt_ctx = (reg_thrd_ctx*)reg_thread_ctx;
    sqlite3_stmt* reg_stmt = NULL;
    sqlite3_stmt* del_stmt = NULL;
    epoll_ctx ec_reg_changed = {.type = EP_EVENT, .fd = rt_ctx->flg_reg_changed};
    epoll_ctx ec_shutdown = {.type = EP_EVENT, .fd = rt_ctx->flg_shutdown};
    epoll_ctx ec_listener = {.type = EP_LISTENER, .fd = -1};

    int32_t epollfd = epoll_create1(0);
    if (epollfd == ERROR)
    {
        dzlog_fatal("Failed to create an epoll instance.");
        pthread_exit(NULL);
    }



    int32_t res_reg = sqlite3_prepare_v2(rt_ctx->db_rw_handle, REG_QUERY, -1, &reg_stmt, NULL);
    if (res_reg)
    {
        dzlog_fatal("Failed to prepare SQL statement for registration. Cause: %s", sqlite3_errmsg(rt_ctx->db_rw_handle));
        pthread_exit(NULL);
    }

    int32_t res_del = sqlite3_prepare_v2(rt_ctx->db_rw_handle, DEL_QUERY, -1, &del_stmt, NULL);
    if (res_del)
    {
        dzlog_fatal("Failed to prepare SQL statement for deletion. Cause: %s", sqlite3_errmsg(rt_ctx->db_rw_handle));
        sqlite3_finalize(reg_stmt);
        pthread_exit(NULL);
    }

    struct epoll_event ev_listener = {.events = EPOLLIN, .data.ptr = &ec_listener};
    struct epoll_event ev_reg_changed = {.events = EPOLLIN, .data.ptr = &ec_reg_changed};
    struct epoll_event ev_shutdown = {.events = EPOLLIN, .data.ptr = &ec_shutdown};

    epoll_ctl(epollfd, EPOLL_CTL_ADD, rt_ctx->flg_reg_changed, &ev_reg_changed);
    epoll_ctl(epollfd, EPOLL_CTL_ADD, rt_ctx->flg_shutdown, &ev_shutdown);

    if (__atomic_load_n(&g_server_cfg->allow_registrations, memory_order_seq_cst))
    {
        ec_listener.fd = server_start_tcp(inet_addr(g_server_cfg->gen_interface), g_server_cfg->reg_port, 128, true, false);
        epoll_ctl(epollfd, EPOLL_CTL_ADD, ec_listener.fd, &ev_listener);
    }

    reg_client_list* list = list_create();

    cl_timerheap clth = {
        .num_clients = 0, .num_slots = DEF_CLTH_SIZE,
        .clients = (reg_client**)xcalloc(DEF_CLTH_SIZE, sizeof(reg_client*))
    };

    struct epoll_event revents[1024];


    uint32_t R = 0;
    while (true)
    {
        dzlog_debug("R = %u", R++);
        int64_t clth_root_timediff = handle_clth_timeout(list, &clth, epollfd, nfn);
        dzlog_debug("Waittime = %ld", clth_root_timediff);
        int32_t num_events = epoll_wait(epollfd, revents, MAX_REVENTS, (int32_t)clth_root_timediff);

        for (uint32_t i = 0; i < num_events; i++)
        {
            epoll_ctx* ectx = (epoll_ctx*)revents[i].data.ptr;
            switch (ectx->type)
            {
                case EP_EVENT:
                {
                    if (ectx->fd == ec_shutdown.fd && revents[i].events & EPOLLIN)
                    {
                        handle_shutdown(list, &clth, epollfd, nfn, rt_ctx->flg_reg_changed, rt_ctx->flg_shutdown,
                            reg_stmt, del_stmt, ec_listener.fd);
                        dzlog_debug("ripbr_count = %lu", htable_get_elem_cnt(rt_ctx->reg_ipblock_tbl));
                        pthread_exit(NULL);
                    }
                    else
                    {
                        handle_flg_reg_changed(&ec_reg_changed, &ec_listener, &ev_listener, epollfd);
                    }
                    break;
                }


                case EP_LISTENER:
                    handle_new_connections(list, &clth, rt_ctx, &ec_listener, epollfd, nfn);
                    break;


                case EP_CLIENT:
                    handle_client_event(list, &clth, &revents[i], rt_ctx, nfn, reg_stmt, del_stmt, epollfd);
                    break;


                default: break;
            }
        }
    }
}
