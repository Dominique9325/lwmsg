//
// Created by dominik on 6/12/26.
//

#include <stdio.h>
#include <sys/socket.h>
#include <sys/epoll.h>
#include <arpa/inet.h>
#include <assert.h>
#include <unistd.h>
#include <openssl/sha.h>
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

#define REG_QUERY "INSERT INTO users (username, password_sha256) VALUES (:username, :password_sha256)"
#define DEL_QUERY "DELETE FROM users WHERE username = :username AND password_sha256 = :password_sha256"
#define MAX_REVENTS 1024

static void cleanup_reg_client(client_list* list, cl_timerheap* clth, client_node* pcln, int32_t epollfd, net_fns* nfn)
{
    epoll_ctl(epollfd, EPOLL_CTL_DEL, pcln->cl.connection.sock_fd, NULL);
    nfn->disconnect_fn(&pcln->cl.connection, pcln->cl.cl_state);
    cl_timerheap_remove(clth, &pcln->cl);
    list_remove(list, pcln);
}

static void handle_flg_reg_changed(epoll_ctx* p_ec_reg_changed, epoll_ctx* p_ec_listener,
                                   struct epoll_event* p_ev_listener, int32_t epollfd)
{
    eventfd_t temp;
    read(p_ec_reg_changed->fd, &temp, 8);
    uint8_t flg_reg = __atomic_load_n(&g_server_cfg->allow_regisrations, memory_order_seq_cst);

    if (flg_reg && p_ec_listener->fd == -1)
    {
        p_ec_listener->fd = server_start_tcp(inet_addr(g_server_cfg->gen_interface), g_server_cfg->reg_port, 128, true);
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

static void handle_shutdown(client_list* list, cl_timerheap* clth, int32_t epollfd, net_fns* nfn, int32_t flg_reg_ch,
                            int32_t flg_shutdown, sqlite3_stmt* reg_stmt, sqlite3_stmt* del_stmt)
{
    sqlite3_finalize(reg_stmt);
    sqlite3_finalize(del_stmt);
    free(clth->clients);

    eventfd_t temp;
    read(flg_shutdown, &temp, 8);

    epoll_ctl(epollfd, EPOLL_CTL_DEL, flg_shutdown, NULL);
    epoll_ctl(epollfd, EPOLL_CTL_DEL, flg_reg_ch, NULL);

    client_node* curr = list->next;
    client_node* prev = NULL;
    while (curr->next)
    {
        epoll_ctl(epollfd, EPOLL_CTL_DEL, curr->cl.connection.sock_fd, NULL);
        nfn->disconnect_fn(&curr->cl.connection, curr->cl.cl_state);
        prev = curr;
        curr = curr->next;
        if (prev->cl.tmpbuf_recv.buf)
        {
            free(prev->cl.tmpbuf_recv.buf);
            prev->cl.tmpbuf_recv.buf = NULL;
        }
        if (prev->cl.tmpbuf_send.buf)
        {
            free(prev->cl.tmpbuf_send.buf);
            prev->cl.tmpbuf_send.buf = NULL;
        }
        free(prev);
    }
    dzlog_warn("Registration thread shutting down.");
}

static void handle_new_connections(client_list* list, cl_timerheap* clth, reg_thrd_ctx* rt_ctx,
                                   epoll_ctx* p_ec_listener, int32_t epollfd, net_fns* nfn)
{
    while (true)
    {
        struct sockaddr_in saddr;
        socklen_t slen = sizeof(saddr);
        int32_t clsock = accept(p_ec_listener->fd, (struct sockaddr*)&saddr, &slen);
        client cl = {.cl_state = ACCEPTING, .connection.sock_fd = clsock};

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

        int32_t cres = nfn->accept_fn(&cl.connection);
        if (cres == ERROR)
        {
            close(clsock);
            continue;
        }

        client_node* cln = (client_node*)xmalloc(sizeof(client_node));
        memcpy(&cln->cl, &cl, sizeof(cl));
        cln->cl.tmpbuf_recv.buf = (char*)xmalloc(sizeof(reg_req_group));
        cln->cl.tmpbuf_recv.buf_size = sizeof(reg_req_group);
        cln->cl.timerheap_index = INVAL_TH_IND;
        fcntl(cln->cl.connection.sock_fd, F_SETFL, O_NONBLOCK);
        list_add(list, cln);
        dzlog_info("%u.%u.%u.%u connected.", IP4DOT(cln->cl.peer_name));
        struct epoll_event cl_epev = {.events = EPOLLIN | EPOLLOUT, .data.ptr = cln};

        if (cres == ACCPT_DONE)
        {
            cln->cl.cl_state = ACCEPTED;
            clock_gettime(CLOCK_MONOTONIC, &cln->cl.auth_deadline);
            cln->cl.auth_deadline.tv_sec += REG_MAXPERM_TIME;
            cl_timerheap_add(clth, &cln->cl);
            cl_epev.events &= ~EPOLLOUT;
        }
        epoll_ctl(epollfd, EPOLL_CTL_ADD, clsock, &cl_epev);
    }
}

static void handle_client_event(client_list* list, cl_timerheap* clth, struct epoll_event* revent,
                        reg_thrd_ctx* rt_ctx, net_fns* nfn, sqlite3_stmt* reg_stmt, sqlite3_stmt* del_stmt,
                        int32_t epollfd)
{
    client_node* pcln = (client_node*)revent->data.ptr;

    if (revent->events & (EPOLLHUP | EPOLLERR))
    {
        if (revent->events & EPOLLIN)
        {
            uint32_t avail_data = nfn->avail_data_fn(&pcln->cl.connection);
            uint32_t offset = pcln->cl.tmpbuf_recv.buf_data_offset;
            if (offset + avail_data == sizeof(reg_req_group))
            {
                nfn->recv_fn(&pcln->cl.connection, pcln->cl.tmpbuf_recv.buf + offset, avail_data);
                reg_req_group* req = (reg_req_group*)pcln->cl.tmpbuf_recv.buf;
                uint32_t req_type = ntohl(req->req_type);
                sqlite3_stmt* req_stmt = NULL;
                if (req_type == REQ_DELETION)
                    req_stmt = del_stmt;
                else if (req_type == REQ_REGISTRATION)
                    req_stmt = reg_stmt;

                bool result = false;
                if (req_stmt)
                    result = process_reg_req(rt_ctx->db_rw_handle, reg_stmt, req);

                if (result)
                    dzlog_info("Processed post-mortem request for %u.%u.%u.%u.", IP4DOT(pcln->cl.peer_name));
            }

        }
        dzlog_info("%u.%u.%u.%u disconnected.", IP4DOT(pcln->cl.peer_name));
        cleanup_reg_client(list, clth, pcln, epollfd, nfn);
        return;
    }

    if (pcln->cl.cl_state == ACCEPTING)
    {
        int32_t ares = nfn->accept_fn(&pcln->cl.connection);
        if (ares == ERROR)
        {
            dzlog_info("%u.%u.%u.%u failed to connect.", IP4DOT(pcln->cl.peer_name));
            cleanup_reg_client(list, clth, pcln, epollfd, nfn);
            return;
        }
        else if (ares == ACCPT_DONE)
        {
            pcln->cl.cl_state = ACCEPTED;
            struct epoll_event ev_cl = {.data.ptr = pcln, .events = EPOLLIN};
            epoll_ctl(epollfd, EPOLL_CTL_MOD, pcln->cl.connection.sock_fd, &ev_cl);
        }
    }
    else
    {
        uint32_t curr_data_len = pcln->cl.tmpbuf_recv.buf_data_offset;
        if (curr_data_len < sizeof(reg_req_group))
        {
            int32_t data_recved = (int32_t)nfn->recv_fn(&pcln->cl.connection, pcln->cl.tmpbuf_recv.buf + curr_data_len,
                                                        sizeof(reg_req_group) - curr_data_len);

            if (data_recved < 1)
            {
                if (data_recved == EDCONN)
                    cleanup_reg_client(list, clth, pcln, epollfd, nfn);

                return;
            }
            pcln->cl.tmpbuf_recv.buf_data_offset += data_recved;
            if (pcln->cl.tmpbuf_recv.buf_data_offset == sizeof(reg_req_group))
            {
                reg_req_group* req = (reg_req_group*)pcln->cl.tmpbuf_recv.buf;
                req->req_type = ntohl(req->req_type);
                sqlite3_stmt* req_stmt = NULL;
                switch (req->req_type)
                {
                    case REQ_REGISTRATION:
                        req_stmt = reg_stmt;
                        break;
                    case REQ_DELETION:
                        req_stmt = del_stmt;
                        break;
                    default: break;
                }

                bool req_result = false;
                if (!req_stmt)
                    dzlog_notice("Invalid request from %u.%u.%u.%u", IP4DOT(pcln->cl.peer_name));
                else
                    req_result = process_reg_req(rt_ctx->db_rw_handle, req_stmt, req);


                uint8_t ripb_reason = req_result ? RSN_REGSUCC : RSN_REGFAIL;
                node* ripbr_node = htable_get(rt_ctx->reg_ipblock_tbl, &pcln->cl.peer_name, sizeof(&pcln->cl.peer_name), true);
                if (!ripbr_node)
                {
                    reg_ipb_rec* ripbr = reg_ipb_rec_create(pcln->cl.peer_name, ripb_reason);
                    htable_add(rt_ctx->reg_ipblock_tbl, &ripbr->nd);
                }
                else
                {
                    reg_ipb_rec* ripbr = node_container_of(reg_ipb_rec, nd, ripbr_node);
                    if (ripb_reason == RSN_REGSUCC)
                        ripbr->succ_regs++;
                    else
                        ripbr->failed_regs++;
                    node_put(ripbr_node);
                }



                reg_resp resp = {.resp_code = req_result ? REG_RESP_OK : REG_RESP_ERR};
                resp.resp_code = htonl(resp.resp_code);
                nfn->send_fn(&pcln->cl.connection, &resp, sizeof(resp));

            }
        }
    }
}

void* reg_thrd_routine(void* reg_thread_ctx)
{
    net_fns* nfn = &g_server_cfg->networking_functions;
    reg_thrd_ctx* rt_ctx = (reg_thrd_ctx*)reg_thread_ctx;
    sqlite3_stmt* reg_stmt = NULL;
    sqlite3_stmt* del_stmt = NULL;
    epoll_ctx ec_reg_changed = {.type = EP_EVENT, .fd = rt_ctx->flg_reg_changed};
    epoll_ctx ec_shutdown = {.type = EP_EVENT, .fd = rt_ctx->flg_shutdown};
    epoll_ctx ec_listener = {.type = EP_LISTENER, .fd = -1};


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
        pthread_exit(NULL);
    }

    int32_t epollfd = epoll_create1(0);
    if (epollfd == ERROR)
        pthread_exit(NULL);

    struct epoll_event ev_listener = {.events = EPOLLIN, .data.ptr = &ec_listener};
    struct epoll_event ev_reg_changed = {.events = EPOLLIN, .data.ptr = &ec_reg_changed};
    struct epoll_event ev_shutdown = {.events = EPOLLIN, .data.ptr = &ec_shutdown};

    epoll_ctl(epollfd, EPOLL_CTL_ADD, rt_ctx->flg_reg_changed, &ev_reg_changed);
    epoll_ctl(epollfd, EPOLL_CTL_ADD, rt_ctx->flg_shutdown, &ev_shutdown);

    if (__atomic_load_n(&g_server_cfg->allow_regisrations, memory_order_seq_cst))
    {
        ec_listener.fd = server_start_tcp(inet_addr(g_server_cfg->gen_interface), g_server_cfg->reg_port, 128, true);
        epoll_ctl(epollfd, EPOLL_CTL_ADD, ec_listener.fd, &ev_listener);
    }

    client_list* list = list_create();

    cl_timerheap clth = {
        .num_clients = 0, .num_slots = DEF_CL_ARR_SIZE,
        .clients = (client**)xcalloc(DEF_CL_ARR_SIZE, sizeof(client*))
    };

    struct epoll_event revents[1024];



    while (true)
    {
        client* cl = cl_timerheap_peek(&clth);
        int32_t num_events = epoll_wait(epollfd, revents, MAX_REVENTS, -1);
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
                            reg_stmt, del_stmt);
                        pthread_exit(NULL);
                    }
                    else
                    {
                        handle_flg_reg_changed(&ec_reg_changed, &ec_listener, &ev_listener, epollfd);
                    }
                    break;
                }



                case EP_LISTENER:
                {
                    handle_new_connections(list, &clth, rt_ctx, &ec_listener, epollfd, nfn);
                    break;
                }



                case EP_CLIENT:
                {
                    handle_client_event(list, &clth, &revents[i], rt_ctx, nfn, reg_stmt, del_stmt, epollfd);
                }

                default: break;
            }
        }
    }
}




bool process_reg_req(sqlite3* dbc, sqlite3_stmt* stmt, reg_req_group* req)
{
    assert(dbc && stmt && req);

    sqlite3_reset(stmt);
    int32_t i = sqlite3_bind_parameter_index(stmt, ":username");
    int32_t j = sqlite3_bind_parameter_index(stmt, ":password_sha256");
    if (!i || !j)
    {
        dzlog_error("Improperly prepared SQL statement. Cause: %s", sqlite3_errmsg(dbc));
        return false;
    }

    req->username[UNAMESIZE - 1] = '\0';
    req->password[PWDSIZE - 1] = '\0';
    unsigned char password_hash[SHA256_DIGEST_LENGTH];
    SHA256((const unsigned char*)req->password, strlen(req->password), password_hash);
    sqlite3_bind_text(stmt, i, req->username, -1, SQLITE_STATIC);
    sqlite3_bind_blob(stmt, j, password_hash, SHA256_DIGEST_LENGTH, SQLITE_STATIC);
    int32_t res = sqlite3_step(stmt);

    if (res != SQLITE_DONE)
    {
        dzlog_notice("Failed to execute query. Cause: %s", sqlite3_errmsg(dbc));
        return false;
    }
    else if (!sqlite3_changes(dbc))
    {
        dzlog_notice("Failed to delete account. Invalid username or password.");
        return false;
    }
    dzlog_info("Successfully %s user %s", req->req_type == REQ_DELETION ? "deleted" : "created", req->username);
    return true;
}