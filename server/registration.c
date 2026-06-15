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
#include "zlog.h"
#include "registration.h"
#include "netwrap.h"
#include "servcfg.h"
#include "thrdctx.h"
#include "clhandle.h"
#include "cltimerheap.h"
#include "xalloc.h"
#include "ipblock.h"

#define REG_QUERY "INSERT INTO users (username, password_sha256) VALUES (:username, :password_sha256)"
#define MAX_REVENTS 1024

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

static void handle_new_connections(client_list* list, cl_timerheap* clth, reg_thrd_ctx* rt_ctx,
                                   epoll_ctx* p_ec_listener, int32_t epollfd, net_fns* nfn)
{
    while (1)
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

        node* ripbr_node = htable_get(rt_ctx->reg_ipblock_tbl, &saddr.sin_addr, sizeof(saddr.sin_addr), true);
        if (ripbr_node)
        {
            reg_ipb_rec* ripbr = node_container_of(reg_ipb_rec, nd, ripbr_node);
            uint8_t blk_status = chk_reg_block(ripbr);

            if (blk_status == BLOCKED)
            {
                node_put(ripbr_node);
                close(clsock);
                continue;
            }
            else if (blk_status == REC_EXPIRED)
            {
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
        list_add(list, cln);
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



void* reg_thrd_routine(void* reg_thread_ctx)
{
    net_fns* nfn = &g_server_cfg->networking_functions;
    reg_thrd_ctx* rt_ctx = (reg_thrd_ctx*)reg_thread_ctx;
    sqlite3_stmt* stmt;
    epoll_ctx ec_reg_changed = {.type = EP_EVENT, .fd = rt_ctx->flg_reg_changed};
    epoll_ctx ec_listener = {.type = EP_LISTENER, .fd = -1};


    int32_t res = sqlite3_prepare_v2(rt_ctx->db_rw_handle, REG_QUERY, -1, &stmt, NULL);
    if (res)
    {
        dzlog_fatal("Failed to prepare SQL statement for registration. Cause: %s", sqlite3_errmsg(rt_ctx->db_rw_handle));
        return NULL;
    }

    int32_t epollfd = epoll_create1(0);
    if (epollfd == ERROR)
        return NULL;

    struct epoll_event ev_listener = {.events = EPOLLIN, .data.ptr = &ec_listener};
    struct epoll_event ev_reg_changed = {.events = EPOLLIN, .data.ptr = &ec_reg_changed};

    epoll_ctl(epollfd, EPOLL_CTL_ADD, rt_ctx->flg_reg_changed, &ev_reg_changed);

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



    while (1)
    {
        int32_t num_events = epoll_wait(epollfd, revents, MAX_REVENTS, -1);
        for (uint32_t i = 0; i < num_events; i++)
        {
            epoll_ctx* ectx = (epoll_ctx*)revents[i].data.ptr;
            switch (ectx->type)
            {
                case EP_EVENT:
                {
                    handle_flg_reg_changed(&ec_reg_changed, &ec_listener, &ev_listener, epollfd);
                    break;
                }



                case EP_LISTENER:
                {
                     handle_new_connections(list, &clth, rt_ctx, &ec_listener, epollfd, nfn);
                    break;
                }



                case EP_CLIENT:
                {
                    client_node* pcln = (client_node*)revents[i].data.ptr;

                    if (revents[i].events & (EPOLLHUP | EPOLLERR))
                    {
                        epoll_ctl(epollfd, EPOLL_CTL_DEL, pcln->cl.connection.sock_fd, NULL);
                        nfn->disconnect_fn(&pcln->cl.connection, pcln->cl.cl_state);
                        cl_timerheap_remove(&clth, &pcln->cl);
                    }
                }

                default: break;
            }
        }
    }
    return NULL;
}

bool register_user(sqlite3* dbc, sqlite3_stmt* stmt, reg_req* req)
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

    unsigned char password_hash[SHA256_DIGEST_LENGTH];
    SHA256((const unsigned char*)req->password, strlen(req->password), password_hash);
    sqlite3_bind_text(stmt, i, req->desired_username, -1, SQLITE_STATIC);
    sqlite3_bind_blob(stmt, j, password_hash, SHA256_DIGEST_LENGTH, SQLITE_STATIC);
    int32_t res = sqlite3_step(stmt);

    if (res != SQLITE_DONE)
    {
        dzlog_error("Failed to execute query. Cause: %s", sqlite3_errmsg(dbc));
        return false;
    }

    return true;
}