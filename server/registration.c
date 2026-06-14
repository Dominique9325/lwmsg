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

void* reg_thrd_routine(void* reg_thread_ctx)
{
    reg_thrd_ctx* rt_ctx = (reg_thrd_ctx*)reg_thread_ctx;
    sqlite3_stmt* stmt;
    int32_t reg_sock_fd = -1;
    struct epoll_event reg_sock_ev = {.events = EPOLLIN | EPOLLERR, .data.fd = reg_sock_fd};
    int32_t res = sqlite3_prepare_v2(rt_ctx->db_rw_handle, REG_QUERY, -1, &stmt, NULL);
    if (res)
    {
        dzlog_fatal("Failed to prepare SQL statement for registration. Cause: %s", sqlite3_errmsg(rt_ctx->db_rw_handle));
        return NULL;
    }

    int32_t epollfd = epoll_create1(0);
    if (epollfd == ERROR)
        return NULL;

    struct epoll_event ev_reg_allow = {.events = EPOLLIN, .data.fd = rt_ctx->flg_reg_changed};

    epoll_ctl(epollfd, EPOLL_CTL_ADD, rt_ctx->flg_reg_changed, &ev_reg_allow);

    if (__atomic_load_n(&g_server_cfg->allow_regisrations, memory_order_seq_cst))
    {
        reg_sock_fd = server_start_tcp(inet_addr(g_server_cfg->gen_interface), g_server_cfg->reg_port, 128, true);
        epoll_ctl(epollfd, EPOLL_CTL_ADD, reg_sock_fd, &reg_sock_ev);
    }

    client_arr arr = {.num_clients = 0, .num_slots = DEF_CL_ARR_SIZE,
                      .clients = (client*)xmalloc(DEF_CL_ARR_SIZE * sizeof(client))
                     };

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
            if (revents[i].data.fd == rt_ctx->flg_reg_changed)
            {
                eventfd_t temp;
                read(rt_ctx->flg_reg_changed, &temp, 8);
                uint64_t flg_reg = __atomic_load_n(&g_server_cfg->allow_regisrations, memory_order_seq_cst);
                if (flg_reg && reg_sock_fd == -1)
                {
                    reg_sock_fd = server_start_tcp(inet_addr(g_server_cfg->gen_interface), g_server_cfg->reg_port, 128, true);
                    reg_sock_ev.data.fd = reg_sock_fd;
                    epoll_ctl(epollfd, EPOLL_CTL_ADD, reg_sock_fd, &reg_sock_ev);
                }
                else if (!flg_reg && reg_sock_fd != -1)
                {
                    epoll_ctl(epollfd, EPOLL_CTL_DEL, reg_sock_fd, NULL);
                    close(reg_sock_fd);
                    reg_sock_fd = -1;
                }
            }
            else if (revents[i].data.fd == reg_sock_fd)
            {
                while (1)
                {
                    client cl = {.cl_state = ACCEPTING};

                    int32_t sock = accept(reg_sock_fd, &cl.peer_name, &cl.peer_name_size);
                    if (sock == EAGAIN)
                        break;

                    node* ripbr_node = htable_get(rt_ctx->reg_ipblock_tbl, &cl.peer_name, cl.peer_name_size, true);
                    if (ripbr_node)
                    {
                        reg_ipb_rec* ripbr = node_container_of(reg_ipb_rec, nd, ripbr_node);
                        if (ripbr->is_manual)
                        {
                            node_put(ripbr_node);
                            break;
                        }

                        struct timespec curr_timestamp;
                        clock_gettime(CLOCK_MONOTONIC, &curr_timestamp);

                        if (curr_timestamp.tv_sec - ripbr->timestamp.tv_sec >= REGBLOCK_EXPIRY)
                        {
                            htable_remove(rt_ctx->reg_ipblock_tbl, ripbr_node->key, ripbr_node->key_size);
                            node_put(ripbr_node);
                        }
                        else if (ripbr->failed_regs)
                    }

                    client_add(&arr, &cl);
                }
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