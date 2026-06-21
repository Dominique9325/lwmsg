//
// Created by dominik on 6/18/26.
//

#include <sys/epoll.h>
#include "thrdctx.h"
#include "worker.h"
#include "clhandle.h"
#include "cltimerheap.h"
#include "dbops.h"
#include "xalloc.h"
#include "zlog.h"
#define THRDNAME_LEN 16

static void cleanup_preauth_client(node* preauth_list, cl_timerheap* clth, node* client_node, int32_t epollfd, net_fns* nfn)
{
    ;
}

static int64_t handle_clth_timeout(node* preauth_list, cl_timerheap* clth, int32_t epollfd, net_fns* nfn)
{
    while (true)
    {
        int64_t timediff = cl_timerheap_compute_root_timediff(clth, ACCEPTED);
        client* cl = NULL;

        switch (timediff)
        {
            case CLTH_NOT_APPLICABLE:
                cl_timerheap_pop(clth);
                break;

            case CLTH_TIMEOUT:
                cl = cl_timerheap_pop(clth);
                req_send_resp(cl, nfn, AUTH_RESP_TIMEOUT);
                cleanup_preauth_client(preauth_list, clth, &((std_client*)cl)->nd, epollfd, nfn);
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

    int32_t epollfd = epoll_create1(0);
    if (epollfd == ERROR)
    {
        dzlog_fatal("Failed to create epoll instance.");
        pthread_exit(NULL);
    }

    sqlite3_stmt* auth_stmt;
    int32_t qres = sqlite3_prepare_v2(wt_ctx->db_rdonly_handle, FETCH_QUERY, -1, &auth_stmt, NULL);
    if (qres != SQLITE_OK)
    {
        dzlog_fatal("Failed to prepare SQL statement for registration. Cause: %s", sqlite3_errmsg(wt_ctx->db_rdonly_handle));
        pthread_exit(NULL);
    }

    std_client** dconn_clients = (std_client**)xmalloc(DEF_STDCL_DCONARR_SIZE * sizeof(std_client*));
    std_client* nonauth_client_list = (std_client*)xcalloc(1, sizeof(std_client));
    cl_timerheap std_clth = {.clients = (client**)xcalloc(DEF_CLTH_SIZE, sizeof(client*)), .num_slots = DEF_CLTH_SIZE, .num_clients = 0};
    epoll_ctx ec_flg_shutdown = {.fd = wt_ctx->flg_shutdown, .type = EP_EVENT};


    dzlog_info("Worker no. %hhu started.", wt_ctx->thrd_id);
    while (true)
    {

    }

}
