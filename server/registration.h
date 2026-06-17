//
// Created by dominik on 6/12/26.
//

#ifndef LWMSG_REGISTRATION_H
#define LWMSG_REGISTRATION_H
#include <sys/eventfd.h>
#include <stdbool.h>
#include <sqlite3.h>
#include "clhandle.h"
#include "lwmp.h"

void* reg_thrd_routine(void* reg_thread_ctx);

bool process_reg_req(sqlite3* dbc, sqlite3_stmt* reg_stmt, reg_req_group* req);

void reg_send_resp(client* cl, net_fns* nfn, uint32_t resp_type);

#endif //LWMSG_REGISTRATION_H
