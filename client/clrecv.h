#ifndef LWMSG_CLRECV_H
#define LWMSG_CLRECV_H

#include "client.h"

void handle_socket_data(client_ctx* ctx);

void close_all_transfers(client_ctx* ctx);

int32_t await_resp(client_ctx* ctx, uint32_t* out_code);

void pump_socket_once(client_ctx* ctx);

#endif
