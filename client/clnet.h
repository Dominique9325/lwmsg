#ifndef LWMSG_CLNET_H
#define LWMSG_CLNET_H

#include "netwrap.h"
#include <openssl/ssl.h>

void load_tcp_fns(net_fns* nfns);

void load_tls_fns(net_fns* nfns);

int32_t send_all(conn* c, net_fns* nfns, void* data, uint64_t len);

int32_t recv_all(conn* c, net_fns* nfns, void* data, uint64_t len);

int32_t resolve_host(const char* host, uint32_t* out_addr);

SSL_CTX* setup_client_ssl_ctx(const char* ca_path);

int32_t do_auth(conn* c, net_fns* nfns, uint32_t req_type, const char* username, const char* password);

#endif
