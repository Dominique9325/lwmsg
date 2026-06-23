#include "clnet.h"

#include <stdio.h>
#include <string.h>
#include <netdb.h>
#include <netinet/in.h>
#include "lwmp.h"

static const unsigned char client_alpn[] = {4, 'l', 'w', 'm', 'p'};

void load_tcp_fns(net_fns* nfns)
{
    nfns->send_fn = send_tcp;
    nfns->recv_fn = recv_tcp;
    nfns->disconnect_fn = disconnect_tcp;
    nfns->avail_data_fn = avail_data_tcp;
    nfns->accept_fn = NULL;
    nfns->connect_fn = connect_tcp;
}

void load_tls_fns(net_fns* nfns)
{
    nfns->send_fn = send_tls;
    nfns->recv_fn = recv_tls;
    nfns->disconnect_fn = disconnect_tls;
    nfns->avail_data_fn = avail_data_tls;
    nfns->accept_fn = NULL;
    nfns->connect_fn = connect_tls;
}

int32_t send_all(conn* c, net_fns* nfns, void* data, uint64_t len)
{
    uint64_t sent = 0;
    while (sent < len)
    {
        int64_t n = nfns->send_fn(c, (char*)data + sent, len - sent);
        if (n == EBLOCK) continue;
        if (n <= 0) return -1;
        sent += n;
    }
    return 0;
}

int32_t recv_all(conn* c, net_fns* nfns, void* data, uint64_t len)
{
    uint64_t got = 0;
    while (got < len)
    {
        int64_t n = nfns->recv_fn(c, (char*)data + got, len - got);
        if (n == EBLOCK) continue;
        if (n <= 0) return -1;
        got += n;
    }
    return 0;
}

int32_t resolve_host(const char* host, uint32_t* out_addr)
{
    struct addrinfo hints = {0};
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;

    struct addrinfo* res;
    int32_t err = getaddrinfo(host, NULL, &hints, &res);
    if (err)
    {
        fprintf(stderr, "DNS resolution failed: %s\n", gai_strerror(err));
        return -1;
    }

    struct sockaddr_in* addr = (struct sockaddr_in*)res->ai_addr;
    *out_addr = addr->sin_addr.s_addr;
    freeaddrinfo(res);
    return 0;
}

SSL_CTX* setup_client_ssl_ctx(const char* ca_path)
{
    SSL_CTX* ctx = SSL_CTX_new(TLS_client_method());
    if (!ctx) return NULL;
    SSL_CTX_set_alpn_protos(ctx, client_alpn, sizeof(client_alpn));
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);

    if (ca_path)
    {
        if (SSL_CTX_load_verify_locations(ctx, ca_path, NULL) != 1)
        {
            fprintf(stderr, "Failed to load CA certificate: %s\n", ca_path);
            SSL_CTX_free(ctx);
            return NULL;
        }
    }
    else
    {
        if (SSL_CTX_set_default_verify_paths(ctx) != 1)
        {
            fprintf(stderr, "Failed to load system CA certificates.\n");
            SSL_CTX_free(ctx);
            return NULL;
        }
    }

    return ctx;
}

int32_t do_auth(conn* c, net_fns* nfns, uint32_t req_type, const char* username, const char* password)
{
    auth_req_group req = {0};
    req.request_type = htonl(req_type);
    strncpy(req.username, username, UNAMESIZE - 1);
    strncpy(req.password, password, PWDSIZE - 1);

    if (send_all(c, nfns, &req, sizeof(req)) < 0)
    {
        fprintf(stderr, "Failed to send auth request.\n");
        return -1;
    }

    auth_resp resp = {0};
    if (recv_all(c, nfns, &resp, sizeof(resp)) < 0)
    {
        fprintf(stderr, "Failed to receive auth response.\n");
        return -1;
    }

    uint32_t code = ntohl(resp.resp_code);
    if (code == AUTH_RESP_OK)
        return 0;

    switch (code)
    {
        case AUTH_RESP_INVAL_REQ:    fprintf(stderr, "Server: invalid request.\n"); break;
        case AUTH_RESP_INVAL_PARAM:  fprintf(stderr, "Server: invalid parameters.\n"); break;
        case AUTH_RESP_TIMEOUT:      fprintf(stderr, "Server: auth timeout.\n"); break;
        case AUTH_RESP_DUPLICATE:    fprintf(stderr, "Server: user already exists/logged in.\n"); break;
        default:                     fprintf(stderr, "Server: unknown response 0x%08X.\n", code); break;
    }
    return -1;
}
