//
// Created by gf-senka on 6/7/2026.
//

#include "netwrap.h"

#include <unistd.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <errno.h>
#include <openssl/err.h>
#include "zlog.h"
#include "misc.h"

int32_t server_start_tcp(uint32_t be_inet4addr, uint16_t le_port, uint16_t backlog, bool nonblock, bool reuse_port)
{
    int32_t sock = socket(AF_INET, SOCK_STREAM | (nonblock ? SOCK_NONBLOCK : 0), IPPROTO_TCP);
    if (sock == ERROR)
        return ERROR;

    if (reuse_port)
        setsockopt(sock, SOL_SOCKET, SO_REUSEPORT, &reuse_port, sizeof(reuse_port));

    struct sockaddr_in addr = {.sin_addr.s_addr = be_inet4addr, .sin_port = htons(le_port), .sin_family = AF_INET};
    int res = bind(sock, (struct sockaddr*)&addr, sizeof(addr));
    if (res == ERROR)
    {
        int32_t err = errno;
        if (err == EADDRNOTAVAIL)
        {
            dzlog_fatal("Error: %u.%u.%u.%u is not a valid interface.", IP4DOT(addr.sin_addr.s_addr));
            goto error;
        }
        else if (err == EADDRINUSE)
        {
            uint16_t new_port = le_port + 1;
            do
            {
                addr.sin_port = htons(new_port++);
                res = bind(sock, (struct sockaddr*)&addr, sizeof(addr));
            }while (res == ERROR && errno == EADDRINUSE && new_port < UINT16_MAX);

            if (res == ERROR)
            {
                dzlog_fatal("Original port %u is already in use, failed to find a suitable replacement.", le_port);
                goto error;
            }

            dzlog_warn("Original port %u is already in use, switched to using port %u.", le_port, new_port - 1);
        }
        else
        {
            dzlog_fatal("Failed to bind to interface %u.%u.%u.%u:%u. Reason: %s",  IP4DOT(be_inet4addr), le_port, strerror(err));
            goto error;
        }
    }

    listen(sock, backlog);
    return sock;

    error:
    close(sock);
    return ERROR;
}

int32_t accept_tcp(conn* c, SSL_CTX* ssl_ctx)
{
    (void)ssl_ctx;
    return ACCPT_DONE;
}

//int32_t connect_tcp(uint32_t be_inet4addr, uint16_t le_port);

int64_t send_tcp(conn* c, void* buf, uint64_t len)
{
    int64_t written = send(c->sock_fd, buf, len, MSG_NOSIGNAL);
    if (written == ERROR)
    {
        int32_t err = errno;
        switch (err)
        {
            case EAGAIN : return EBLOCK;
            case ECONNRESET:
            case EPIPE : return ERROR;
            default: return ERROR;
        }
    }

    return written;
}

int64_t recv_tcp(conn* c, void* buf, uint64_t len)
{
    int64_t received = recv(c->sock_fd, buf, len, 0);
    if (received == ERROR)
    {
        int32_t err = errno;
        switch (err)
        {
            case EAGAIN : return EBLOCK;
            case ECONNRESET : return ERROR;
            default: return ERROR;
        }
    }

    return received;
}

uint64_t avail_data_tcp(conn* c)
{
    uint64_t data;
    ioctl(c->sock_fd, FIONREAD, &data);
    return data;
}

void disconnect_tcp(conn* c)
{
    close(c->sock_fd);
}

int32_t accept_tls(conn* c, SSL_CTX* ssl_ctx)
{
    if (!c->ssl)
    {
        SSL* ssl = SSL_new(ssl_ctx);
        if (!ssl)
            return ERROR;

        if (!SSL_set_fd(ssl, c->sock_fd))
            return ERROR;

        c->ssl = ssl;
    }


    int32_t res = SSL_accept(c->ssl);
    if (res != 1)
    {
        int32_t err = SSL_get_error(c->ssl, res);
        dzlog_info("SSL error: %d", err);
        switch (err)
        {
            case SSL_ERROR_ZERO_RETURN:
            case SSL_ERROR_SYSCALL: return ERROR;
            case SSL_ERROR_WANT_READ:
            case SSL_ERROR_WANT_WRITE: return ACCPT_IN_PROGRESS;
            default: return ERROR;
        }
    }
    return ACCPT_DONE;
}

int32_t connect_tls(uint32_t be_inet4addr, uint16_t le_port);

int64_t send_tls(conn* c, void* buf, uint64_t len)
{
    int32_t res = SSL_write(c->ssl, buf, (int32_t)len);
    if (res <= 0)
    {
        int32_t err = SSL_get_error(c->ssl, res);
        switch (err)
        {
            case SSL_ERROR_ZERO_RETURN:
            case SSL_ERROR_SYSCALL: return ERROR;
            case SSL_ERROR_WANT_READ:
            case SSL_ERROR_WANT_WRITE: return EBLOCK;
            default: return ERROR;
        }
    }
    return res;
}

int64_t recv_tls(conn* c, void* buf, uint64_t len)
{
    int32_t res = SSL_read(c->ssl, buf, (int32_t)len);
    if (res <= 0)
    {
        int32_t err = SSL_get_error(c->ssl, res);
        switch (err)
        {
            case SSL_ERROR_ZERO_RETURN:
            case SSL_ERROR_SYSCALL: return ERROR;
            case SSL_ERROR_WANT_READ:
            case SSL_ERROR_WANT_WRITE: return EBLOCK;
            default: return ERROR;
        }
    }
    return res;
}

uint64_t avail_data_tls(conn* c)
{
    int32_t data = SSL_pending(c->ssl);
    if (data < 0)
        return 0;

    return data;
}

void disconnect_tls(conn* c)
{
    if (c->ssl && SSL_is_init_finished(c->ssl))
    {
        SSL_shutdown(c->ssl);
        SSL_free(c->ssl);
    }

    close(c->sock_fd);
}