#include "clcmd.h"
#include "clnet.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <inttypes.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <fcntl.h>
#include <errno.h>
#include <endian.h>
#include <netinet/in.h>
#include "util.h"

int32_t tokenize(char* line, char** tokens, int32_t max_tokens)
{
    int32_t n = 0;
    char* p = line;
    while (*p && n < max_tokens)
    {
        while (*p == ' ' || *p == '\t') p++;
        if (!*p) break;

        if (*p == '"')
        {
            p++;
            tokens[n++] = p;
            while (*p && *p != '"') p++;
            if (*p == '"') *p++ = '\0';
        }
        else
        {
            tokens[n++] = p;
            while (*p && *p != ' ' && *p != '\t') p++;
            if (*p) *p++ = '\0';
        }
    }
    return n;
}

char* rest_after_tokens(char* line, int32_t skip)
{
    char* p = line;
    for (int32_t i = 0; i < skip; i++)
    {
        while (*p == ' ' || *p == '\t') p++;
        if (!*p) return p;
        if (*p == '"')
        {
            p++;
            while (*p && *p != '"') p++;
            if (*p == '"') p++;
        }
        else
        {
            while (*p && *p != ' ' && *p != '\t') p++;
        }
    }
    while (*p == ' ' || *p == '\t') p++;
    return p;
}

static void cmd_connect(client_ctx* ctx, char** tokens, int32_t ntokens)
{
    if (ctx->state != ST_DISCONNECTED)
    {
        printf("Already connected. Disconnect first.\n");
        return;
    }
    if (ntokens < 5)
    {
        printf("Usage: connect <host> <port> <username> <password>\n");
        return;
    }

    const char* host = tokens[1];
    uint16_t port = (uint16_t)atoi(tokens[2]);
    const char* username = tokens[3];
    const char* password = tokens[4];

    if (!port) { printf("Invalid port.\n"); return; }

    uint32_t addr;
    if (resolve_host(host, &addr) < 0) return;

    if (ctx->use_tls)
        load_tls_fns(&ctx->nfns);
    else
        load_tcp_fns(&ctx->nfns);

    printf("Connecting to %s:%u...\n", host, port);
    if (ctx->nfns.connect_fn(&ctx->connection, ctx->ssl_ctx, addr, port) < 0)
    {
        fprintf(stderr, "Connection failed.\n");
        return;
    }

    if (ctx->use_tls)
        printf("TLS handshake OK.\n");

    printf("Authenticating as %s...\n", username);
    if (do_auth(&ctx->connection, &ctx->nfns, REQ_AUTHENTICATION, username, password) < 0)
    {
        ctx->nfns.disconnect_fn(&ctx->connection);
        return;
    }

    strncpy(ctx->username, username, UNAMESIZE - 1);
    normalize_string(ctx->username);

    int32_t flags = fcntl(ctx->connection.sock_fd, F_GETFL, 0);
    fcntl(ctx->connection.sock_fd, F_SETFL, flags | O_NONBLOCK);
    struct timeval tv = {0};
    setsockopt(ctx->connection.sock_fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(ctx->connection.sock_fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

    struct epoll_event ev = {.events = EPOLLIN, .data.fd = ctx->connection.sock_fd};
    epoll_ctl(ctx->epoll_fd, EPOLL_CTL_ADD, ctx->connection.sock_fd, &ev);

    ctx->state = ST_CONNECTED;
    ctx->recv_len = 0;
    printf("Connected as %s.\n", ctx->username);
}

static void cmd_register(client_ctx* ctx, char** tokens, int32_t ntokens)
{
    if (ntokens < 5)
    {
        printf("Usage: register <host> <port> <username> <password>\n");
        return;
    }

    const char* host = tokens[1];
    uint16_t port = (uint16_t)atoi(tokens[2]);
    const char* username = tokens[3];
    const char* password = tokens[4];

    if (!port) { printf("Invalid port.\n"); return; }

    uint32_t addr;
    if (resolve_host(host, &addr) < 0) return;

    conn c = {.sock_fd = ERROR, .ssl = NULL};
    net_fns nfns;

    if (ctx->use_tls)
        load_tls_fns(&nfns);
    else
        load_tcp_fns(&nfns);

    printf("Connecting to %s:%u for registration...\n", host, port);
    if (nfns.connect_fn(&c, ctx->ssl_ctx, addr, port) < 0)
    {
        fprintf(stderr, "Connection failed.\n");
        return;
    }

    int32_t res = do_auth(&c, &nfns, REQ_REGISTRATION, username, password);
    nfns.disconnect_fn(&c);

    if (res == 0)
        printf("Registration successful.\n");
}

static void cmd_disconnect(client_ctx* ctx)
{
    if (ctx->state == ST_DISCONNECTED)
    {
        printf("Not connected.\n");
        return;
    }
    epoll_ctl(ctx->epoll_fd, EPOLL_CTL_DEL, ctx->connection.sock_fd, NULL);
    ctx->nfns.disconnect_fn(&ctx->connection);
    ctx->state = ST_DISCONNECTED;
    ctx->connection.sock_fd = ERROR;
    ctx->recv_len = 0;
    ctx->username[0] = '\0';
    printf("Disconnected.\n");
}

static void cmd_msg(client_ctx* ctx, char* orig_line)
{
    if (ctx->state != ST_CONNECTED)
    {
        printf("Not connected.\n");
        return;
    }

    char tmp[INPUT_LINE_MAX];
    strncpy(tmp, orig_line, INPUT_LINE_MAX - 1);
    tmp[INPUT_LINE_MAX - 1] = '\0';
    char* toks[2];
    int32_t n = tokenize(tmp, toks, 2);
    if (n < 2)
    {
        printf("Usage: msg <recipient> <message>\n");
        return;
    }

    char recipient[UNAMESIZE] = {0};
    strncpy(recipient, toks[1], UNAMESIZE - 1);
    normalize_string(recipient);

    char* msg_text = rest_after_tokens(orig_line, 2);
    if (!*msg_text)
    {
        printf("Usage: msg <recipient> <message>\n");
        return;
    }

    uint64_t msg_len = strlen(msg_text) + 1;
    if (msg_len > LWMP_PDU_BUF_SIZE)
    {
        printf("Message too long (max %d bytes).\n", LWMP_PDU_BUF_SIZE - 1);
        return;
    }

    lwmp_pdu pdu = {0};
    pdu.hdr_mark = htonl(PDU_SYNC_HDR_MARK);
    pdu.msg_type = MT_MSG;
    strncpy(pdu.subject_uname, recipient, UNAMESIZE);
    pdu.total_msg_size = htobe64(msg_len);
    memcpy(pdu.buf, msg_text, msg_len);
    pdu.crc32 = htonl(crc32(&pdu, offsetof(lwmp_pdu, crc32)));

    if (send_all(&ctx->connection, &ctx->nfns, &pdu, LWMP_HDR_SIZE + msg_len) < 0)
        fprintf(stderr, "Failed to send message.\n");
}

static void cmd_sendfile(client_ctx* ctx, char** tokens, int32_t ntokens)
{
    if (ctx->state != ST_CONNECTED)
    {
        printf("Not connected.\n");
        return;
    }
    if (ntokens < 3)
    {
        printf("Usage: sendfile <recipient> <filepath>\n");
        return;
    }

    char recipient[UNAMESIZE] = {0};
    strncpy(recipient, tokens[1], UNAMESIZE - 1);
    normalize_string(recipient);

    const char* filepath = tokens[2];
    FILE* f = fopen(filepath, "rb");
    if (!f)
    {
        fprintf(stderr, "Cannot open file: %s\n", strerror(errno));
        return;
    }

    fseek(f, 0, SEEK_END);
    int64_t file_size = (int64_t)ftell(f);
    fseek(f, 0, SEEK_SET);
    if (file_size <= 0)
    {
        printf("File is empty or unreadable.\n");
        fclose(f);
        return;
    }

    lwmp_pdu pdu = {0};
    pdu.hdr_mark = htonl(PDU_SYNC_HDR_MARK);
    pdu.msg_type = MT_FILE;
    strncpy(pdu.subject_uname, recipient, UNAMESIZE);
    pdu.total_msg_size = htobe64((uint64_t)file_size);

    strncpy(pdu.file_metadata.buf, filepath, OPTDATA_LEN - 1);

    uint64_t first_chunk = (uint64_t)file_size < LWMP_PDU_BUF_SIZE ? (uint64_t)file_size : LWMP_PDU_BUF_SIZE;
    if (fread(pdu.buf, 1, first_chunk, f) != first_chunk)
    {
        fprintf(stderr, "Failed to read file.\n");
        fclose(f);
        return;
    }
    pdu.crc32 = htonl(crc32(&pdu, offsetof(lwmp_pdu, crc32)));

    if (send_all(&ctx->connection, &ctx->nfns, &pdu, LWMP_HDR_SIZE + first_chunk) < 0)
    {
        fprintf(stderr, "Failed to send file header.\n");
        fclose(f);
        return;
    }

    uint64_t remaining = (uint64_t)file_size - first_chunk;
    while (remaining > 0)
    {
        unsigned char data[LWMP_CHUNK_BUF_SIZE];
        uint16_t chunk_sz = remaining < LWMP_CHUNK_BUF_SIZE ? (uint16_t)remaining : LWMP_CHUNK_BUF_SIZE;
        if (fread(data, 1, chunk_sz, f) != chunk_sz)
        {
            fprintf(stderr, "Failed to read file.\n");
            fclose(f);
            return;
        }

        lwmp_chunk chunk = {0};
        lwmp_prepare_chunk(&chunk, chunk_sz, recipient, data);

        if (send_all(&ctx->connection, &ctx->nfns, &chunk, LWMP_CHUNK_HDR_SIZE + chunk_sz) < 0)
        {
            fprintf(stderr, "Failed to send file chunk.\n");
            fclose(f);
            return;
        }
        remaining -= chunk_sz;
    }

    fclose(f);
    printf("File %s (%" PRId64 " bytes) sent to %s.\n", filepath, file_size, recipient);
}

static void cmd_userlist(client_ctx* ctx)
{
    if (ctx->state != ST_CONNECTED)
    {
        printf("Not connected.\n");
        return;
    }

    lwmp_pdu pdu = {0};
    pdu.hdr_mark = htonl(PDU_SYNC_HDR_MARK);
    pdu.msg_type = MT_REQ;
    pdu.request.req_type = htonl(REQ_USER_LIST);
    pdu.total_msg_size = 0;
    pdu.crc32 = htonl(crc32(&pdu, offsetof(lwmp_pdu, crc32)));

    if (send_all(&ctx->connection, &ctx->nfns, &pdu, LWMP_HDR_SIZE) < 0)
        fprintf(stderr, "Failed to send userlist request.\n");
}

static void cmd_list(void)
{
    printf("connect, register, disconnect, msg, sendfile, userlist, list, help, quit\n");
}

static void cmd_help(char** tokens, int32_t ntokens)
{
    if (ntokens < 2)
    {
        printf("Use 'list' to see available commands.\n"
               "Use 'help <command>' for details on a specific command.\n");
        return;
    }

    const char* cmd = tokens[1];
    if (strcmp(cmd, "connect") == 0)
        printf("Connect and authenticate to a server.\n"
               "Usage: connect <host> <port> <username> <password>\n");
    else if (strcmp(cmd, "register") == 0)
        printf("Register a new account on a server.\n"
               "Usage: register <host> <port> <username> <password>\n");
    else if (strcmp(cmd, "disconnect") == 0)
        printf("Disconnect from the current server.\n"
               "Usage: disconnect\n");
    else if (strcmp(cmd, "msg") == 0)
        printf("Send a text message to a user.\n"
               "Usage: msg <recipient> <message>\n");
    else if (strcmp(cmd, "sendfile") == 0)
        printf("Send a file to a user.\n"
               "Usage: sendfile <recipient> <filepath>\n");
    else if (strcmp(cmd, "userlist") == 0)
        printf("List all online users.\n"
               "Usage: userlist\n");
    else if (strcmp(cmd, "list") == 0)
        printf("List all available commands.\n"
               "Usage: list\n");
    else if (strcmp(cmd, "help") == 0)
        printf("Show help for a command.\n"
               "Usage: help <command>\n");
    else if (strcmp(cmd, "quit") == 0 || strcmp(cmd, "q") == 0)
        printf("Exit the client.\n"
               "Usage: quit\n");
    else
        printf("Unknown command: %s\n", cmd);
}

static void dispatch_line(client_ctx* ctx, char* line)
{
    if (!line[0]) { printf("> "); fflush(stdout); return; }

    char line_copy[INPUT_LINE_MAX];
    strncpy(line_copy, line, INPUT_LINE_MAX - 1);
    line_copy[INPUT_LINE_MAX - 1] = '\0';

    char* tokens[MAX_TOKENS];
    int32_t ntokens = tokenize(line, tokens, MAX_TOKENS);
    if (ntokens == 0) { printf("> "); fflush(stdout); return; }

    if (strcmp(tokens[0], "connect") == 0)
        cmd_connect(ctx, tokens, ntokens);
    else if (strcmp(tokens[0], "register") == 0)
        cmd_register(ctx, tokens, ntokens);
    else if (strcmp(tokens[0], "disconnect") == 0)
        cmd_disconnect(ctx);
    else if (strcmp(tokens[0], "quit") == 0 || strcmp(tokens[0], "q") == 0)
        ctx->running = false;
    else if (strcmp(tokens[0], "msg") == 0)
        cmd_msg(ctx, line_copy);
    else if (strcmp(tokens[0], "sendfile") == 0)
        cmd_sendfile(ctx, tokens, ntokens);
    else if (strcmp(tokens[0], "userlist") == 0)
        cmd_userlist(ctx);
    else if (strcmp(tokens[0], "list") == 0)
        cmd_list();
    else if (strcmp(tokens[0], "help") == 0)
        cmd_help(tokens, ntokens);
    else
        printf("Unknown command: %s. Type 'help' for commands.\n", tokens[0]);

    if (ctx->running) { printf("> "); fflush(stdout); }
}

void handle_stdin(client_ctx* ctx)
{
    int64_t n = read(STDIN_FILENO, ctx->stdin_buf + ctx->stdin_len,
                     INPUT_LINE_MAX - 1 - ctx->stdin_len);
    if (n <= 0)
    {
        ctx->running = false;
        return;
    }

    ctx->stdin_len += n;

    char* nl;
    while ((nl = memchr(ctx->stdin_buf, '\n', ctx->stdin_len)) != NULL)
    {
        *nl = '\0';
        dispatch_line(ctx, ctx->stdin_buf);

        uint32_t consumed = (uint32_t)(nl - ctx->stdin_buf) + 1;
        ctx->stdin_len -= consumed;
        if (ctx->stdin_len > 0)
            memmove(ctx->stdin_buf, nl + 1, ctx->stdin_len);
    }

    if (ctx->stdin_len >= INPUT_LINE_MAX - 1)
    {
        ctx->stdin_buf[INPUT_LINE_MAX - 1] = '\0';
        dispatch_line(ctx, ctx->stdin_buf);
        ctx->stdin_len = 0;
    }
}
