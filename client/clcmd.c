#include "clcmd.h"
#include "clrecv.h"
#include "clnet.h"
#include "clio.h"

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

#define DEFAULT_HOST "lwmsg.duckdns.org"
#define DEFAULT_PORT_CONNECT 7228
#define DEFAULT_PORT_REGISTER 6671

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

static bool parse_target(char** tokens, int32_t ntokens, uint16_t default_port, const char** host,
                         uint16_t* port, const char** username, const char** password)
{
    if (ntokens >= 2 && strcmp(tokens[1], "defaulthost") == 0)
    {
        if (ntokens < 4) return false;
        *host = DEFAULT_HOST;
        *port = default_port;
        *username = tokens[2];
        *password = tokens[3];
        return true;
    }

    if (ntokens < 5) return false;
    int32_t p = atoi(tokens[2]);
    if (p <= 0 || p > 65535) return false;
    *host = tokens[1];
    *port = (uint16_t)p;
    *username = tokens[3];
    *password = tokens[4];
    return true;
}

static void cmd_connect(client_ctx* ctx, char** tokens, int32_t ntokens)
{
    if (ctx->state != ST_DISCONNECTED)
    {
        clio_print("Already connected. Disconnect first.\n");
        return;
    }

    const char* host;
    uint16_t port;
    const char* username;
    const char* password;
    if (!parse_target(tokens, ntokens, DEFAULT_PORT_CONNECT, &host, &port, &username, &password))
    {
        clio_print("Usage: connect <host> <port> <username> <password>\n"
                   "   or: connect defaulthost <username> <password>\n");
        return;
    }

    uint32_t addr;
    if (resolve_host(host, &addr) < 0) return;

    if (ctx->use_tls)
        load_tls_fns(&ctx->nfns);
    else
        load_tcp_fns(&ctx->nfns);

    clio_print("Connecting to %s:%u...\n", host, port);
    if (ctx->nfns.connect_fn(&ctx->connection, ctx->ssl_ctx, addr, port) < 0)
    {
        clio_print("Connection failed.\n");
        return;
    }

    if (ctx->use_tls)
        clio_print("TLS handshake OK.\n");

    clio_print("Authenticating as %s...\n", username);
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
    strncpy(ctx->server_host, host, sizeof(ctx->server_host) - 1);
    ctx->server_host[sizeof(ctx->server_host) - 1] = '\0';

    char prompt[INPUT_LINE_MAX];
    snprintf(prompt, sizeof(prompt), "%s@%s> ", ctx->username, ctx->server_host);
    clio_set_prompt(prompt);

    clio_print("Connected as %s.\n", ctx->username);
}

static void cmd_register(client_ctx* ctx, char** tokens, int32_t ntokens)
{
    const char* host;
    uint16_t port;
    const char* username;
    const char* password;
    if (!parse_target(tokens, ntokens, DEFAULT_PORT_REGISTER, &host, &port, &username, &password))
    {
        clio_print("Usage: register <host> <port> <username> <password>\n"
                   "   or: register defaulthost <username> <password>\n");
        return;
    }

    uint32_t addr;
    if (resolve_host(host, &addr) < 0) return;

    conn c = {.sock_fd = ERROR, .ssl = NULL};
    net_fns nfns;

    if (ctx->use_tls)
        load_tls_fns(&nfns);
    else
        load_tcp_fns(&nfns);

    clio_print("Connecting to %s:%u for registration...\n", host, port);
    if (nfns.connect_fn(&c, ctx->ssl_ctx, addr, port) < 0)
    {
        clio_print("Connection failed.\n");
        return;
    }

    int32_t res = do_auth(&c, &nfns, REQ_REGISTRATION, username, password);
    nfns.disconnect_fn(&c);

    if (res == 0)
        clio_print("Registration successful.\n");
}

static void cmd_disconnect(client_ctx* ctx)
{
    if (ctx->state == ST_DISCONNECTED)
    {
        clio_print("Not connected.\n");
        return;
    }
    epoll_ctl(ctx->epoll_fd, EPOLL_CTL_DEL, ctx->connection.sock_fd, NULL);
    ctx->nfns.disconnect_fn(&ctx->connection);
    ctx->state = ST_DISCONNECTED;
    ctx->connection.sock_fd = ERROR;
    ctx->recv_len = 0;
    ctx->username[0] = '\0';
    ctx->server_host[0] = '\0';
    close_all_transfers(ctx);
    clio_reset_prompt();
    clio_print("Disconnected.\n");
}

static void cmd_msg(client_ctx* ctx, char* orig_line)
{
    if (ctx->state != ST_CONNECTED)
    {
        clio_print("Not connected.\n");
        return;
    }

    char tmp[INPUT_LINE_MAX];
    strncpy(tmp, orig_line, INPUT_LINE_MAX - 1);
    tmp[INPUT_LINE_MAX - 1] = '\0';
    char* toks[2];
    int32_t n = tokenize(tmp, toks, 2);
    if (n < 2)
    {
        clio_print("Usage: msg <recipient> <message>\n");
        return;
    }

    char recipient[UNAMESIZE] = {0};
    strncpy(recipient, toks[1], UNAMESIZE - 1);
    normalize_string(recipient);

    char* msg_text = rest_after_tokens(orig_line, 2);
    if (!*msg_text)
    {
        clio_print("Usage: msg <recipient> <message>\n");
        return;
    }

    uint64_t msg_len = strlen(msg_text) + 1;
    if (msg_len > LWMP_PDU_BUF_SIZE)
    {
        clio_print("Message too long (max %d bytes).\n", LWMP_PDU_BUF_SIZE - 1);
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
        clio_print("Failed to send message.\n");
}

static void cmd_sendfile(client_ctx* ctx, char** tokens, int32_t ntokens)
{
    if (ctx->state != ST_CONNECTED)
    {
        clio_print("Not connected.\n");
        return;
    }
    if (ntokens < 3)
    {
        clio_print("Usage: sendfile <recipient> <filepath>\n");
        return;
    }

    char recipient[UNAMESIZE] = {0};
    strncpy(recipient, tokens[1], UNAMESIZE - 1);
    normalize_string(recipient);

    const char* filepath = tokens[2];
    FILE* f = fopen(filepath, "rb");
    if (!f)
    {
        clio_print("Cannot open file: %s\n", strerror(errno));
        return;
    }

    fseek(f, 0, SEEK_END);
    int64_t file_size = (int64_t)ftell(f);
    fseek(f, 0, SEEK_SET);
    if (file_size <= 0)
    {
        clio_print("File is empty or unreadable.\n");
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
        clio_print("Failed to read file.\n");
        fclose(f);
        return;
    }
    pdu.crc32 = htonl(crc32(&pdu, offsetof(lwmp_pdu, crc32)));

    if (send_all(&ctx->connection, &ctx->nfns, &pdu, LWMP_HDR_SIZE + first_chunk) < 0)
    {
        clio_print("Failed to send file header.\n");
        fclose(f);
        return;
    }

    bool multi = (uint64_t)file_size > LWMP_PDU_BUF_SIZE;
    if (!multi)
    {
        fclose(f);
        clio_print("File %s (%" PRId64 " bytes) sent to %s.\n", filepath, file_size, recipient);
        return;
    }

    ctx->transfer_error = false;
    uint32_t resp_code = 0;
    int32_t ar = await_resp(ctx, &resp_code);
    if (ar == -2)
    {
        fclose(f);
        return;
    }
    if (ar == -1)
    {
        clio_print("No response from server; aborting transfer.\n");
        fclose(f);
        return;
    }
    if (resp_code != RESP_OK)
    {
        clio_print("Server rejected the file; aborting transfer.\n");
        fclose(f);
        return;
    }

    ctx->sending_chunks = true;
    uint64_t remaining = (uint64_t)file_size - first_chunk;
    bool aborted = false;

    while (remaining > 0)
    {
        unsigned char data[LWMP_MAX_PDU_SIZE];
        uint64_t chunk_sz = remaining < sizeof(data) ? remaining : sizeof(data);
        if (fread(data, 1, chunk_sz, f) != chunk_sz)
        {
            clio_print("Failed to read file.\n");
            aborted = true;
            break;
        }

        if (send_all(&ctx->connection, &ctx->nfns, data, chunk_sz) < 0)
        {
            clio_print("Failed to send file data.\n");
            aborted = true;
            break;
        }
        remaining -= chunk_sz;

        pump_socket_once(ctx);
        if (ctx->state != ST_CONNECTED || ctx->transfer_error)
        {
            aborted = true;
            break;
        }
    }

    ctx->sending_chunks = false;
    fclose(f);

    if (aborted)
        clio_print("File transfer to %s aborted.\n", recipient);
    else
        clio_print("File %s (%" PRId64 " bytes) sent to %s.\n", filepath, file_size, recipient);
}

static void cmd_clear(void)
{
    clio_print("\x1b[2J\x1b[H");
}

static void cmd_userlist(client_ctx* ctx)
{
    if (ctx->state != ST_CONNECTED)
    {
        clio_print("Not connected.\n");
        return;
    }

    lwmp_pdu pdu = {0};
    pdu.hdr_mark = htonl(PDU_SYNC_HDR_MARK);
    pdu.msg_type = MT_REQ;
    pdu.request.req_type = htonl(REQ_USER_LIST);
    pdu.total_msg_size = 0;
    pdu.crc32 = htonl(crc32(&pdu, offsetof(lwmp_pdu, crc32)));

    if (send_all(&ctx->connection, &ctx->nfns, &pdu, LWMP_HDR_SIZE) < 0)
        clio_print("Failed to send userlist request.\n");
}

typedef struct help_entry
{
    const char* name;
    const char* desc;
    const char* usage;
} help_entry;

static const help_entry help_table[] = {
    {"connect",    "Connect and authenticate to a server.",
                   "connect <host> <port> <username> <password>\n"
                   "     or: connect defaulthost <username> <password>"},
    {"register",   "Register a new account on a server.",
                   "register <host> <port> <username> <password>\n"
                   "     or: register defaulthost <username> <password>"},
    {"disconnect", "Disconnect from the current server.",
                   "disconnect"},
    {"msg",        "Send a text message to a user.",
                   "msg <recipient> <message>"},
    {"sendfile",   "Send a file to a user.",
                   "sendfile <recipient> <filepath>"},
    {"userlist",   "List all online users.",
                   "userlist"},
    {"clear",      "Clears the screen.",
                   "clear"},
    {"help",       "Displays all available commands and their usage.",
                   "help [command]"},
    {"quit",       "Exit the client.",
                   "quit  (or q)"}
};

static void print_help_entry(const help_entry* e)
{
    clio_print("%s - %s\n", e->name, e->desc);
    clio_print("  Usage: %s\n", e->usage);
}

static void cmd_help(char** tokens, int32_t ntokens)
{
    size_t count = sizeof(help_table) / sizeof(help_table[0]);

    if (ntokens < 2)
    {
        for (size_t i = 0; i < count; i++)
            print_help_entry(&help_table[i]);
        return;
    }

    const char* cmd = tokens[1];
    if (strcmp(cmd, "q") == 0) cmd = "quit";
    for (size_t i = 0; i < count; i++)
    {
        if (strcmp(cmd, help_table[i].name) == 0)
        {
            print_help_entry(&help_table[i]);
            return;
        }
    }
    clio_print("Unknown command: %s\n", cmd);
}

void handle_command_line(client_ctx* ctx, char* line)
{
    if (!line[0]) return;

    char line_copy[INPUT_LINE_MAX];
    strncpy(line_copy, line, INPUT_LINE_MAX - 1);
    line_copy[INPUT_LINE_MAX - 1] = '\0';

    char* tokens[MAX_TOKENS];
    int32_t ntokens = tokenize(line, tokens, MAX_TOKENS);
    if (ntokens == 0) return;

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
    else if (strcmp(tokens[0], "clear") == 0)
        cmd_clear();
    else if (strcmp(tokens[0], "help") == 0)
        cmd_help(tokens, ntokens);
    else
        clio_print("Unknown command: %s. Type 'help' for commands.\n", tokens[0]);
}
