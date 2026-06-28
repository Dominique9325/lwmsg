#include "clrecv.h"
#include "clio.h"

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <poll.h>
#include <sys/epoll.h>
#include <inttypes.h>
#include <endian.h>
#include <netinet/in.h>

static const char* sanitize_filename(const char* raw)
{
    const char* base = raw;
    const char* p = strrchr(raw, '/');
    if (p) base = p + 1;
    p = strrchr(base, '\\');
    if (p) base = p + 1;
    if (!base[0] || strcmp(base, ".") == 0 || strcmp(base, "..") == 0)
        return "received_file";
    return base;
}

#define MAX_DEDUP_ATTEMPTS 10000

static void make_unique_filename(const char* desired, char* out, size_t out_cap)
{
    const char* dot = strrchr(desired, '.');
    const char* ext = (dot && dot != desired) ? dot : "";
    size_t stem_len = (dot && dot != desired) ? (size_t)(dot - desired) : strlen(desired);
    size_t ext_len = strlen(ext);

    snprintf(out, out_cap, "%s", desired);
    if (access(out, F_OK) != 0)
        return;

    size_t maxlen = OPTDATA_LEN;
    if (maxlen > out_cap - 1)
        maxlen = out_cap - 1;

    for (uint32_t n = 1; n <= MAX_DEDUP_ATTEMPTS; n++)
    {
        char suffix[16];
        int slen = snprintf(suffix, sizeof(suffix), "(%u)", n);
        size_t fixed = ext_len + (size_t)slen;
        size_t avail_stem = (maxlen > fixed) ? maxlen - fixed : 0;
        size_t use_stem = stem_len < avail_stem ? stem_len : avail_stem;
        snprintf(out, out_cap, "%.*s%s%s", (int)use_stem, desired, suffix, ext);
        if (access(out, F_OK) != 0)
            return;
    }
}

static file_transfer* find_transfer(client_ctx* ctx, const char* sender)
{
    for (int32_t i = 0; i < MAX_ACTIVE_TRANSFERS; i++)
        if (ctx->transfers[i].active && strncmp(ctx->transfers[i].sender, sender, UNAMESIZE) == 0)
            return &ctx->transfers[i];
    return NULL;
}

static file_transfer* alloc_transfer(client_ctx* ctx)
{
    for (int32_t i = 0; i < MAX_ACTIVE_TRANSFERS; i++)
        if (!ctx->transfers[i].active)
            return &ctx->transfers[i];
    return NULL;
}

void close_all_transfers(client_ctx* ctx)
{
    for (int32_t i = 0; i < MAX_ACTIVE_TRANSFERS; i++)
    {
        if (ctx->transfers[i].active && ctx->transfers[i].fp)
        {
            fclose(ctx->transfers[i].fp);
            ctx->transfers[i].fp = NULL;
        }
        ctx->transfers[i].active = false;
    }
}

static void cache_userlist(client_ctx* ctx, const unsigned char* buf, uint64_t payload_size)
{
    ctx->user_cache_count = 0;
    uint64_t offset = 0;
    while (offset < payload_size && ctx->user_cache_count < USER_CACHE_MAX)
    {
        const char* uname = (const char*)(buf + offset);
        uint64_t len = strnlen(uname, payload_size - offset);
        if (len > 0 && len <= UNAMESIZE)
        {
            memcpy(ctx->user_cache[ctx->user_cache_count], uname, len);
            ctx->user_cache[ctx->user_cache_count][len] = '\0';
            ctx->user_cache_count++;
        }
        offset += len + 1;
    }
}

static const char* resp_friendly(uint32_t code)
{
    switch (code)
    {
        case RESP_OK:              return "OK.";
        case RESP_DISALLOWED_FILE: return "The server does not allow file transfers.";
        case RESP_TOOBIG_FILE:     return "The file is larger than the server allows.";
        case RESP_TOOBIG_MSG:      return "The message is too large.";
        case RESP_INVAL_CRC:       return "The message failed integrity validation (CRC mismatch).";
        case RESP_INVAL_REQ:       return "The server rejected the request as invalid.";
        case RESP_INVAL_PDU:       return "The server received a malformed message.";
        case RESP_DCONN_SUBJ:      return "The recipient is offline or has disconnected.";
        default:                   return "Unknown server response.";
    }
}

static void print_server_resp(lwmp_pdu* pdu, uint64_t payload_size, uint32_t resp_code)
{
    if (resp_code == RESP_OK)
        return;

    if (payload_size > 0 && payload_size <= LWMP_PDU_BUF_SIZE)
    {
        pdu->buf[payload_size - 1] = '\0';
        clio_print("[server] %s (%s)\n", (char*)pdu->buf, strresp(resp_code));
    }
    else
        clio_print("[server] %s (%s)\n", resp_friendly(resp_code), strresp(resp_code));
}

static void process_received_pdu(client_ctx* ctx, lwmp_pdu* pdu, uint64_t payload_size)
{
    char sender[UNAMESIZE + 1] = {0};
    memcpy(sender, pdu->subject_uname, UNAMESIZE);

    switch (pdu->msg_type)
    {
        case MT_MSG:
        {
            if (payload_size > 0 && payload_size <= LWMP_PDU_BUF_SIZE)
                pdu->buf[payload_size - 1] = '\0';
            else
                pdu->buf[0] = '\0';
            clio_print("[%s]: %s\n", sender, pdu->buf);
            break;
        }
        case MT_INFO:
        {
            uint32_t resp_code = ntohl(pdu->response.resp_code);
            print_server_resp(pdu, payload_size, resp_code);

            if (ctx->awaiting_resp)
            {
                ctx->last_resp_code = resp_code;
                ctx->awaiting_resp = false;
            }
            if (ctx->sending_chunks && resp_code != RESP_OK)
                ctx->transfer_error = true;
            break;
        }
        case MT_REQ:
        {
            uint32_t resp_code = ntohl(pdu->response.resp_code);
            if (resp_code == RESP_OK && payload_size > 0)
            {
                cache_userlist(ctx, pdu->buf, payload_size);
                clio_print("Online users (%d):\n", ctx->user_cache_count);
                for (int32_t i = 0; i < ctx->user_cache_count; i++)
                    clio_print("  %s\n", ctx->user_cache[i]);
            }
            else
                print_server_resp(pdu, payload_size, resp_code);
            break;
        }
        case MT_FILE:
        {
            uint64_t file_size = be64toh(pdu->total_msg_size);

            char raw_name[OPTDATA_LEN + 1] = {0};
            memcpy(raw_name, pdu->file_metadata.buf, OPTDATA_LEN);
            const char* filename = sanitize_filename(raw_name);

            file_transfer* existing = find_transfer(ctx, sender);
            if (existing)
            {
                fclose(existing->fp);
                existing->fp = NULL;
                existing->active = false;
            }

            file_transfer* ft = alloc_transfer(ctx);
            if (!ft)
            {
                clio_print("Too many concurrent file transfers\n");
                break;
            }

            char destname[OPTDATA_LEN + 1];
            make_unique_filename(filename, destname, sizeof(destname));

            FILE* fp = fopen(destname, "wb");
            if (!fp)
            {
                clio_print("Failed to create file: %s\n", destname);
                break;
            }

            if (payload_size > 0)
                fwrite(pdu->buf, 1, payload_size, fp);

            if (payload_size >= file_size)
            {
                fclose(fp);
                clio_print("[%s] received file %s (%" PRIu64 " bytes)\n", sender, destname, file_size);
            }
            else
            {
                ft->active = true;
                ft->fp = fp;
                ft->expected_size = file_size;
                ft->received = payload_size;
                strncpy(ft->sender, sender, UNAMESIZE);
                snprintf(ft->filename, sizeof(ft->filename), "%s", destname);
                clio_print("[%s] receiving file %s (%" PRIu64 " bytes)...\n", sender, destname, file_size);
            }
            break;
        }
        default:
            clio_print("[unknown msg_type %u]\n", pdu->msg_type);
            break;
    }
}

static int32_t clrecv_fill(client_ctx* ctx)
{
    while (ctx->recv_len < RECV_BUF_SIZE)
    {
        int64_t n = ctx->nfns.recv_fn(&ctx->connection,
            ctx->recv_buf + ctx->recv_len,
            RECV_BUF_SIZE - ctx->recv_len);
        if (n == EBLOCK) break;
        if (n <= 0)
        {
            epoll_ctl(ctx->epoll_fd, EPOLL_CTL_DEL, ctx->connection.sock_fd, NULL);
            ctx->nfns.disconnect_fn(&ctx->connection);
            ctx->state = ST_DISCONNECTED;
            ctx->connection.sock_fd = ERROR;
            ctx->recv_len = 0;
            ctx->awaiting_resp = false;
            ctx->sending_chunks = false;
            ctx->username[0] = '\0';
            ctx->server_host[0] = '\0';
            close_all_transfers(ctx);
            clio_reset_prompt();
            clio_print("Disconnected from server.\n");
            return -1;
        }
        ctx->recv_len += n;
    }
    return 0;
}

static void clrecv_parse(client_ctx* ctx)
{
    while (true)
    {
        if (ctx->recv_len < 4) break;

        uint32_t mark;
        memcpy(&mark, ctx->recv_buf, sizeof(mark));
        mark = ntohl(mark);

        if (mark == PDU_SYNC_HDR_MARK)
        {
            if (ctx->recv_len < LWMP_HDR_SIZE) break;

            lwmp_pdu* pdu = (lwmp_pdu*)ctx->recv_buf;
            uint32_t orig_crc = ntohl(pdu->crc32);
            uint32_t comp_crc = crc32(pdu, offsetof(lwmp_pdu, crc32));
            if (comp_crc != orig_crc)
            {
                ctx->recv_buf[0] = 0;
                uint64_t new_len = lwmp_stream_resync(ctx->recv_buf, ctx->recv_len);
                ctx->recv_len = (uint32_t)new_len;
                continue;
            }

            uint64_t payload_size = be64toh(pdu->total_msg_size);
            uint64_t wire_payload = payload_size;
            if (pdu->msg_type == MT_FILE && wire_payload > LWMP_PDU_BUF_SIZE)
                wire_payload = LWMP_PDU_BUF_SIZE;
            uint64_t total_needed = LWMP_HDR_SIZE + wire_payload;
            if (ctx->recv_len < total_needed) break;

            process_received_pdu(ctx, pdu, wire_payload);

            if (ctx->recv_len > total_needed)
                memmove(ctx->recv_buf, ctx->recv_buf + total_needed, ctx->recv_len - total_needed);
            ctx->recv_len -= (uint32_t)total_needed;
        }
        else if (mark == CHUNK_SYNC_HDR_MARK)
        {
            if (ctx->recv_len < LWMP_CHUNK_HDR_SIZE) break;

            lwmp_chunk* chunk = (lwmp_chunk*)ctx->recv_buf;
            uint16_t chunk_size = ntohs(chunk->chunk_size);
            uint64_t total_needed = LWMP_CHUNK_HDR_SIZE + chunk_size;
            if (ctx->recv_len < total_needed) break;

            if (chunk_size > 0)
            {
                char sender[UNAMESIZE + 1] = {0};
                memcpy(sender, chunk->subject_uname, UNAMESIZE);
                file_transfer* ft = find_transfer(ctx, sender);

                if (ft)
                {
                    fwrite(chunk->payload, 1, chunk_size, ft->fp);
                    ft->received += chunk_size;

                    if (ft->received >= ft->expected_size)
                    {
                        fclose(ft->fp);
                        ft->fp = NULL;
                        ft->active = false;
                        clio_print("[%s] received file %s (%" PRIu64 " bytes)\n",
                            ft->sender, ft->filename, ft->expected_size);
                    }
                }
            }

            if (ctx->recv_len > total_needed)
                memmove(ctx->recv_buf, ctx->recv_buf + total_needed, ctx->recv_len - total_needed);
            ctx->recv_len -= (uint32_t)total_needed;
        }
        else
        {
            uint64_t new_len = lwmp_stream_resync(ctx->recv_buf, ctx->recv_len);
            ctx->recv_len = (uint32_t)new_len;
            if (!new_len) break;
        }
    }
}

void handle_socket_data(client_ctx* ctx)
{
    if (clrecv_fill(ctx) < 0)
        return;
    clrecv_parse(ctx);
}

static int32_t wait_readable(client_ctx* ctx, int32_t timeout_ms)
{
    if (ctx->nfns.avail_data_fn(&ctx->connection) > 0)
        return 1;

    struct pollfd pfd = {.fd = ctx->connection.sock_fd, .events = POLLIN};
    while (true)
    {
        int32_t r = poll(&pfd, 1, timeout_ms);
        if (r < 0 && errno == EINTR)
            continue;
        return r;
    }
}

int32_t await_resp(client_ctx* ctx, uint32_t* out_code)
{
    ctx->awaiting_resp = true;
    clrecv_parse(ctx);

    while (ctx->awaiting_resp && ctx->state == ST_CONNECTED)
    {
        int32_t r = wait_readable(ctx, AWAIT_RESP_TIMEOUT_MS);
        if (r == 0)
        {
            ctx->awaiting_resp = false;
            return -1;
        }
        if (r < 0)
            return -2;
        if (clrecv_fill(ctx) < 0)
            return -2;
        clrecv_parse(ctx);
    }

    if (ctx->state != ST_CONNECTED)
        return -2;

    *out_code = ctx->last_resp_code;
    return 0;
}

void pump_socket_once(client_ctx* ctx)
{
    if (wait_readable(ctx, 0) <= 0)
        return;
    if (clrecv_fill(ctx) < 0)
        return;
    clrecv_parse(ctx);
}
