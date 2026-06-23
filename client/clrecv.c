#include "clrecv.h"

#include <stdio.h>
#include <string.h>
#include <sys/epoll.h>
#include <inttypes.h>
#include <endian.h>
#include <netinet/in.h>

static void process_received_pdu(lwmp_pdu* pdu, uint64_t payload_size)
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
            printf("\r[%s]: %s\n> ", sender, pdu->buf);
            fflush(stdout);
            break;
        }
        case MT_INFO:
        {
            uint32_t resp_code = ntohl(pdu->response.resp_code);
            if (payload_size > 0 && payload_size <= LWMP_PDU_BUF_SIZE)
            {
                pdu->buf[payload_size - 1] = '\0';
                printf("\r[server] (0x%08X) %s: %s\n> ", resp_code, strresp(resp_code), pdu->buf);
            }
            else
                printf("\r[server] response: (0x%08X) %s\n> ", resp_code, strresp(resp_code));
            fflush(stdout);
            break;
        }
        case MT_REQ:
        {
            uint32_t resp_code = ntohl(pdu->response.resp_code);
            if (resp_code == RESP_OK && payload_size > 0)
            {
                printf("\rOnline users:\n");
                uint64_t offset = 0;
                while (offset < payload_size)
                {
                    char* uname = (char*)(pdu->buf + offset);
                    uint64_t len = strnlen(uname, payload_size - offset);
                    if (len > 0)
                        printf("  %s\n", uname);
                    offset += len + 1;
                }
                printf("> ");
                fflush(stdout);
            }
            else
            {
                if (payload_size > 0 && payload_size <= LWMP_PDU_BUF_SIZE)
                {
                    pdu->buf[payload_size - 1] = '\0';
                    printf("\r[server] (0x%08X): %s\n> ", resp_code, pdu->buf);
                }
                else
                    printf("\r[server] response: 0x%08X\n> ", resp_code);
                fflush(stdout);
            }
            break;
        }
        case MT_FILE:
        {
            uint64_t file_size = be64toh(pdu->total_msg_size);
            printf("\r[%s] sent file (%" PRIu64 " bytes)\n> ", sender, file_size);
            fflush(stdout);
            break;
        }
        default:
            fprintf(stderr, "\r[unknown msg_type %u]\n> ", pdu->msg_type);
            fflush(stdout);
            break;
    }
}

void handle_socket_data(client_ctx* ctx)
{
    while (ctx->recv_len < RECV_BUF_SIZE)
    {
        int64_t n = ctx->nfns.recv_fn(&ctx->connection,
            ctx->recv_buf + ctx->recv_len,
            RECV_BUF_SIZE - ctx->recv_len);
        if (n == EBLOCK) break;
        if (n <= 0)
        {
            printf("\rDisconnected from server.\n");
            epoll_ctl(ctx->epoll_fd, EPOLL_CTL_DEL, ctx->connection.sock_fd, NULL);
            ctx->nfns.disconnect_fn(&ctx->connection);
            ctx->state = ST_DISCONNECTED;
            ctx->connection.sock_fd = ERROR;
            ctx->recv_len = 0;
            printf("> ");
            fflush(stdout);
            return;
        }
        ctx->recv_len += n;
    }

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

            process_received_pdu(pdu, wire_payload);

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

            char sender[UNAMESIZE + 1] = {0};
            memcpy(sender, chunk->subject_uname, UNAMESIZE);
            printf("\r[%s] file chunk (%u bytes)\n> ", sender, chunk_size);
            fflush(stdout);

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
