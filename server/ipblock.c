//
// Created by dominik on 6/14/26.
//
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include "ipblock.h"

#include <errno.h>
#include <arpa/inet.h>

#include "cltimerheap.h"
#include "xalloc.h"
#include "zlog.h"

static void ripbr_free(node* nd)
{
    reg_ipb_rec* rec = container_of(reg_ipb_rec, nd, nd);
    free(rec);
}

uint8_t chk_reg_block(reg_ipb_rec* ripbr)
{
    if (ripbr->is_manual)
        return RS_BLOCKED;

    struct timespec curr_timestamp;
    clock_gettime(CLOCK_MONOTONIC, &curr_timestamp);

    if (curr_timestamp.tv_sec - ripbr->timestamp.tv_sec >= REGBLOCK_EXPIRY)
        return RS_EXPIRED;
    else if (ripbr->failed_regs >= REGBLOCK_FAIL_THRES || ripbr->succ_regs >= REGBLOCK_SUCC_THRES)
        return RS_BLOCKED;

    return RS_NOT_BLOCKED;
}

int32_t ip_cmp(const void* a, const void* b, uint32_t lena, uint32_t lenb)
{
    in_addr_t ip_a = *(in_addr_t*)a;
    in_addr_t ip_b = *(in_addr_t*)b;

    for (uint32_t i = 0; i < lena; i++)
    {
        unsigned char a_byte = ip_a >> (8 * i) & 0xFF;
        unsigned char b_byte = ip_b >> (8 * i) & 0xFF;
        int32_t cmpres = a_byte - b_byte;
        if (cmpres)
            return cmpres;
    }

    return 0;
}

reg_ipb_rec* reg_ipb_rec_create(in_addr_t peer_name, uint8_t rec_reason)
{
    reg_ipb_rec temp = {
        .failed_regs = rec_reason == RSN_REGFAIL ? 1 : 0,
        .succ_regs = rec_reason == RSN_REGSUCC ? 1 : 0,
        .is_manual = rec_reason == RSN_MANUAL ? 1 : 0,
        .ip_addr = peer_name,
        .nd.ref_cnt = 1,
        .nd.next = NULL,
        .nd.free_fn = ripbr_free,
        .nd.key_size = sizeof(peer_name)
    };

    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    ts.tv_sec += REGBLOCK_EXPIRY;
    temp.timestamp = ts;

    reg_ipb_rec* rec = (reg_ipb_rec*)xmalloc(sizeof(reg_ipb_rec));
    memcpy(rec, &temp, sizeof(reg_ipb_rec));
    rec->nd.key = &rec->ip_addr;
    return rec;
}

static void std_ipb_rec_free(node* node)
{
    std_ipb_rec* rec = container_of(std_ipb_rec, nd, node);
    free(rec);
}

uint8_t chk_std_block(std_ipb_rec* stdipbr)
{
    if (stdipbr->is_manual)
        return RS_BLOCKED;

    struct timespec curr_timestamp;
    clock_gettime(CLOCK_MONOTONIC, &curr_timestamp);

    if (curr_timestamp.tv_sec - stdipbr->timestamp.tv_sec >= AUTHBLOCK_EXPIRY)
        return RS_EXPIRED;
    else if (stdipbr->failed_auths >= AUTHBLOCK_FAIL_THRES)
        return RS_BLOCKED;

    return RS_NOT_BLOCKED;
}

std_ipb_rec* std_ipb_rec_create(in_addr_t peer_name, bool is_manual)
{
    std_ipb_rec temp = {
        .failed_auths = is_manual ? 0 : 1,
        .ip_addr = peer_name,
        .nd = {.next = NULL, .ref_cnt = 1, .free_fn = std_ipb_rec_free, .key_size = sizeof(peer_name)},
        .is_manual = is_manual
    };
    std_ipb_rec* rec = xmalloc(sizeof(std_ipb_rec));
    memcpy(rec, &temp, sizeof(std_ipb_rec));
    clock_gettime(CLOCK_MONOTONIC, &rec->timestamp);
    rec->timestamp.tv_sec += AUTHBLOCK_EXPIRY;
    rec->nd.key = &rec->ip_addr;
    return rec;
}

static void whitelist_rec_free(node* node)
{
    whitelist_rec* rec = container_of(whitelist_rec, nd, node);
    free(rec);
}

whitelist_rec* whitelist_rec_create(in_addr_t peer_name)
{
    whitelist_rec temp = {
        .nd.free_fn = whitelist_rec_free,
        .nd.ref_cnt = 1,
        .nd.next = NULL,
        .nd.key_size = sizeof(peer_name),
        .ip_addr = peer_name
    };

    whitelist_rec* rec = (whitelist_rec*)xmalloc(sizeof(whitelist_rec));
    memcpy(rec, &temp, sizeof(whitelist_rec));
    rec->nd.key = &rec->ip_addr;
    return rec;
}

int32_t node_copy_peername(node* nd, void* buf, uint64_t buf_size)
{
    generic_ip_rec* rec = container_of(generic_ip_rec, nd, nd);
    struct in_addr ina = {.s_addr = rec->ip_addr};
    socklen_t slen = (socklen_t)buf_size;
    const char* res = inet_ntop(AF_INET, &ina, buf, slen);
    if (!res)
    {
        int32_t err = errno;
        if (err == ENOSPC)
            return BUF_TOOSMALL;

        char errbuf[256];
        strerror_r(err, errbuf, 256);
        dzlog_error("Error copying peer name. Cause: %s", errbuf);
        return KEY_SKIP;
    }

    int32_t peername_len = (int32_t)strlen(res) + 1;
    return peername_len;
}