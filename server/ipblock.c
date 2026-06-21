//
// Created by dominik on 6/14/26.
//
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include "ipblock.h"

#include "cltimerheap.h"
#include "xalloc.h"

static void ripbr_free(node* nd)
{
    reg_ipb_rec* rec = node_container_of(reg_ipb_rec, nd, nd);
    free(rec);
}

uint8_t chk_reg_block(reg_ipb_rec* ripbr)
{
    if (ripbr->is_manual)
        return BLOCKED;

    struct timespec curr_timestamp;
    clock_gettime(CLOCK_MONOTONIC, &curr_timestamp);

    if (curr_timestamp.tv_sec - ripbr->timestamp.tv_sec >= REGBLOCK_EXPIRY)
        return REC_EXPIRED;
    else if (ripbr->failed_regs >= REGBLOCK_FAIL_THRES || ripbr->succ_regs >= REGBLOCK_SUCC_THRES)
        return BLOCKED;

    return NOT_BLOCKED;
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
    std_ipb_rec* rec = node_container_of(std_ipb_rec, nd, node);
    free(rec);
}

uint8_t chk_std_block(std_ipb_rec* stdipbr)
{
    if (stdipbr->is_manual)
        return BLOCKED;

    struct timespec curr_timestamp;
    clock_gettime(CLOCK_MONOTONIC, &curr_timestamp);

    if (curr_timestamp.tv_sec - stdipbr->timestamp.tv_sec >= AUTHBLOCK_EXPIRY)
        return REC_EXPIRED;
    else if (stdipbr->failed_auths >= AUTHBLOCK_FAIL_THRES)
        return BLOCKED;

    return NOT_BLOCKED;
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
    whitelist_rec* rec = node_container_of(whitelist_rec, nd, node);
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