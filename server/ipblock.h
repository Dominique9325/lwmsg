//
// Created by dominik on 6/14/26.
//

#ifndef LWMSG_IPBLOCK_H
#define LWMSG_IPBLOCK_H
#include <netinet/in.h>
#include <stdbool.h>
#include <time.h>
#include "htable.h"

#define REGBLOCK_FAIL_THRES 500000 // 5
#define REGBLOCK_SUCC_THRES 100000 // 1
#define AUTHBLOCK_FAIL_THRES 500000 // 5

#define REGBLOCK_EXPIRY 7200 // 2 h
#define AUTHBLOCK_EXPIRY 3600 // 1 h

#define IPBL_TBL_SIZE_POW2 10
#define IPBL_TBL_RESIZE_POW2 1
#define IPBL_TBL_BKT_PER_LOCK_POW2 10
#define IPBL_TBL_THRES_LDFAC 100

enum record_status
{
    RS_NOT_BLOCKED,
    RS_BLOCKED,
    RS_EXPIRED
};

enum record_reason
{
    RSN_MANUAL,
    RSN_REGFAIL,
    RSN_REGSUCC
};

typedef struct generic_ip_rec
{
    in_addr_t ip_addr;
    node nd;
}generic_ip_rec;

typedef struct reg_ipb_rec
{
    in_addr_t ip_addr;
    node nd;
    struct timespec timestamp;
    uint32_t succ_regs;
    uint32_t failed_regs;
    const bool is_manual;
}reg_ipb_rec;

typedef struct std_ipb_rec
{
    in_addr_t ip_addr;
    node nd;
    struct timespec timestamp;
    ATOMIC uint32_t failed_auths;
    const bool is_manual;
}std_ipb_rec;

typedef struct whitelist_rec
{
    in_addr_t ip_addr;
    node nd;
}whitelist_rec;

uint8_t chk_reg_block(reg_ipb_rec* ripbr);

uint8_t chk_std_block(std_ipb_rec* stdipbr);

reg_ipb_rec* reg_ipb_rec_create(in_addr_t peer_name, uint8_t rec_reason);

whitelist_rec* whitelist_rec_create(in_addr_t peer_name);

std_ipb_rec* std_ipb_rec_create(in_addr_t peer_name, bool is_manual);

int32_t ip_cmp(const void* a, const void* b, uint32_t lena, uint32_t lenb);

int32_t node_copy_peername(node* nd, void* buf, uint64_t buf_size);

#endif //LWMSG_IPBLOCK_H

