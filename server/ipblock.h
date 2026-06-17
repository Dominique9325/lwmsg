//
// Created by dominik on 6/14/26.
//

#ifndef LWMSG_IPBLOCK_H
#define LWMSG_IPBLOCK_H
#include <netinet/in.h>
#include <stdbool.h>
#include <time.h>
#include "htable.h"

#define REGBLOCK_FAIL_THRES 5 // 5
#define REGBLOCK_SUCC_THRES 1 // 1
#define REGBLOCK_EXPIRY 7200 // 2 h

#define NOT_BLOCKED 0
#define BLOCKED 1
#define REC_EXPIRED 2

#define IPBL_TBL_SIZE_POW2 10
#define IPBL_TBL_RESIZE_POW2 1
#define IPBL_TBL_BKT_PER_LOCK_POW2 10
#define IPBL_TBL_THRES_LDFAC 100

enum record_reason
{
    RSN_MANUAL,
    RSN_REGFAIL,
    RSN_REGSUCC
};

typedef struct reg_ipb_rec
{
    node nd;
    struct timespec timestamp;
    in_addr_t ip_addr;
    uint32_t succ_regs;
    uint32_t failed_regs;
    const bool is_manual;
}reg_ipb_rec;

typedef struct whitelist_rec
{
    node nd;
    in_addr_t ip_addr;
}whitelist_rec;

uint8_t chk_reg_block(reg_ipb_rec* ripbr);

reg_ipb_rec* reg_ipb_rec_create(in_addr_t peer_name, uint8_t rec_reason);

whitelist_rec* whitelist_rec_create(in_addr_t peer_name);

int32_t ip_cmp(const void* a, const void* b, uint32_t lena, uint32_t lenb);

#endif //LWMSG_IPBLOCK_H

