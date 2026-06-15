//
// Created by dominik on 6/14/26.
//

#ifndef LWMSG_IPBLOCK_H
#define LWMSG_IPBLOCK_H
#include <netinet/in.h>
#include <stdbool.h>
#include <time.h>
#include "htable.h"

#define REGBLOCK_FAIL_THRES 5
#define REGBLOCK_SUCC_THRES 1
#define REGBLOCK_EXPIRY 7200 // 2 h

#define NOT_BLOCKED 0
#define BLOCKED 1
#define REC_EXPIRED 2

typedef struct reg_ipb_rec
{
    node nd;
    struct timespec timestamp;
    in_addr_t ip_addr;
    uint8_t succ_regs;
    uint8_t failed_regs;
    const bool is_manual;
}reg_ipb_rec;

uint8_t chk_reg_block(reg_ipb_rec* ripbr);

#endif //LWMSG_IPBLOCK_H

