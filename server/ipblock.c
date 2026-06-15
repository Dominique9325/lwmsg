//
// Created by dominik on 6/14/26.
//

#include "ipblock.h"

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