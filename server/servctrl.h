//
// Created by gf-senka on 6/7/2026.
//

#ifndef LWMSG_SERVCTRL_H
#define LWMSG_SERVCTRL_H
#include <stdint.h>
#include <stdio.h>
#include "servcfg.h"
#include "htable.h"
#include "zlog.h"
#define MAX_TOKENS_PER_LINE 20


typedef struct ctrl_ctx
{
    striped_htable* std_cl_tbl;
    striped_htable* std_ipblock_tbl;
    striped_htable* reg_ipblock_tbl;
    striped_htable* ip_whitelist_tbl;
    zlog_category_t* zct;
    int32_t flg_reg_changed;
    int32_t flg_shutdown;
}ctrl_ctx;

FILE* open_ctrl_if();

void close_ctrl_if(FILE* cifp);

int32_t ctrl_parse_input(FILE* cifp, char line[1024], char** tokens);

bool ctrl_process_cmd(ctrl_ctx* ctrlctx, char** tokens, int32_t num_tokens);

#endif //LWMSG_SERVCTRL_H
