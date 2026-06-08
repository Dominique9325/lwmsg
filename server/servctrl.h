//
// Created by gf-senka on 6/7/2026.
//

#ifndef LWMSG_SERVCTRL_H
#define LWMSG_SERVCTRL_H
#include <stdint.h>
#define HDR_MARK 0x18C04DF2U
#define VARARG (-1)

typedef struct command
{
    uint8_t cmd_code;
    char cmd_name[32];
    int8_t cmd_argc;
    uint8_t local;
}command;

extern command commands[];
extern uint8_t command_count;
extern char cmd_manuals[][256];

typedef struct serv_cmd
{
    uint8_t cmd_code;
}serv_cmd;

int32_t ctrl_read_cmd(int32_t sockfd, void* buf, int32_t bufsize);

#endif //LWMSG_SERVCTRL_H
