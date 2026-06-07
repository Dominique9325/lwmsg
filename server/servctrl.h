//
// Created by gf-senka on 6/7/2026.
//

#ifndef LWMSG_SERVCTRL_H
#define LWMSG_SERVCTRL_H
#include <stdint.h>

void ctrl_parse_line(int32_t sockfd, char* buf, uint32_t bufsize);

#endif //LWMSG_SERVCTRL_H
