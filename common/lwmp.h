//
// Created by dominik on 6/12/26.
//

#ifndef LWMSG_LWMP_H
#define LWMSG_LWMP_H
#include <stdint.h>
#define UNAMESIZE 32
#define PWDSIZE 20
#define REQ_REGISTRATION 0x1FE32976U
#define REQ_DELETION 0xDE1059BCU
#define REG_RESP_OK 0x51CEF28DU
#define REG_RESP_ERR 0x128CE6DAU

typedef struct reg_req_group
{
    uint32_t req_type;
    char username[UNAMESIZE];
    char password[20];
}reg_req_group;

typedef struct reg_resp
{
    uint32_t resp_code;
}reg_resp;


#endif //LWMSG_LWMP_H
