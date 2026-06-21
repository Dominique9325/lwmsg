//
// Created by dominik on 6/12/26.
//

#ifndef LWMSG_LWMP_H
#define LWMSG_LWMP_H
#include <stdint.h>
#define UNAMESIZE 32
#define PWDSIZE 20

enum req_type
{
    REQ_REGISTRATION = 0x1FE32976U,
    REQ_DELETION =  0xDE1059BCU,
    REQ_AUTHENTICATION = 0xF68C104AU
};

enum auth_req_resp_code
{
    AUTH_RESP_OK = 0x51CEF28DU,
    AUTH_RESP_INVAL_REQ = 0x23A80DBFU,
    AUTH_RESP_INVAL_PARAM = 0x128CE6DAU,
    AUTH_RESP_TIMEOUT = 0x7F0CDE45U
};

typedef struct auth_req_group
{
    uint32_t request_type;
    char username[UNAMESIZE];
    char password[PWDSIZE];
}auth_req_group;

typedef struct auth_resp
{
    uint32_t resp_code;
}auth_resp;


#endif //LWMSG_LWMP_H
