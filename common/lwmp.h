//
// Created by dominik on 6/12/26.
//

#ifndef LWMSG_LWMP_H
#define LWMSG_LWMP_H
#include <stdint.h>
#include <stddef.h>

#define UNAMESIZE 32
#define PWDSIZE 20
#define MAX_RECV_PDU_SIZE 4096

enum msg_type
{
    MT_NONE,
    MT_MSG,
    MT_FILE,
    MT_REQ,
    MT_INFO
};

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

enum lwmp_flags
{
    FLG_SERVER = 1 << 0U,
    FLG_NO_PAYLOAD = 1 << 1U,
};


typedef struct __attribute__((packed)) lwmp_base
{
    uint8_t msg_type;
    uint8_t flags;

}lwmp_base;

typedef struct __attribute__((packed)) lwmp_server_msg
{
    uint32_t payload_size;
    void* payload;
}lwmp_server_msg;

typedef struct __attribute__((packed)) lwmp_pdu
{
    uint64_t msg_id;
    uint8_t msg_type;
    uint8_t flags;
    char subject_uname[UNAMESIZE];
    uint64_t total_msg_size;
    uint16_t payload_size;

}lwmp_pdu;

typedef struct lwmp_chunk
{
    uint64_t msg_id;
    uint16_t payload_size;
    void* payload;
}lwmp_chunk;

#endif //LWMSG_LWMP_H
