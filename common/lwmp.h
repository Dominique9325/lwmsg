//
// Created by dominik on 6/12/26.
//

#ifndef LWMSG_LWMP_H
#define LWMSG_LWMP_H
#include <stdint.h>
#include <stddef.h>
#include <assert.h>

#define UNAMESIZE 32
#define OPTDATA_LEN 32
#define PWDSIZE 20
#define LWMP_MAX_PDU_SIZE 4096
#define PDU_SYNC_HDR_MARK 0xF7C3EDA8U
#define CHUNK_SYNC_HDR_MARK 0x4FE2CD81U
#define LWMP_HDR_SIZE 81
#define LWMP_CHUNK_HDR_SIZE 38
#define LWMP_PDU_BUF_SIZE (LWMP_MAX_PDU_SIZE - LWMP_HDR_SIZE)
#define LWMP_CHUNK_BUF_SIZE (LWMP_MAX_PDU_SIZE - LWMP_CHUNK_HDR_SIZE)
#define MAX_TEXTMSG_SIZE LWMP_PDU_BUF_SIZE
#define X_RESPONSES(X)                                         \
    X(HV_OK,               RESP_OK,              0x4F643180U)  \
    X(HV_FILE_NOT_ALLOWED, RESP_DISALLOWED_FILE, 0x7F1C825BU)  \
    X(HV_FILE_TOOBIG,      RESP_TOOBIG_FILE,     0x1C337928U)  \
    X(HV_TXTMSG_TOOBIG,    RESP_TOOBIG_MSG,      0x4829CD33U)  \
    X(HV_CRCERR,           RESP_INVAL_CRC,       0xCC32621AU)  \
    X(HV_INVAL_REQ,        RESP_INVAL_REQ,       0x3738AA64U)  \
    X(HV_INVAL_PDU,        RESP_INVAL_PDU,       0x337C801AU)  \
    X(HV_INVAL_SUBJ,       RESP_DCONN_SUBJ,      0x772A5C19U)

enum hdr_validation_status
{
#define X_HDR_VALIDATION(enumname, respname, respval) enumname,
    X_RESPONSES(X_HDR_VALIDATION)
#undef X_HDR_VALIDATION
};

enum resp_code
{
#define X_RESP_CODES(enumname, respname, respval) respname = respval,
    X_RESPONSES(X_RESP_CODES)
#undef X_RESP_CODES
};


enum msg_type
{
    MT_NONE,
    MT_MSG,
    MT_FILE,
    MT_REQ,
    MT_INFO
};

enum auth_req_type
{
    REQ_REGISTRATION = 0x1FE32976U,
    REQ_DELETION =  0xDE1059BCU,
    REQ_AUTHENTICATION = 0xF68C104AU
};

enum std_req_type
{
    REQ_USER_LIST
};

enum auth_req_resp_code
{
    AUTH_RESP_OK = 0x51CEF28DU,
    AUTH_RESP_INVAL_REQ = 0x23A80DBFU,
    AUTH_RESP_INVAL_PARAM = 0x128CE6DAU,
    AUTH_RESP_TIMEOUT = 0x7F0CDE45U,
    AUTH_RESP_DUPLICATE = 0x1F7CE628U
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
    FLG_REQ_INVAL = 1 << 0U,
    FLG_
};

extern const uint32_t resp_codes[];
extern const uint64_t lwmp_hdr_size;
extern const uint64_t lwmp_init_payload_size;

typedef struct lwmp_pdu lwmp_pdu;

typedef struct hdr_validation_fns
{
    bool(*subj_valid_fn)(void* subj_container, char* subj);
    bool(*req_valid_fn)(lwmp_pdu* pdu);
}hdr_validation_fns;

typedef struct req_opt_data
{
    uint32_t req_type;
}req_opt_data;

typedef struct file_opt_data
{
    char buf[OPTDATA_LEN];
}file_opt_data;

typedef struct serv_resp_opt_data
{
    uint32_t resp_code;
}serv_resp_opt_data;


// Note: When not in use, optional data shall be zeroed.
typedef struct __attribute__((packed)) lwmp_pdu
{
    uint32_t hdr_mark;
    uint8_t msg_type;
    char subject_uname[UNAMESIZE];
    union
    {
        file_opt_data file_metadata;
        serv_resp_opt_data response;
        req_opt_data request;
        char optional_data[OPTDATA_LEN];
    };
    uint64_t total_msg_size;
    uint32_t crc32;
    unsigned char buf[LWMP_PDU_BUF_SIZE];
}lwmp_pdu;

static_assert(offsetof(lwmp_pdu, buf) == LWMP_HDR_SIZE, "Incorrect lwmp PDU header size");

typedef struct __attribute__((packed)) lwmp_chunk
{
    uint32_t ch_hdr_mark;
    uint16_t chunk_size;
    char subject_uname[UNAMESIZE];
    unsigned char payload[LWMP_MAX_PDU_SIZE];
}lwmp_chunk;

static_assert(offsetof(lwmp_chunk, payload) == LWMP_CHUNK_HDR_SIZE, "Incorrect lwmp chunk header size");




uint32_t crc32(const void* data, uint64_t len);

uint64_t lwmp_stream_resync(unsigned char* buf, uint64_t buf_size);

uint8_t lwmp_validate_hdrs(lwmp_pdu* pdu, void* subj_container, char* subject, const hdr_validation_fns* hvfns);

void lwmp_prepare_response(lwmp_pdu* pdu, uint8_t msg_type, void* optdata, uint8_t optdata_len, char* text);

void lwmp_prepare_chunk(lwmp_chunk* lwc, uint16_t size, char* subject, void* data);

#endif //LWMSG_LWMP_H
