//
// Created by dominik on 4/23/26.
//

#ifndef LWMSG_SERVCFG_H
#define LWMSG_SERVCFG_H
#include <stdbool.h>
#include <stdint.h>
#include <stdatomic.h>
#include <stdio.h>
#include "misc.h"


#define CFG_MAX_STRLEN 32
#define MIN_NONPRIV_PORT 1024
#define DEFAULT_CERT_CHAIN_PATH "cert_chain.pem"
#define DEFAULT_PRIVATE_KEY_PATH "private_key.pem"
#define DEFAULT_DB_FILE_PATH "database.db"
#define DEFAULT_IP_WHITELIST_PATH "ip_whitelist.json"
#define DEFAULT_IP_BLACKLIST_PATH "ip_blacklist.json"

typedef char path[CFG_MAX_STRLEN];

#define CFG_INT_FIELDS(X) \
X(ATOMIC uint64_t,         max_filesize_b,                  200,              UINT64_MAX,  1U << 22) \
X(uint8_t,                 nr_worker_threads,               1,                128,         4       ) \
X(uint8_t,                 cl_htable_size_pow2,             1,                21,          12      ) \
X(uint8_t,                 cl_htable_expansion_pow2,        1,                12,          8       ) \
X(uint8_t,                 cl_htable_loadfactor_exp_thres,  1,                UINT8_MAX,   70      ) \
X(uint8_t,                 cl_htable_locks_pow2,            1,                32,          16      ) \
X(ATOMIC uint16_t,         pop_cap,                         0,                UINT16_MAX,  20      ) \
X(uint16_t,                reg_port,                        6500,             7000,        6671    ) \
X(uint16_t,                gen_port,                        7001,             UINT16_MAX,  7228    ) \
X(uint16_t,                ctrl_port,                       MIN_NONPRIV_PORT, UINT16_MAX,  6777    ) \
X(uint8_t,                 autoconf_nr_threads,             false,            true,        false   ) \
X(uint8_t,                 use_tls,                         false,            true,        true    ) \
X(uint8_t,                 use_auth,                        false,            true,        true    ) \
X(ATOMIC uint8_t,          allow_regisrations,              false,            true,        true    ) \
X(ATOMIC uint8_t,          allow_file_transfers,            false,            true,        true    ) \
X(ATOMIC uint8_t,          use_ip_whitelist,                false,            true,        false   )
// type                       var name                    min value        max value     default value

#define CFG_STR_FIELDS(X) \
X(path, cert_chain_path,  0, CFG_MAX_STRLEN, DEFAULT_CERT_CHAIN_PATH   ) \
X(path, private_key_path, 0, CFG_MAX_STRLEN, DEFAULT_PRIVATE_KEY_PATH  ) \
X(path, db_file_path,     0, CFG_MAX_STRLEN, DEFAULT_DB_FILE_PATH      ) \
X(path, ip_whitelist_path,0, CFG_MAX_STRLEN, DEFAULT_IP_WHITELIST_PATH ) \
X(path, ip_blacklist_path,0, CFG_MAX_STRLEN, DEFAULT_IP_BLACKLIST_PATH ) \

#define CFG_FIELDS(X) CFG_INT_FIELDS(X) CFG_STR_FIELDS(X) \

typedef struct serv_cfg
{
#define X_FIELDS(mtype, mname, mmin, mmax, mdef) mtype mname;
    CFG_FIELDS(X_FIELDS)
#undef X_FIELDS
    char padding[4];
}serv_cfg;

extern serv_cfg* g_server_cfg;

void load_cfg(const char* cfg_file);

void save_cfg(const char* cfg_file);



#endif //LWMSG_SERVCFG_H
