//
// Created by dominik on 6/20/26.
//

#include <assert.h>
#include <openssl/sha.h>
#include <openssl/crypto.h>
#include <string.h>
#include "util.h"
#include "zlog.h"
#include "dbops.h"

#include "servcfg.h"


bool process_reg_req(sqlite3* dbc, sqlite3_stmt* stmt, auth_req_group* req)
{
    assert(dbc && stmt && req);

    sqlite3_reset(stmt);
    int32_t i = sqlite3_bind_parameter_index(stmt, ":username");
    int32_t j = sqlite3_bind_parameter_index(stmt, ":password_sha256");
    if (!i || !j)
    {
        dzlog_error("Improperly prepared SQL statement. Cause: %s", sqlite3_errmsg(dbc));
        return false;
    }

    req->username[UNAMESIZE - 1] = '\0';
    req->password[PWDSIZE - 1] = '\0';
    normalize_string(req->username);
    unsigned char password_hash[SHA256_DIGEST_LENGTH];
    SHA256((const unsigned char*)req->password, strlen(req->password), password_hash);
    sqlite3_bind_text(stmt, i, req->username, -1, SQLITE_STATIC);
    sqlite3_bind_blob(stmt, j, password_hash, SHA256_DIGEST_LENGTH, SQLITE_STATIC);
    int32_t res = sqlite3_step(stmt);

    if (res != SQLITE_DONE)
    {
        dzlog_notice("Failed to execute query. Cause: %s", sqlite3_errmsg(dbc));
        return false;
    }
    else if (!sqlite3_changes(dbc))
    {
        dzlog_notice("Failed to delete account. Invalid username or password.");
        return false;
    }
    dzlog_info("Successfully %s user %s", req->request_type == REQ_DELETION ? "deleted" : "created", req->username);
    return true;
}

bool validate_auth(sqlite3* dbc, sqlite3_stmt* auth_fetch_stmt, auth_req_group* req)
{
    assert(dbc && auth_fetch_stmt && req);
    if (!g_server_cfg->use_auth)
        return true;

    sqlite3_reset(auth_fetch_stmt);
    int32_t i = sqlite3_bind_parameter_index(auth_fetch_stmt, ":username");
    if (!i)
    {
        dzlog_error("Improperly prepared SQL statement. Cause: %s", sqlite3_errmsg(dbc));
        return false;
    }

    req->username[UNAMESIZE - 1] = '\0';
    req->password[PWDSIZE - 1] = '\0';
    normalize_string(req->username);
    sqlite3_bind_text(auth_fetch_stmt, i, req->username, -1, SQLITE_STATIC);
    int32_t res = sqlite3_step(auth_fetch_stmt);
    if (res != SQLITE_DONE)
    {
        dzlog_error("Failed to execute query. Reason: %s", sqlite3_errmsg(dbc));
        return false;
    }

    const unsigned char* dbpw_sha256 =  sqlite3_column_blob(auth_fetch_stmt, 0);
    unsigned char reqpw_sha256[SHA256_DIGEST_LENGTH];
    SHA256((const unsigned char*)req->password, strlen(req->password), reqpw_sha256);
    int32_t pwcmp_res = CRYPTO_memcmp(dbpw_sha256, reqpw_sha256, SHA256_DIGEST_LENGTH);
    if (pwcmp_res)
    {
        dzlog_info("Failed authentication attempt for user %s.", req->username);
        return false;
    }

    return true;
}