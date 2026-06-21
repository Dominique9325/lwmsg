//
// Created by dominik on 6/20/26.
//

#ifndef LWMSG_DBOPS_H
#define LWMSG_DBOPS_H
#include <sqlite3.h>
#include <stdbool.h>
#include "lwmp.h"

#define REG_QUERY "INSERT INTO users (username, password_sha256) VALUES (:username, :password_sha256)"
#define DEL_QUERY "DELETE FROM users WHERE username = :username AND password_sha256 = :password_sha256"
#define FETCH_QUERY "SELECT password_sha256 FROM users WHERE username = :username"

bool process_reg_req(sqlite3* dbc, sqlite3_stmt* reg_stmt, auth_req_group* req);

bool validate_auth(sqlite3* dbc, sqlite3_stmt* auth_fetch_stmt, auth_req_group* req);

#endif //LWMSG_DBOPS_H
