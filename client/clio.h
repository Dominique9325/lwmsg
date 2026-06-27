#ifndef LWMSG_CLIO_H
#define LWMSG_CLIO_H

#include "client.h"

void clio_init(client_ctx* ctx);

void clio_shutdown(void);

void clio_on_stdin(void);

void clio_set_prompt(const char* prompt);

void clio_reset_prompt(void);

void clio_print(const char* fmt, ...);

#endif
