#ifndef LWMSG_CLCMD_H
#define LWMSG_CLCMD_H

#include "client.h"

#define MAX_TOKENS 32

int32_t tokenize(char* line, char** tokens, int32_t max_tokens);

char* rest_after_tokens(char* line, int32_t skip);

void handle_command_line(client_ctx* ctx, char* line);

#endif
