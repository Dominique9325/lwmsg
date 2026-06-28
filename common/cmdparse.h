#ifndef LWMSG_CMDPARSE_H
#define LWMSG_CMDPARSE_H

#include <stdint.h>

#define CMDPARSE_MAX_TOKENS 32

int32_t cmdparse_tokenize(char* line, char** tokens, int32_t max_tokens);

char* cmdparse_rest_after_tokens(char* line, int32_t skip);

#endif
