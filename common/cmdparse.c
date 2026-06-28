#include "cmdparse.h"

int32_t cmdparse_tokenize(char* line, char** tokens, int32_t max_tokens)
{
    int32_t n = 0;
    char* p = line;
    while (*p && n < max_tokens)
    {
        while (*p == ' ' || *p == '\t') p++;
        if (!*p) break;

        if (*p == '"')
        {
            p++;
            tokens[n++] = p;
            while (*p && *p != '"') p++;
            if (*p == '"') *p++ = '\0';
        }
        else
        {
            tokens[n++] = p;
            while (*p && *p != ' ' && *p != '\t') p++;
            if (*p) *p++ = '\0';
        }
    }
    return n;
}

char* cmdparse_rest_after_tokens(char* line, int32_t skip)
{
    char* p = line;
    for (int32_t i = 0; i < skip; i++)
    {
        while (*p == ' ' || *p == '\t') p++;
        if (!*p) return p;
        if (*p == '"')
        {
            p++;
            while (*p && *p != '"') p++;
            if (*p == '"') p++;
        }
        else
        {
            while (*p && *p != ' ' && *p != '\t') p++;
        }
    }
    while (*p == ' ' || *p == '\t') p++;
    return p;
}
