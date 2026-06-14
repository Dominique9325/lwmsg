//
// Created by dominik on 6/14/26.
//

#include <stdlib.h>
#include "zlog.h"
#include "xalloc.h"
#define ERRMSG "Allocation failed, out of memory. Requested size: %lu"

void* xmalloc(size_t size)
{
    void* tp = malloc(size);
    if (!tp)
    {
        dzlog_fatal(ERRMSG, size);
        abort();
    }
    return tp;
}

void* xrealloc(void* ptr, size_t size)
{
    void* tp = realloc(ptr, size);
    if (!tp)
    {
        dzlog_fatal(ERRMSG, size);
        free(ptr);
        abort();
    }
    return tp;
}

void* xcalloc(size_t nmemb, size_t size)
{
    void* tp = calloc(nmemb, size);
    if (!tp)
    {
        dzlog_fatal(ERRMSG, nmemb * size);
        abort();
    }
    return tp;
}