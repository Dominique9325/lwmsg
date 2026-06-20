//
// Created by dominik on 6/16/26.
//

#ifndef LWMSG_UTIL_H
#define LWMSG_UTIL_H
#include <stdint.h>

typedef struct buffer
{
    void* buf;
    uint32_t buf_size;
    uint32_t buf_data_offset;
}buffer;

void normalize_string(char* str);

#endif //LWMSG_UTIL_H
