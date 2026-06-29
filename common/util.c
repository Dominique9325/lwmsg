//
// Created by dominik on 6/16/26.
//
#include <string.h>
#include "util.h"

#include <ctype.h>

void normalize_string(char* str)
{
    for (uint32_t i = 0; i < strlen(str); i++)
        str[i] = (char)tolower((unsigned char)str[i]);
}
