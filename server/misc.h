//
// Created by dominik on 6/9/26.
//

#ifndef LWMSG_MISC_H
#define LWMSG_MISC_H

// Because clangd is being an absolute pain, this is just for labeling. Will use compiler builtins instead of C11 atomics.
#define ATOMIC

#define STR(X) #X
#define IP4DOT(ipv4_be) ipv4_be & 0xFF, ipv4_be >> 8 & 0xFF, ipv4_be >> 16 & 0xFF, ipv4_be >> 24 & 0xFF

#endif //LWMSG_MISC_H
