//
// Created by dominik on 6/14/26.
//

#ifndef LWMSG_XALLOC_H
#define LWMSG_XALLOC_H

void* xmalloc(size_t size);

void* xrealloc(void* ptr, size_t size);

void* xcalloc(size_t nmemb, size_t size);

#endif //LWMSG_XALLOC_H
