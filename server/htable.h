//
// Created by dominik on 6/8/26.
//

#ifndef LWMSG_HTABLE_H
#define LWMSG_HTABLE_H
#include <stdint.h>
#include <pthread.h>
#include <stdatomic.h>
#include "misc.h"

#define node_container_of(parent_type, member_name, member_ptr) \
    (parent_type *)((char *)(member_ptr) - offsetof(parent_type, member_name))

typedef struct node
{
    char* key;
    struct node* next;
    uint32_t key_size;
}node;

typedef int(*cmp_func)(const char* a, const char* b);

typedef struct striped_htable
{
    node** buckets;
    const cmp_func cmpfn;
    uint64_t bucket_count;
    ATOMIC uint64_t element_count;
    ATOMIC uint64_t resize_thres_elem_count;
    pthread_rwlock_t g_resize_lock;
    pthread_rwlock_t* locks;
    ATOMIC uint64_t lock_count;
    const uint8_t buckets_per_lock_pow2;
    const uint8_t threshold_load_factor;
    const uint8_t htable_pow2_expansion_factor;
}striped_htable;


uint32_t fnv1a_32_hash(const unsigned char* input, uint32_t size);

striped_htable* htable_create(uint16_t pow2_size_factor, uint8_t thres_load_factor, uint8_t buckets_per_lock, cmp_func cmpfn);

bool htable_add(striped_htable* htable, node* element);

#endif //LWMSG_HTABLE_H
