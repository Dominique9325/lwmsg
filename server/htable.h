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
    const void* key;
    struct node* next;
    uint32_t key_size;
    ATOMIC uint32_t ref_cnt;
}node;

typedef int(*cmp_func)(const void* a, const void* b, uint32_t lena, uint32_t lenb);

typedef struct striped_htable
{
    node** buckets;
    const cmp_func cmpfn;
    uint64_t bucket_count;
    ATOMIC uint64_t element_count;
    ATOMIC uint64_t resize_thres_elem_count;
    pthread_rwlock_t g_resize_lock;
    pthread_rwlock_t* locks;
    uint64_t lock_count; // doesn't need to be atomic.
    const uint8_t buckets_per_lock_pow2;
    const uint8_t threshold_load_factor;
    const uint8_t htable_pow2_resize_factor;
}striped_htable;

striped_htable* htable_create(uint8_t htable_pow2_size_factor, uint8_t htable_pow2_resize_factor,
                              uint8_t thres_load_factor, uint8_t buckets_per_lock, cmp_func cmpfn);

bool htable_add(striped_htable* htable, node* element);

void htable_remove(striped_htable*, node* element);

node* htable_get(striped_htable* htable, const void* key, uint32_t len);

#endif //LWMSG_HTABLE_H
