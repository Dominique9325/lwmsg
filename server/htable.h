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

typedef struct node node;

typedef struct striped_htable striped_htable;

typedef void(*free_func)(node* n);

typedef int(*cmp_func)(const void* a, const void* b, uint32_t lena, uint32_t lenb);

struct node
{
    const void* key;
    const free_func free_fn;
    node* next;
    const uint32_t key_size;
    ATOMIC uint32_t ref_cnt;
};

striped_htable* htable_create(uint8_t htable_pow2_size_factor, uint8_t htable_pow2_resize_factor,
                              uint8_t thres_load_factor, uint8_t buckets_per_lock, cmp_func cmpfn);

bool htable_add(striped_htable* htable, node* element);

void htable_remove(striped_htable* htable, const void* key, uint32_t key_size);

node* htable_get(striped_htable* htable, const void* key, uint32_t len, bool ref_inc);

node* htable_get_cond(striped_htable* htable, const void* key, uint32_t len, bool(*cond_fn)(node* nd));

void node_get(node* n);

void node_put(node* n);

void htable_delete(striped_htable* htable);

uint64_t htable_get_elem_cnt(striped_htable* htable);

#endif //LWMSG_HTABLE_H
