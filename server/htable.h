//
// Created by dominik on 6/8/26.
//

#ifndef LWMSG_HTABLE_H
#define LWMSG_HTABLE_H
#include <stdint.h>
#include <stdbool.h>
#include <pthread.h>
#include <stdatomic.h>
#include "../common/misc.h"
#define BUF_TOOSMALL (-1)
#define KEY_SKIP (-2)

#define container_of(parent_type, member_name, member_ptr) \
    (parent_type *)((char *)(member_ptr) - offsetof(parent_type, member_name))

typedef struct node dummy_node;

typedef struct node node;

typedef struct striped_htable striped_htable;

typedef void(*free_func)(node* n);

typedef int(*cmp_func)(const void* a, const void* b, uint32_t lena, uint32_t lenb);

struct node
{
    void* key;
    free_func free_fn;
    node* next;
    uint32_t key_size;
    ATOMIC uint32_t ref_cnt;
};

typedef struct node_arr
{
    node** nodes;
    uint32_t size;
    uint32_t elem_cnt;
}node_arr;

striped_htable* htable_create(uint8_t htable_pow2_size_factor, uint8_t htable_pow2_resize_factor,
                              uint8_t thres_load_factor, uint8_t buckets_per_lock, cmp_func cmpfn);

bool htable_add(striped_htable* htable, node* element);

void htable_remove(striped_htable* htable, const void* key, uint32_t key_size);

node* htable_get(striped_htable* htable, const void* key, uint32_t len, bool ref_inc);

node* htable_get_cond(striped_htable* htable, const void* key, uint32_t len, bool(*cond_fn)(node* nd));

uint64_t htable_copy_all_keys(striped_htable* htable, void** pkeybuf, int32_t(*copy_fn)(node* nd, void* buf, uint64_t bufsize));

void node_get(node* n);

void node_put(node* n);

void htable_delete(striped_htable* htable);

uint64_t htable_get_elem_cnt(striped_htable* htable);

dummy_node* intrusive_list_create();

void intrusive_list_add(dummy_node* list, node* cl);

void intrusive_list_remove(dummy_node* list, node* cl);

void node_arr_add(node_arr* ndarr, node* nd);

void node_arr_sweep(striped_htable* cltable, node_arr* ndarr);

#endif //LWMSG_HTABLE_H
