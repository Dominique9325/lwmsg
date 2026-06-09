//
// Created by dominik on 6/8/26.
//


#include <stdlib.h>
#include <math.h>
#include <string.h>
#include <stdbool.h>
//#include <stddef.h>
#include "htable.h"

// #ifdef __clang__
// #undef atomic_load
// #define atomic_load(object) __c11_atomic_load(object, __ATOMIC_SEQ_CST)
// #endif

#define FNV1A_32_PRIME 0x01000193U
#define FNV1A_32_OFFSET_BASIS 0x811C9DC5

uint32_t fnv1a_32_hash(const unsigned char* input, uint32_t size)
{
    uint32_t hash = FNV1A_32_OFFSET_BASIS;
    for (uint32_t i = 0; i < size; i++)
    {
        hash ^= input[i];
        hash *= FNV1A_32_PRIME;
    }
    return hash;
}

striped_htable* htable_create(uint16_t pow2_size_factor, uint8_t thres_load_factor,
                              uint8_t buckets_per_lock_pow2, cmp_func cmpfn
                              )
{
    if (thres_load_factor < 1 || pow2_size_factor < 1)
        return NULL;

    uint64_t bucket_count = 1ULL << pow2_size_factor;
    uint64_t lock_count = bucket_count >> buckets_per_lock_pow2;
    lock_count = lock_count ? lock_count : 1;
    striped_htable* htable = NULL;

    striped_htable tmp_htable = {
                                 .bucket_count = bucket_count,
                                 .threshold_load_factor = thres_load_factor,
                                 .buckets_per_lock_pow2 = buckets_per_lock_pow2,
                                 .resize_thres_elem_count = bucket_count * thres_load_factor / 100,
                                 .htable_pow2_expansion_factor = pow2_size_factor,
                                 .buckets = (node**)malloc(bucket_count * sizeof(node*)),
                                 .lock_count = lock_count,
                                 .locks = (pthread_rwlock_t*)malloc(lock_count * sizeof(pthread_rwlock_t)),
                                 .element_count = 0,
                                 .cmpfn = cmpfn
                                };

    uint32_t i = 0;
    bool g_lock = false;

    if (!tmp_htable.buckets || !tmp_htable.locks)
        goto fail;

    g_lock = pthread_rwlock_init(&htable->g_resize_lock, NULL) ? false : true;
    if (!g_lock)
        goto fail;

    htable = (striped_htable*)malloc(sizeof(striped_htable));
    if (!htable)
        goto fail;

    memcpy(htable, &tmp_htable, sizeof(striped_htable));
    memset(htable->buckets, 0, bucket_count * sizeof(void*));

    for (; i < lock_count; i++)
    {
        if (pthread_rwlock_init(&htable->locks[i], NULL))
            goto fail;
    }

    return htable;

    fail:
    for (uint32_t j = 0; j < i; j++)
        pthread_rwlock_destroy(&htable->locks[j]);
    if (g_lock) pthread_rwlock_destroy(&htable->g_resize_lock);
    if (tmp_htable.buckets) free(tmp_htable.buckets);
    if (tmp_htable.locks) free(tmp_htable.locks);
    if (htable) free(htable);
    return NULL;
}

static void htable_resize(striped_htable* htable)
{
    uint64_t old_bucket_count = htable->bucket_count;
    htable->bucket_count <<= htable->htable_pow2_expansion_factor;
    
    node** temp = realloc(htable->buckets, htable->bucket_count);
    if (!temp)
        return;
    htable->buckets = temp;
    memset(&htable->buckets[old_bucket_count], 0, (htable->bucket_count - old_bucket_count) * sizeof(node*));


    node* current = NULL;

    for (uint64_t src_bucket_index = 0; src_bucket_index < old_bucket_count; src_bucket_index++)
    {
        node** src_bucket = &htable->buckets[src_bucket_index];
        current = *src_bucket;

        while (current != NULL)
        {
            uint64_t dest_bucket_index = fnv1a_32_hash((unsigned char*)current->key, current->key_size) & (htable->bucket_count - 1);
            if (src_bucket_index == dest_bucket_index)
                continue;

            node** dest_bucket = &htable->buckets[dest_bucket_index];
            
            if (!(*dest_bucket))
            {
                *dest_bucket = current;
                *src_bucket = current->next;
                current->next = NULL;
                break;
            }

            do
            {

            }while (*dest_bucket);


        }

    }
}

bool htable_add(striped_htable* htable, node* element)
{
    if (!htable || !htable->buckets || !element)
        return false;


    if (__atomic_load_n(&htable->element_count, memory_order_seq_cst) >=
        __atomic_load_n(&htable->resize_thres_elem_count, memory_order_seq_cst))
    {
        if (!pthread_rwlock_trywrlock(&htable->g_resize_lock))
        {
            htable_resize(htable);
            pthread_rwlock_unlock(&htable->g_resize_lock);
        }
    }

    if (pthread_rwlock_rdlock(&htable->g_resize_lock))
        return false;

    cmp_func cmpfn = htable->cmpfn;
    uint64_t bucket_index = fnv1a_32_hash((const unsigned char*)element->key, element->key_size) & (htable->bucket_count - 1);
    uint64_t lock_index = bucket_index >> htable->buckets_per_lock_pow2;

    if (pthread_rwlock_wrlock(&htable->locks[lock_index]))
        return false;

    if (!htable->buckets[bucket_index])
    {
        __atomic_fetch_add(&htable->element_count, 1, memory_order_seq_cst);
        htable->buckets[bucket_index] = element;
        pthread_rwlock_unlock(&htable->locks[lock_index]);
        return true;
    }

    node* prev = NULL;
    node* comparator = htable->buckets[bucket_index];
    bool result = false;

    do
    {
        int32_t comp_res = comparator ? cmpfn(element->key, comparator->key) : -1;
        if (!comp_res)
            break;
        else if (comp_res < 0)
        {
            if (!prev)
            {
                __atomic_fetch_add(&htable->element_count, 1, memory_order_seq_cst);
                element->next = comparator;
                htable->buckets[bucket_index] = element;
                result = true;
                break;
            }

            __atomic_fetch_add(&htable->element_count, 1, memory_order_seq_cst);
            element->next = comparator;
            prev->next = element;
            result = true;
            break;
        }

        prev = comparator;
        comparator = comparator->next;

    } while(comparator);

    pthread_rwlock_unlock(&htable->locks[lock_index]);
    pthread_rwlock_unlock(&htable->g_resize_lock);
    return result;
}
