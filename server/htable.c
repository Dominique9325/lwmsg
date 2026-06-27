//
// Created by dominik on 6/8/26.
//


#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <assert.h>
#include "htable.h"
#include "zlog.h"
#include "clhandle.h"
#include "xalloc.h"

#define FNV1A_32_PRIME 0x01000193U
#define FNV1A_32_OFFSET_BASIS 0x811C9DC5
#define C_THRES_ELEM(thres_factor, bucket_count) ((bucket_count) * (thres_factor) / 100)


struct striped_htable
{
    node **buckets;
    const cmp_func cmpfn;
    uint64_t bucket_count;
    ATOMIC uint64_t element_count;
    ATOMIC uint64_t resize_thres_elem_count;
    pthread_rwlock_t g_resize_lock;
    pthread_rwlock_t *locks;
    uint64_t lock_count; // doesn't need to be atomic.
    const uint8_t buckets_per_lock_pow2;
    const uint8_t threshold_load_factor;
    const uint8_t htable_pow2_resize_factor;
};

static uint32_t fnv1a_32_hash(const unsigned char *input, uint32_t size)
{
    assert(input && size);
    uint32_t hash = FNV1A_32_OFFSET_BASIS;
    for (uint32_t i = 0; i < size; i++)
    {
        hash ^= input[i];
        hash *= FNV1A_32_PRIME;
    }
    return hash;
}


striped_htable *htable_create(uint8_t htable_pow2_size_factor, uint8_t htable_pow2_resize_factor,
                              uint8_t thres_load_factor,
                              uint8_t buckets_per_lock_pow2, cmp_func cmpfn
)
{
    assert(thres_load_factor && buckets_per_lock_pow2 <= htable_pow2_size_factor && htable_pow2_resize_factor &&
        htable_pow2_resize_factor < 64 && htable_pow2_size_factor < 64 && cmpfn);

#ifdef NDEBUG
    if (!thres_load_factor || buckets_per_lock_pow2 > htable_pow2_size_factor ||
        !htable_pow2_resize_factor || htable_pow2_resize_factor >= 64 || htable_pow2_size_factor >= 64 || !cmpfn)
        return NULL;
#endif

    uint64_t bucket_count = 1ULL << htable_pow2_size_factor;
    uint64_t lock_count = bucket_count >> buckets_per_lock_pow2;
    lock_count = lock_count ? lock_count : 1;
    striped_htable *htable = NULL;

    striped_htable tmp_htable = {
        .bucket_count = bucket_count,
        .threshold_load_factor = thres_load_factor,
        .buckets_per_lock_pow2 = buckets_per_lock_pow2,
        .resize_thres_elem_count = C_THRES_ELEM(thres_load_factor, bucket_count),
        .htable_pow2_resize_factor = htable_pow2_resize_factor,
        .buckets = (node **) malloc(bucket_count * sizeof(node *)),
        .lock_count = lock_count,
        .locks = (pthread_rwlock_t *) malloc(lock_count * sizeof(pthread_rwlock_t)),
        .element_count = 0,
        .cmpfn = cmpfn
    };

    uint32_t i = 0;
    bool g_lock = false;

    if (!tmp_htable.buckets || !tmp_htable.locks)
        goto fail;

    htable = (striped_htable *) malloc(sizeof(striped_htable));
    if (!htable)
        goto fail;

    memcpy(htable, &tmp_htable, sizeof(striped_htable));
    memset(htable->buckets, 0, bucket_count * sizeof(void *));

    g_lock = pthread_rwlock_init(&htable->g_resize_lock, NULL) ? false : true;
    if (!g_lock)
        goto fail;

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


static void htable_resize(striped_htable *htable)
{
    assert(htable && htable->buckets && htable->locks);

    uint64_t old_bucket_count = htable->bucket_count;
    uint8_t resize_count = 0;

    /*To prevent there being a necessity for an immediate resize again,
     *and to prevent another thread from resizing right after the previous one did.*/
    while (__atomic_load_n(&htable->element_count, __ATOMIC_SEQ_CST) >=
           __atomic_load_n(&htable->resize_thres_elem_count, __ATOMIC_SEQ_CST))
    {
        htable->bucket_count <<= htable->htable_pow2_resize_factor;
        if (htable->bucket_count < old_bucket_count)
        {
            htable->bucket_count = old_bucket_count;
            return; // Overflow.
        }

        __atomic_store_n(
            &htable->resize_thres_elem_count,
            C_THRES_ELEM(htable->threshold_load_factor, htable->bucket_count), __ATOMIC_SEQ_CST
        );
        resize_count++;
    }

    // If the size hasn't changed, there is no need to proceed.
    if (!resize_count)
        return;

    cmp_func cmpfn = htable->cmpfn;

    node **temp = realloc(htable->buckets, htable->bucket_count * sizeof(node *));
    if (!temp)
        goto bucket_resize_fail;

    uint64_t old_lock_count = htable->lock_count;
    htable->lock_count = htable->bucket_count >> htable->buckets_per_lock_pow2;
    htable->buckets = temp;

    pthread_rwlock_t *lock_temp = realloc(htable->locks, htable->lock_count * sizeof(pthread_rwlock_t));
    if (!lock_temp)
        goto lock_resize_fail;

    htable->locks = lock_temp;
    uint64_t i;
    for (i = old_lock_count; i < htable->lock_count; i++)
    {
        if (pthread_rwlock_init(&htable->locks[i], NULL))
            goto lock_init_fail;
    }


    memset(&htable->buckets[old_bucket_count], 0, (htable->bucket_count - old_bucket_count) * sizeof(node *));


    for (uint64_t src_bucket_index = 0; src_bucket_index < old_bucket_count; src_bucket_index++)
    {
        node **src_bucket = &htable->buckets[src_bucket_index];
        node *src = *src_bucket;
        node *src_prev = NULL;

        while (src != NULL)
        {
            node *curr_el = src;
            uint64_t dest_bucket_index = fnv1a_32_hash((unsigned char *) src->key, src->key_size) & (
                                             htable->bucket_count - 1);
            if (src_bucket_index == dest_bucket_index)
            {
                src_prev = src;
                src = src->next;
                continue;
            }

            node **dest_bucket = &htable->buckets[dest_bucket_index];
            node *dest = *dest_bucket;
            node *dest_prev = NULL;

            if (!(*dest_bucket))
            {
                *dest_bucket = curr_el;

                if (!src_prev)
                    *src_bucket = src->next;
                else
                    src_prev->next = src->next;

                src = src->next;
                curr_el->next = NULL;
                continue;
            }

            node *src_next = src->next;

            while (dest)
            {
                /*They can never be equal because we're simply re-inserting the same set of nodes, duplicates can
                 * never be present in the hashtable.
                 */
                int32_t cmp_res = cmpfn(src->key, dest->key, src->key_size, dest->key_size);
                if (cmp_res < 0 || !dest->next)
                {
                    if (!src_prev)
                        *src_bucket = src->next;
                    else
                        src_prev->next = src->next;

                    if (cmp_res < 0)
                    {
                        curr_el->next = dest;

                        if (!dest_prev)
                            *dest_bucket = curr_el;
                        else
                            dest_prev->next = curr_el;
                    }
                    else
                    {
                        dest->next = curr_el;
                        curr_el->next = NULL;
                    }

                    break;
                }

                dest_prev = dest;
                dest = dest->next;
            }

            src = src_next;
        }
    }

    return;

lock_init_fail:
    for (uint64_t j = old_lock_count; j < i; j++)
        pthread_rwlock_destroy(&htable->locks[j]);

    lock_temp = realloc(htable->locks, old_lock_count * sizeof(pthread_rwlock_t));
    if (!lock_temp)
        abort(); // This condition should never be met, if it does then the program simply cannot continue on.

    htable->locks = lock_temp;

lock_resize_fail:
    htable->lock_count = old_lock_count;
    temp = realloc(htable->buckets, old_bucket_count * sizeof(node *));
    if (!temp)
        return;
    htable->buckets = temp;

bucket_resize_fail:
    htable->bucket_count = old_bucket_count;
    __atomic_store_n(&htable->resize_thres_elem_count,
                     C_THRES_ELEM(htable->threshold_load_factor, htable->bucket_count), __ATOMIC_SEQ_CST);
}


bool htable_add(striped_htable *htable, node *element)
{
    assert(htable && htable->buckets && htable->locks && element);

#ifdef NDEBUG
    if (!htable || !htable->buckets || !htable->locks || !element)
        return false;
#endif

    if (__atomic_load_n(&htable->element_count, __ATOMIC_SEQ_CST) >=
        __atomic_load_n(&htable->resize_thres_elem_count, __ATOMIC_SEQ_CST))
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
    uint64_t bucket_index = fnv1a_32_hash((const unsigned char *) element->key, element->key_size) & (
                                htable->bucket_count - 1);
    uint64_t lock_index = bucket_index >> htable->buckets_per_lock_pow2;

    if (pthread_rwlock_wrlock(&htable->locks[lock_index]))
    {
        pthread_rwlock_unlock(&htable->g_resize_lock);
        return false;
    }

    element->next = NULL;

    if (!htable->buckets[bucket_index])
    {
        __atomic_fetch_add(&htable->element_count, 1, __ATOMIC_SEQ_CST);
        htable->buckets[bucket_index] = element;
        pthread_rwlock_unlock(&htable->locks[lock_index]);
        pthread_rwlock_unlock(&htable->g_resize_lock);
        return true;
    }

    node *prev = NULL;
    node *comparator = htable->buckets[bucket_index];
    int32_t comp_res;
    bool result = false;

    do
    {
        comp_res = cmpfn(element->key, comparator->key, element->key_size, comparator->key_size);
        if (!comp_res)
            break;
        else if (comp_res < 0)
        {
            if (!prev)
            {
                __atomic_fetch_add(&htable->element_count, 1, __ATOMIC_SEQ_CST);
                element->next = comparator;
                htable->buckets[bucket_index] = element;
                result = true;
                break;
            }

            __atomic_fetch_add(&htable->element_count, 1, __ATOMIC_SEQ_CST);
            element->next = comparator;
            prev->next = element;
            result = true;
            break;
        }

        prev = comparator;
        comparator = comparator->next;
    } while (comparator);

    if (!result && comp_res)
    {
        __atomic_fetch_add(&htable->element_count, 1, __ATOMIC_SEQ_CST);
        prev->next = element;
        element->next = NULL;
        result = true;
    }

    pthread_rwlock_unlock(&htable->locks[lock_index]);
    pthread_rwlock_unlock(&htable->g_resize_lock);
    return result;
}


void htable_remove(striped_htable *htable, const void *key, uint32_t key_size)
{
    assert(htable && htable->buckets && htable->locks && key && key_size);

    if (pthread_rwlock_rdlock(&htable->g_resize_lock))
        return;

    uint64_t index = fnv1a_32_hash((const unsigned char *) key, key_size) & (htable->bucket_count - 1);
    uint64_t lock_index = index >> htable->buckets_per_lock_pow2;

    if (pthread_rwlock_wrlock(&htable->locks[lock_index]))
    {
        pthread_rwlock_unlock(&htable->g_resize_lock);
        return;
    }

    node **bucket = &htable->buckets[index];
    node *current = *bucket;
    node *prev = NULL;
    cmp_func cmpfn = htable->cmpfn;
    int32_t cmp_res = 1;

    while (current)
    {
        if (!((cmp_res = cmpfn(key, current->key, key_size, current->key_size))))
            break;
        prev = current;
        current = current->next;
    }

    if (!current && cmp_res)
        goto exit;
    else if (!prev)
    {
        *bucket = current->next; // NOLINT
        current->next = NULL;
    }
    else
    {
        prev->next = current->next; // NOLINT
        current->next = NULL;
    }

    node_put(current);
    __atomic_sub_fetch(&htable->element_count, 1, __ATOMIC_SEQ_CST);
exit:
    pthread_rwlock_unlock(&htable->locks[lock_index]);
    pthread_rwlock_unlock(&htable->g_resize_lock);
}


node *htable_get(striped_htable *htable, const void *key, uint32_t len, bool ref_inc)
{
    assert(htable && htable->buckets && htable->locks && key && len);

#ifdef NDEBUG
    if (!htable || !htable->buckets || !htable->locks || !key || !len)
        return NULL;
#endif

    if (pthread_rwlock_rdlock(&htable->g_resize_lock))
        return NULL;

    uint64_t index = fnv1a_32_hash((const unsigned char *) key, len) & (htable->bucket_count - 1);
    uint64_t lock_index = index >> htable->buckets_per_lock_pow2;
    node *seeker = htable->buckets[index];
    node *target = NULL;
    cmp_func cmpfn = htable->cmpfn;
    int32_t cmp_res = 1;

    if (pthread_rwlock_rdlock(&htable->locks[lock_index]))
    {
        pthread_rwlock_unlock(&htable->g_resize_lock);
        return NULL;
    }

    while (seeker)
    {
        if (!((cmp_res = cmpfn(key, seeker->key, len, seeker->key_size))))
            break;

        seeker = seeker->next;
    }

    if (!cmp_res)
    {
        target = seeker;
        if (ref_inc)
            node_get(target);
    }

    pthread_rwlock_unlock(&htable->locks[lock_index]);
    pthread_rwlock_unlock(&htable->g_resize_lock);
    return target;
}

node* htable_get_cond(striped_htable* htable, const void* key, uint32_t len, bool(*cond_fn)(node* nd))
{
    if (!key || ((char*)key)[0] == '\0')
        return NULL;

    node* nd = htable_get(htable, key, len, true);
    if (!nd)
        return NULL;

    if (cond_fn(nd))
        return nd;

    node_put(nd);
    return NULL;
}

uint64_t htable_copy_all_keys(striped_htable* htable, void** pkeybuf, int32_t(*copy_fn)(node* nd, void* buf, uint64_t bufsize))
{
    pthread_rwlock_rdlock(&htable->g_resize_lock);
    if (!htable->bucket_count || !__atomic_load_n(&htable->element_count, __ATOMIC_SEQ_CST))
    {
        pthread_rwlock_unlock(&htable->g_resize_lock);
        return 0;
    }

    uint64_t buf_offset = 0;
    uint64_t buf_size = 1024;
    void* buf = xmalloc(buf_size);

    for (uint64_t i = 0; i < htable->lock_count; i++)
    {
        pthread_rwlock_rdlock(&htable->locks[i]);
        for (uint64_t j = i << htable->buckets_per_lock_pow2; j < ((i + 1) << htable->buckets_per_lock_pow2); j++)
        {
            node* iterator_node = htable->buckets[j];
            while (iterator_node)
            {
                int32_t data_copied = copy_fn(iterator_node, buf + buf_offset, buf_size - buf_offset);
                while (data_copied == BUF_TOOSMALL)
                {
                    buf_size <<= 1;
                    void* temp = xrealloc(buf, buf_size);
                    buf = temp;
                    data_copied = copy_fn(iterator_node, buf + buf_offset, buf_size - buf_offset);
                }
                if (data_copied != KEY_SKIP)
                    buf_offset += data_copied;

                iterator_node = iterator_node->next;
            }
        }
        pthread_rwlock_unlock(&htable->locks[i]);
    }
    pthread_rwlock_unlock(&htable->g_resize_lock);

    if (!buf_offset)
    {
        free(buf);
        buf = NULL;
    }

    *pkeybuf = buf;
    return buf_offset;
}

void node_get(node *n)
{
    __atomic_add_fetch(&n->ref_cnt, 1, __ATOMIC_SEQ_CST);
}


void node_put(node *n)
{
    uint32_t refcnt = __atomic_sub_fetch(&n->ref_cnt, 1, __ATOMIC_SEQ_CST);
    if (!refcnt)
        n->free_fn(n);
}


void htable_delete(striped_htable *htable)
{
    assert(htable);

#ifdef NDEBUG
    if (!htable)
        return;
#endif

    for (uint64_t i = 0; i < htable->bucket_count; i++)
    {
        node *nd = htable->buckets[i];
        while (nd)
        {
            node* temp = nd;
            nd = nd->next;
            temp->free_fn(temp);
        }
    }

    pthread_rwlock_destroy(&htable->g_resize_lock);

    for (uint64_t i = 0; i < htable->lock_count; i++)
        pthread_rwlock_destroy(&htable->locks[i]);

    free(htable->locks);
    htable->locks = NULL;

    free(htable->buckets);
    htable->buckets = NULL;

    free(htable);
}

uint64_t htable_get_elem_cnt(striped_htable* htable)
{
    return __atomic_load_n(&htable->element_count, __ATOMIC_SEQ_CST);
}

dummy_node* intrusive_list_create()
{
    dummy_node* list = (dummy_node*)xcalloc(1, sizeof(dummy_node));
    return list;
}

void intrusive_list_add(dummy_node* list, node* nd)
{
    nd->next = NULL;


    if (!list->next)
    {
        list->next = nd;
        return;
    }

    nd->next = list->next;
    list->next = nd;
}

void intrusive_list_remove(dummy_node* list, node* nd)
{
    if (!list->next || !nd)
        return;

    node* curr = list->next;
    node* prev = NULL;

    while (curr && nd != curr)
    {
        prev = curr;
        curr = curr->next;
    }

    if (!curr)
        return;

    if (!prev)
        list->next = nd->next;
    else
        prev->next = nd->next;

    nd->next = NULL;
}

void node_arr_add(node_arr* ndarr, node* nd)
{
    if (ndarr->elem_cnt == ndarr->size)
    {
        node** temp = xrealloc(ndarr->nodes, 2 * ndarr->size * sizeof(node*));
        ndarr->nodes = temp;
        ndarr->size *= 2;
    }

    ndarr->nodes[ndarr->elem_cnt++] = nd;
}

void node_arr_sweep(striped_htable* cltable, node_arr* ndarr)
{
    uint32_t i;
    for (i = 0; i < ndarr->elem_cnt; i++)
        htable_remove(cltable, ndarr->nodes[i]->key, ndarr->nodes[i]->key_size);


    if (i)
        dzlog_debug("Cleaned up %u clients in sweep.", i);
    node** temp = xrealloc(ndarr->nodes, DEF_STDCL_DCONARR_SIZE * sizeof(node*));
    ndarr->nodes = temp;
    ndarr->size = DEF_STDCL_DCONARR_SIZE;
    ndarr->elem_cnt = 0;
}