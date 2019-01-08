/*
 * Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"). You may not use
 * this file except in compliance with the License. A copy of the License is
 * located at
 *
 *     http://aws.amazon.com/apache2.0/
 *
 * or in the "license" file accompanying this file. This file is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
 * implied. See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <aws/cryptosdk/cache.h>
#include <aws/cryptosdk/cipher.h>
#include <aws/cryptosdk/enc_ctx.h>
#include <aws/cryptosdk/list_utils.h>
#include <aws/cryptosdk/private/cipher.h>
#include <aws/cryptosdk/private/enc_ctx.h>

#include <aws/common/array_list.h>
#include <aws/common/linked_list.h>
#include <aws/common/mutex.h>
#include <aws/common/priority_queue.h>

#define CACHE_ID_MD_ALG AWS_CRYPTOSDK_MD_SHA512
#define TTL_EXPIRATION_BATCH_SIZE 8
#define NO_EXPIRY UINT64_MAX

/*
 * An entry in the local cache. This is what the aws_cryptosdk_mat_cache_entry pointers actually
 * point to.
 */
struct local_cache_entry {
    /*
     * The local_cache_entry is kept allocated until refcount hits zero.
     * To keep it alive while it's referenced in the cache hash table, we consider
     * the hashtable itself to have a reference, and so refcount >= 1 when zombie == false.
     */
    struct aws_atomic_var refcount;

    /* The owning cache */
    struct aws_cryptosdk_local_cache *owner;

    /*
     * The cache ID for this entry. Owned by the entry itself, and freed when the entry
     * becomes a zombie.
     */
    struct aws_byte_buf cache_id;

    /*
     * expiry_time is NO_EXPIRY if no TTL has been configured
     */
    uint64_t expiry_time, creation_time;

    struct aws_cryptosdk_encryption_materials *enc_materials;
    struct aws_cryptosdk_decryption_materials *dec_materials;

    /* Initialized for encrypt-mode entries only */
    struct aws_hash_table enc_ctx;

    /*
     * we extract the public or private key out of the enc/dec materials and store it
     * separately, in order to initialize the signing context later on
     */
    struct aws_string *key_materials;

    struct aws_atomic_var usage_messages, usage_bytes;

    /*
     * Cache entries are organized into a binary heap sorted by (expiration timestamp, thisptr)
     *
     * Note: If expiry_time = NO_EXPIRY, then this entry is not part of the heap.
     */
    struct aws_priority_queue_node heap_node;

    /* For LRU purposes, we also include an intrusive circular doubly-linked-list */
    struct aws_linked_list_node lru_node;

    /*
     * After an entry is invalidated, it's possible that one or more references to it
     * remain via entry pointers returned to callers. In this case, we set the zombie
     * flag.
     *
     * When the zombie flag is set:
     *   * The dec/enc_materials structures are cleaned up
     *   * enc_ctx is cleaned up
     *   * The entry is not in the TTL heap (expiry_time = NO_EXPIRY)
     *   * lru_node is not in the LRU list
     */
    bool zombie;
};

struct aws_cryptosdk_local_cache {
    struct aws_cryptosdk_mat_cache base;

    /*
     * This mutex protects most cache operations.
     * In particular, manipulating entries, ttl_heap, or the LRU list requires that
     * this mutex be held.
     */
    struct aws_mutex mutex;

    struct aws_allocator *allocator;

    size_t capacity;

    /* aws_string (hash of request) -> local_cache_entry */
    struct aws_hash_table entries;

    /* Priority queue used to track TTL hints */
    struct aws_priority_queue ttl_heap;

    /*
     * the root of a _circular_ doubly linked list. lru_head->next is the MOST recently used;
     * lru_head->prev is the LEAST recently used.
     */
    struct aws_linked_list_node lru_head;

    /*
     * Time source - overridable in tests
     */
    int (*clock_get_ticks)(uint64_t *timestamp);
};

/********** General helpers **********/

/* Hash and compare functions that operate on struct aws_byte_buf * */
AWS_CRYPTOSDK_TEST_STATIC uint64_t hash_cache_id(const void *vp_buf);
static bool eq_cache_id(const void *vp_a, const void *vp_b);
/* Heap comparator that acts on struct local_cache_entry * */
static inline int ttl_heap_cmp(const void *vpa, const void *vpb);

/*
 * Note: locked_* functions must be invoked while holding a lock on the cache mutex.
 * It follows that these locked_* functions must not reacquire the mutex, as aws-c-common
 * mutexes are not reentrant.
 */
static void locked_invalidate_entry(
    struct aws_cryptosdk_local_cache *cache, struct local_cache_entry *entry, bool skip_hash);
static inline void locked_lru_move_to_head(struct aws_linked_list_node *head, struct aws_linked_list_node *entry);
static int locked_process_ttls(struct aws_cryptosdk_local_cache *cache);
static bool locked_find_entry(
    struct aws_cryptosdk_local_cache *cache, struct local_cache_entry **entry, const struct aws_byte_buf *cache_id);
static int locked_insert_entry(struct aws_cryptosdk_local_cache *cache, struct local_cache_entry *entry);
static void locked_release_entry(
    struct aws_cryptosdk_local_cache *cache, struct local_cache_entry *entry, bool invalidate);

static struct local_cache_entry *new_entry(
    struct aws_cryptosdk_local_cache *cache, const struct aws_byte_buf *cache_id);
static void destroy_cache_entry(struct local_cache_entry *entry);
static void destroy_cache_entry_vp(void *vp_entry);
static int copy_encryption_materials(
    struct aws_allocator *alloc,
    struct aws_cryptosdk_encryption_materials *out,
    const struct aws_cryptosdk_encryption_materials *in);

AWS_CRYPTOSDK_TEST_STATIC uint64_t hash_cache_id(const void *vp_buf) {
    const struct aws_byte_buf *buf = vp_buf;

    /*
     * Our cache IDs are already (large) hashes, so we can just take a subset of the hash
     * as our cache ID. We make sure that if the hash is smaller than 64 bits, we align
     * it to the low-order bits of the value, as the hash table itself will further truncate
     * down and we don't want all the entropy of the cache ID to be discarded by this masking
     * step.
     * TODO: Should we re-hash to deal with CMMs which don't pre-hash?
     */
    uint64_t hash_code = 0;
    size_t copylen     = buf->len > sizeof(hash_code) ? sizeof(hash_code) : buf->len;
    memcpy((char *)&hash_code + sizeof(hash_code) - copylen, buf->buffer, copylen);

    /* We placed the hash code at the big-endian LSBs, so convert to host endian now */
    hash_code = aws_ntoh64(hash_code);

    return hash_code;
}

static bool eq_cache_id(const void *vp_a, const void *vp_b) {
    const struct aws_byte_buf *a = vp_a;
    const struct aws_byte_buf *b = vp_b;

    return aws_byte_buf_eq(a, b);
}

static inline int ttl_heap_cmp(const void *vpa, const void *vpb) {
    const struct local_cache_entry *const *pa = vpa;
    const struct local_cache_entry *const *pb = vpb;

    const struct local_cache_entry *a = *pa;
    const struct local_cache_entry *b = *pb;

    if (a == b) {
        return 0;
    } else if (a->expiry_time < b->expiry_time) {
        return -1;
    } else if (a->expiry_time > b->expiry_time) {
        return 1;
    } else if (a < b) {
        return -1;
    } else {
        return 1;
    }
}

/**
 * Remove (invalidate) an entry from the cache, if it is not already invalidated.
 * The cache mutex must be held.
 *
 * This may result in entry being deallocated, if the cache's reference is the only one remaining.
 * This function is idempotent, provided that the entry was not actually deallocated.
 *
 * This is distinct from locked_clean_entry in that it also removes the references from the
 * hash table and LRU.
 *
 * If skip_hash is true, this function will not actually remove the entry from the hashtable;
 * this is useful when the hashtable is being iterated, or otherwise when the entry will be
 * cleared by some other means.
 *
 * Note that the entry may be destroyed upon return, and the cache_id certainly will be
 * freed upon return. As such, if skip_hash is true, the caller must arrange to remove
 * the hash table's reference to the key without performing a lookup.
 */
static void locked_invalidate_entry(
    struct aws_cryptosdk_local_cache *cache, struct local_cache_entry *entry, bool skip_hash) {
    assert(entry->owner == cache);

    if (entry->zombie) {
        return;
    }

    if (entry->expiry_time != NO_EXPIRY) {
        void *ignored;
        aws_priority_queue_remove(&cache->ttl_heap, &ignored, &entry->heap_node);
    }

    if (!skip_hash) {
        struct aws_hash_element element;
        /*
         * Note: Because we accept the old value into element, destroy_cache_entry_vp
         * is not called.
         */
        aws_hash_table_remove(&cache->entries, &entry->cache_id, &element, NULL);
        assert(element.value == entry);
    }

    aws_linked_list_remove(&entry->lru_node);
    entry->lru_node.next = entry->lru_node.prev = &entry->lru_node;
    entry->zombie                               = true;

    /* Release the reference count owned by the cache itself */
    locked_release_entry(entry->owner, entry, false);
}

static inline void locked_lru_move_to_head(struct aws_linked_list_node *head, struct aws_linked_list_node *entry) {
    aws_linked_list_remove(entry);
    aws_linked_list_insert_after(head, entry);
}

static int locked_process_ttls(struct aws_cryptosdk_local_cache *cache) {
    size_t max_items_to_expire = TTL_EXPIRATION_BATCH_SIZE;

    void *vp_item;
    struct local_cache_entry *entry;
    uint64_t now;

    if (cache->clock_get_ticks(&now)) {
        return AWS_OP_ERR;
    }

    while (max_items_to_expire-- && aws_priority_queue_size(&cache->ttl_heap) &&
           !aws_priority_queue_top(&cache->ttl_heap, &vp_item) &&
           (entry = *(struct local_cache_entry **)vp_item)->expiry_time <= now) {
        locked_invalidate_entry(cache, entry, false);
    }

    return AWS_OP_SUCCESS;
}

static bool locked_find_entry(
    struct aws_cryptosdk_local_cache *cache, struct local_cache_entry **entry, const struct aws_byte_buf *cache_id) {
    struct aws_hash_element *element;

    locked_process_ttls(cache);

    if (aws_hash_table_find(&cache->entries, cache_id, &element) || !element) {
        return false;
    }

    *entry = element->value;

    locked_lru_move_to_head(&cache->lru_head, &(*entry)->lru_node);

    return true;
}

static int locked_insert_entry(struct aws_cryptosdk_local_cache *cache, struct local_cache_entry *entry) {
    int was_created = 0;
    struct aws_hash_element *element;

    locked_process_ttls(cache);

    if (aws_hash_table_create(&cache->entries, &entry->cache_id, &element, &was_created)) {
        return AWS_OP_ERR;
    }

    if (!was_created) {
        /* Invalidate the old entry first. skip_hash = true as we'll remove it by replacing the hash value directly */
        locked_invalidate_entry(cache, element->value, true);
    }

    /* Update the key pointer in case we're overwriting an existing entry */
    element->key   = &entry->cache_id;
    element->value = entry;

    aws_linked_list_insert_after(&cache->lru_head, &entry->lru_node);

    while (aws_hash_table_get_entry_count(&cache->entries) > cache->capacity) {
        assert(cache->lru_head.prev != &cache->lru_head);
        assert(cache->lru_head.prev != &entry->lru_node);

        locked_invalidate_entry(
            cache, AWS_CONTAINER_OF(cache->lru_head.prev, struct local_cache_entry, lru_node), false);
    }

    return AWS_OP_SUCCESS;
}

static void locked_release_entry(
    struct aws_cryptosdk_local_cache *cache, struct local_cache_entry *entry, bool invalidate) {
    /*
     * We must use release memory order here, to guard against a race condition. Consider the following
     * program order:
     *
     * Thread A:
     *   get_encryption_materials
     *   locked_release_entry(invalidate=true)
     *
     * Thread B:
     *   release_entry
     *
     * If we use relaxed memory order, we could end up with the following execution order:
     *
     * Thread A:
     *   locked_release_entry (old_count = 2)
     * Thread B:
     *   release_entry (old_count = 1)
     *     -> destroy_cache_entry
     * Thread A:
     *   get_encryption_materials
     *     (accesses uninitialized memory)
     *
     * To prevent this race, we use release memory order; this prevents any memory accesses performed
     * before this atomic operation from being reordered to happen later, resolving this race.
     */
    size_t old_count = aws_atomic_fetch_sub_explicit(&entry->refcount, 1, aws_memory_order_release);
    assert(old_count != 0);

    if (old_count == 1) {
        assert(entry->zombie);

        destroy_cache_entry(entry);

        return;
    }

    if (invalidate && !entry->zombie) {
        /* We should have had least two references: The caller's reference, and the cache's reference */
        assert(old_count >= 2);

        /*
         * This will recurse back into locked_release_entry to remove the cache's reference
         * (and potentially free the entry)
         */
        locked_invalidate_entry(cache, entry, false);
    }
}

static struct local_cache_entry *new_entry(
    struct aws_cryptosdk_local_cache *cache, const struct aws_byte_buf *cache_id) {
    uint64_t now;

    if (cache->clock_get_ticks(&now)) {
        return NULL;
    }

    struct local_cache_entry *entry = aws_mem_acquire(cache->allocator, sizeof(*entry));

    if (!entry) {
        return NULL;
    }

    memset(entry, 0, sizeof(*entry));

    if (aws_byte_buf_init_copy(&entry->cache_id, cache->allocator, cache_id)) {
        aws_mem_release(cache->allocator, entry);
        return NULL;
    }

    aws_atomic_init_int(&entry->refcount, 1);
    entry->owner = cache;

    entry->creation_time = now;
    entry->expiry_time   = NO_EXPIRY;

    entry->lru_node.next = entry->lru_node.prev = &entry->lru_node;

    return entry;
}

/**
 * Called when the last reference to an entry is released;
 * frees all memory associated with the entry.
 */
static void destroy_cache_entry(struct local_cache_entry *entry) {
    aws_cryptosdk_encryption_materials_destroy(entry->enc_materials);
    aws_cryptosdk_decryption_materials_destroy(entry->dec_materials);

    entry->enc_materials = NULL;
    entry->dec_materials = NULL;

    aws_string_destroy_secure(entry->key_materials);
    aws_cryptosdk_enc_ctx_clean_up(&entry->enc_ctx);

    aws_byte_buf_clean_up(&entry->cache_id);

    aws_mem_release(entry->owner->allocator, entry);
}

static void destroy_cache_entry_vp(void *vp_entry) {
    /*
     * We enter this function already holding the cache mutex; because aws-common mutexes are non-reentrant,
     * and because we're actively manipulating the hash table, we can't safely re-use the release_entry invalidation
     * logic.
     *
     * Instead, we'll just set expiry_time to NO_EXPIRY (the priority queue has already been destroyed) and free
     * the entry immediately.
     */
    struct local_cache_entry *entry = vp_entry;

    destroy_cache_entry(entry);
}

static int copy_encryption_materials(
    struct aws_allocator *alloc,
    struct aws_cryptosdk_encryption_materials *out,
    const struct aws_cryptosdk_encryption_materials *in) {
    if (aws_byte_buf_init_copy(&out->unencrypted_data_key, alloc, &in->unencrypted_data_key) ||
        aws_cryptosdk_edk_list_copy_all(alloc, &out->encrypted_data_keys, &in->encrypted_data_keys) ||
        aws_cryptosdk_keyring_trace_copy_all(alloc, &out->keyring_trace, &in->keyring_trace)) {
        return AWS_OP_ERR;
    }

    /* We do not clone the signing context itself, but instead we save the public or private keys elsewhere */
    out->signctx = NULL;
    out->alg     = in->alg;

    return AWS_OP_SUCCESS;
}

static int copy_decryption_materials(
    struct aws_allocator *alloc,
    struct aws_cryptosdk_decryption_materials *out,
    const struct aws_cryptosdk_decryption_materials *in) {
    if (aws_byte_buf_init_copy(&out->unencrypted_data_key, alloc, &in->unencrypted_data_key) ||
        aws_cryptosdk_keyring_trace_copy_all(alloc, &out->keyring_trace, &in->keyring_trace)) {
        return AWS_OP_ERR;
    }

    /* We do not clone the signing context itself, but instead we save the public or private keys elsewhere */
    out->signctx = NULL;
    out->alg     = in->alg;

    return AWS_OP_SUCCESS;
}

/********** Local cache vtable methods **********/

static void destroy_cache(struct aws_cryptosdk_mat_cache *generic_cache) {
    struct aws_cryptosdk_local_cache *cache = (struct aws_cryptosdk_local_cache *)generic_cache;

    /* No need to take a lock - we're the only thread with a reference now */

    /*
     * Destroy the pqueue first - when we destroy the hash table, destroy_cache_entry_vp will
     * free all entries in the cache, and so we want to make sure the pqueue references to
     * local_cache_entry->heap_node are no longer usable first.
     */
    aws_priority_queue_clean_up(&cache->ttl_heap);
    aws_hash_table_clean_up(&cache->entries);
    aws_mutex_clean_up(&cache->mutex);

    aws_mem_release(cache->allocator, cache);
}

static size_t entry_count(const struct aws_cryptosdk_mat_cache *generic_cache) {
    // Removing const so we can lock the cache mutex
    struct aws_cryptosdk_local_cache *cache = (struct aws_cryptosdk_local_cache *)generic_cache;

    if (aws_mutex_lock(&cache->mutex)) {
        return SIZE_MAX;
    }

    size_t entry_count = aws_hash_table_get_entry_count(&cache->entries);

    if (aws_mutex_unlock(&cache->mutex)) {
        abort();
    }

    return entry_count;
}

static int find_entry(
    struct aws_cryptosdk_mat_cache *generic_cache,
    struct aws_cryptosdk_mat_cache_entry **entry,
    bool *is_encrypt,
    const struct aws_byte_buf *cache_id) {
    struct aws_cryptosdk_local_cache *cache = (struct aws_cryptosdk_local_cache *)generic_cache;

    *entry = NULL;

    if (aws_mutex_lock(&cache->mutex)) {
        return AWS_OP_ERR;
    }

    struct local_cache_entry *local_entry;
    if (locked_find_entry(cache, &local_entry, cache_id)) {
        aws_atomic_fetch_add_explicit(&local_entry->refcount, 1, aws_memory_order_relaxed);
        *entry = (struct aws_cryptosdk_mat_cache_entry *)local_entry;
        if (is_encrypt) {
            *is_encrypt = (local_entry->enc_materials != NULL);
        }
    }

    if (aws_mutex_unlock(&cache->mutex)) {
        abort();
    }

    return AWS_OP_SUCCESS;
}

static int update_usage_stats(
    struct aws_cryptosdk_mat_cache *cache,
    struct aws_cryptosdk_mat_cache_entry *entry,
    struct aws_cryptosdk_cache_usage_stats *usage_stats) {
    (void)cache;
    struct local_cache_entry *local_entry = (struct local_cache_entry *)entry;

    if (local_entry->zombie || !local_entry->enc_materials) {
        return aws_raise_error(AWS_CRYPTOSDK_ERR_BAD_STATE);
    }

    /* TODO: Saturation */
    usage_stats->bytes_encrypted += aws_atomic_fetch_add(&local_entry->usage_bytes, usage_stats->bytes_encrypted);
    usage_stats->messages_encrypted +=
        aws_atomic_fetch_add(&local_entry->usage_messages, usage_stats->messages_encrypted);

    return AWS_OP_SUCCESS;
}

static int get_encryption_materials(
    struct aws_cryptosdk_mat_cache *cache,
    struct aws_allocator *allocator,
    struct aws_cryptosdk_encryption_materials **materials_out,
    struct aws_hash_table *enc_ctx,
    struct aws_cryptosdk_mat_cache_entry *entry) {
    (void)cache;
    struct local_cache_entry *local_entry                = (struct local_cache_entry *)entry;
    struct aws_cryptosdk_encryption_materials *materials = NULL;
    *materials_out                                       = NULL;

    if (!local_entry->enc_materials) {
        return aws_raise_error(AWS_CRYPTOSDK_ERR_BAD_STATE);
    }
    materials = aws_cryptosdk_encryption_materials_new(allocator, local_entry->enc_materials->alg);
    if (!materials) {
        return AWS_OP_ERR;
    }

    if (copy_encryption_materials(allocator, materials, local_entry->enc_materials)) {
        goto out;
    }

    if (aws_cryptosdk_enc_ctx_clone(allocator, enc_ctx, &local_entry->enc_ctx)) {
        goto out;
    }

    if (local_entry->key_materials && aws_cryptosdk_sig_sign_start(
                                          &materials->signctx,
                                          allocator,
                                          NULL,
                                          aws_cryptosdk_alg_props(materials->alg),
                                          local_entry->key_materials)) {
        goto out;
    }

    *materials_out = materials;
    materials      = NULL;

out:
    aws_cryptosdk_encryption_materials_destroy(materials);

    return *materials_out ? AWS_OP_SUCCESS : AWS_OP_ERR;
}
static int get_decryption_materials(
    const struct aws_cryptosdk_mat_cache *cache,
    struct aws_allocator *allocator,
    struct aws_cryptosdk_decryption_materials **materials_out,
    const struct aws_cryptosdk_mat_cache_entry *entry) {
    (void)cache;
    struct local_cache_entry *local_entry                = (struct local_cache_entry *)entry;
    struct aws_cryptosdk_decryption_materials *materials = NULL;
    *materials_out                                       = NULL;

    if (!local_entry->dec_materials) {
        // XXX
        return aws_raise_error(AWS_CRYPTOSDK_ERR_BAD_STATE);
    }

    materials = aws_cryptosdk_decryption_materials_new(allocator, local_entry->dec_materials->alg);

    if (!materials || copy_decryption_materials(allocator, materials, local_entry->dec_materials)) {
        goto out;
    }

    if (local_entry->key_materials &&
        aws_cryptosdk_sig_verify_start(
            &materials->signctx, allocator, local_entry->key_materials, aws_cryptosdk_alg_props(materials->alg))) {
        goto out;
    }

    *materials_out = materials;
    materials      = NULL;
out:
    aws_cryptosdk_decryption_materials_destroy(materials);

    return *materials_out ? AWS_OP_SUCCESS : AWS_OP_ERR;
}

static void put_entry_for_encrypt(
    struct aws_cryptosdk_mat_cache *generic_cache,
    struct aws_cryptosdk_mat_cache_entry **ret_entry,
    const struct aws_cryptosdk_encryption_materials *materials,
    struct aws_cryptosdk_cache_usage_stats initial_usage,
    const struct aws_hash_table *enc_ctx,
    const struct aws_byte_buf *cache_id) {
    struct aws_cryptosdk_local_cache *cache = (struct aws_cryptosdk_local_cache *)generic_cache;
    *ret_entry                              = NULL;

    if (aws_mutex_lock(&cache->mutex)) {
        return;
    }

    struct local_cache_entry *entry = new_entry(cache, cache_id);
    if (!entry) {
        goto out;
    }

    aws_atomic_init_int(&entry->usage_bytes, initial_usage.bytes_encrypted);
    aws_atomic_init_int(&entry->usage_messages, initial_usage.messages_encrypted);

    if (!(entry->enc_materials = aws_cryptosdk_encryption_materials_new(cache->allocator, materials->alg))) {
        goto out;
    }

    if (copy_encryption_materials(cache->allocator, entry->enc_materials, materials)) {
        goto out;
    }

    if (aws_cryptosdk_enc_ctx_init(cache->allocator, &entry->enc_ctx)) {
        goto out;
    }

    if (aws_cryptosdk_enc_ctx_clone(cache->allocator, &entry->enc_ctx, enc_ctx)) {
        goto out;
    }

    if (materials->signctx) {
        if (aws_cryptosdk_sig_get_privkey(materials->signctx, cache->allocator, &entry->key_materials)) {
            goto out;
        }
    }

    if (!locked_insert_entry(cache, entry)) {
        /* Prevent the entry from being freed - and prepare to return it */
        *ret_entry = (struct aws_cryptosdk_mat_cache_entry *)entry;
        aws_atomic_fetch_add_explicit(&entry->refcount, 1, aws_memory_order_acq_rel);
        entry = NULL;
    }
out:
    if (entry) {
        /*
         * If entry is non-NULL, it means we didn't successfully insert the entry.
         * We will therefore destroy it immediately.
         */
        destroy_cache_entry(entry);
    }

    if (aws_mutex_unlock(&cache->mutex)) {
        abort();
    }
}

static void put_entry_for_decrypt(
    struct aws_cryptosdk_mat_cache *generic_cache,
    struct aws_cryptosdk_mat_cache_entry **ret_entry,
    const struct aws_cryptosdk_decryption_materials *materials,
    const struct aws_byte_buf *cache_id) {
    struct aws_cryptosdk_local_cache *cache = (struct aws_cryptosdk_local_cache *)generic_cache;
    *ret_entry                              = NULL;

    if (aws_mutex_lock(&cache->mutex)) {
        return;
    }

    struct local_cache_entry *entry = new_entry(cache, cache_id);
    if (!entry) {
        goto out;
    }

    aws_atomic_init_int(&entry->usage_bytes, 0);
    aws_atomic_init_int(&entry->usage_messages, 0);

    if (!(entry->dec_materials = aws_cryptosdk_decryption_materials_new(cache->allocator, materials->alg))) {
        goto out;
    }

    if (copy_decryption_materials(cache->allocator, entry->dec_materials, materials)) {
        goto out;
    }

    if (materials->signctx) {
        if (aws_cryptosdk_sig_get_pubkey(materials->signctx, cache->allocator, &entry->key_materials)) {
            goto out;
        }
    }

    if (!locked_insert_entry(cache, entry)) {
        /* Prevent the entry from being freed - and prepare to return it */
        *ret_entry = (struct aws_cryptosdk_mat_cache_entry *)entry;
        aws_atomic_fetch_add_explicit(&entry->refcount, 1, aws_memory_order_acq_rel);
        entry = NULL;
    }
out:
    if (entry) {
        /*
         * If entry is non-NULL, it means we didn't successfully insert the entry.
         * We will therefore destroy it immediately.
         */
        destroy_cache_entry(entry);
    }

    if (aws_mutex_unlock(&cache->mutex)) {
        abort();
    }
}

static uint64_t get_creation_time(
    const struct aws_cryptosdk_mat_cache *cache, const struct aws_cryptosdk_mat_cache_entry *generic_entry) {
    const struct local_cache_entry *entry = (const struct local_cache_entry *)generic_entry;

    assert(&entry->owner->base == cache);
    (void)cache;

    return entry->creation_time;
}

static void set_expiration_hint(
    struct aws_cryptosdk_mat_cache *generic_cache,
    struct aws_cryptosdk_mat_cache_entry *generic_entry,
    uint64_t expiry_time) {
    struct local_cache_entry *entry         = (struct local_cache_entry *)generic_entry;
    struct aws_cryptosdk_local_cache *cache = entry->owner;
    assert(&cache->base == generic_cache);
    (void)generic_cache;

    /*
     * Fast path: If we already have the right expiration hint or are invalidated,
     * we don't need to take any locks.
     */
    if (entry->zombie || entry->expiry_time <= expiry_time) {
        return;
    }

    if (aws_mutex_lock(&cache->mutex)) {
        return;
    }

    /*
     * Recheck now that we have the lock.
     */
    if (entry->zombie || entry->expiry_time <= expiry_time) {
        goto out;
    }

    if (entry->expiry_time < NO_EXPIRY) {
        void *ignored;
        /* Remove from the heap before we muck with the heap order */
        int rv = aws_priority_queue_remove(&cache->ttl_heap, &ignored, &entry->heap_node);
        assert(!rv);
        /* Suppress unused rv warnings when NDEBUG is set */
        (void)rv;
    }

    entry->expiry_time = expiry_time;
    void *vp_entry     = entry;
    if (aws_priority_queue_push_ref(&cache->ttl_heap, &vp_entry, &entry->heap_node)) {
        /* Heap insertion failed - should be impossible, but deal with it anyway */
        entry->expiry_time = NO_EXPIRY;
    }

out:
    if (aws_mutex_unlock(&cache->mutex)) {
        /* Failed to release a lock - no recovery is possible */
        abort();
    }
}

static void release_entry(
    struct aws_cryptosdk_mat_cache *generic_cache,
    struct aws_cryptosdk_mat_cache_entry *generic_entry,
    bool invalidate) {
    struct aws_cryptosdk_local_cache *cache = (struct aws_cryptosdk_local_cache *)generic_cache;
    struct local_cache_entry *entry         = (struct local_cache_entry *)generic_entry;

    if (!entry) {
        return;
    }

    assert(entry->owner == cache);

    if (invalidate && !entry->zombie) {
        if (aws_mutex_lock(&cache->mutex)) {
            /*
             * If we failed to lock the mutex, we'll end up leaking the entry.
             * There's no meaningful recovery we can do, so just let it happen.
             */
            return;
        }

        /* This call will re-check the entry->zombie flag */
        locked_release_entry(cache, entry, invalidate);

        if (aws_mutex_unlock(&cache->mutex)) {
            abort();
        }

        return;
    }

    /*
     * We must use release order here; see comments in locked_release_entry regarding the race we're guarding
     * against.
     */
    size_t old_count = aws_atomic_fetch_sub_explicit(&entry->refcount, 1, aws_memory_order_release);
    assert(old_count != 0);

    if (old_count == 1) {
        /*
         * We took the last reference; free the entry.
         * Note that since we had the last reference, we know that it's already a zombie,
         * so all we need to do now is actually free the entry structure.
         */
        assert(entry->zombie);
        destroy_cache_entry(entry);
    }
}

static void clear_cache(struct aws_cryptosdk_mat_cache *generic_cache) {
    struct aws_cryptosdk_local_cache *cache = (struct aws_cryptosdk_local_cache *)generic_cache;

    if (aws_mutex_lock(&cache->mutex)) {
        return;
    }

    for (struct aws_hash_iter iter = aws_hash_iter_begin(&cache->entries); !aws_hash_iter_done(&iter);
         aws_hash_iter_next(&iter)) {
        struct local_cache_entry *entry = iter.element.value;

        /*
         * Don't delete from the entries table from within invalidate,
         * as this would interfere with our iterator. Instead delete via the
         * iterator.
         */
        locked_invalidate_entry(cache, entry, true);

        aws_hash_iter_delete(&iter, false);
    }

    if (aws_mutex_unlock(&cache->mutex)) {
        abort();
    }
}

static const struct aws_cryptosdk_mat_cache_vt local_cache_vt = { .vt_size                  = sizeof(local_cache_vt),
                                                                  .name                     = "Local materials cache",
                                                                  .find_entry               = find_entry,
                                                                  .update_usage_stats       = update_usage_stats,
                                                                  .get_encryption_materials = get_encryption_materials,
                                                                  .get_decryption_materials = get_decryption_materials,
                                                                  .put_entry_for_encrypt    = put_entry_for_encrypt,
                                                                  .put_entry_for_decrypt    = put_entry_for_decrypt,
                                                                  .destroy                  = destroy_cache,
                                                                  .entry_count              = entry_count,
                                                                  .entry_release            = release_entry,
                                                                  .entry_get_creation_time  = get_creation_time,
                                                                  .entry_ttl_hint           = set_expiration_hint,
                                                                  .clear                    = clear_cache };

AWS_CRYPTOSDK_TEST_STATIC
void aws_cryptosdk_local_cache_set_clock(
    struct aws_cryptosdk_mat_cache *generic_cache, int (*clock_get_ticks)(uint64_t *timestamp)) {
    assert(generic_cache->vt == &local_cache_vt);
    struct aws_cryptosdk_local_cache *cache = (struct aws_cryptosdk_local_cache *)generic_cache;

    cache->clock_get_ticks = clock_get_ticks;
}

struct aws_cryptosdk_mat_cache *aws_cryptosdk_mat_cache_local_new(struct aws_allocator *alloc, size_t capacity) {
    /* Suppress unused static method warnings */
    (void)aws_cryptosdk_local_cache_set_clock;

    if (capacity < 2) {
        /* This miniumum capacity avoids some annoying edge conditions in the LRU removal logic */
        capacity = 2;
    }

    struct aws_cryptosdk_local_cache *cache = aws_mem_acquire(alloc, sizeof(*cache));

    if (!cache) {
        goto err_alloc;
    }

    memset(cache, 0, sizeof(*cache));

    aws_cryptosdk_mat_cache_base_init(&cache->base, &local_cache_vt);
    cache->allocator     = alloc;
    cache->lru_head.next = cache->lru_head.prev = &cache->lru_head;
    cache->capacity                             = capacity;
    cache->clock_get_ticks                      = aws_sys_clock_get_ticks;

    if (aws_mutex_init(&cache->mutex)) {
        goto err_mutex;
    }

    if (aws_hash_table_init(
            &cache->entries, alloc, capacity, hash_cache_id, eq_cache_id, NULL, destroy_cache_entry_vp)) {
        goto err_hash_table;
    }

    if (aws_priority_queue_init_dynamic(
            &cache->ttl_heap, alloc, capacity, sizeof(struct local_cache_entry *), ttl_heap_cmp)) {
        goto err_pq;
    }

    return &cache->base;

err_pq:
    aws_hash_table_clean_up(&cache->entries);
err_hash_table:
    aws_mutex_clean_up(&cache->mutex);
err_mutex:
    aws_mem_release(alloc, cache);
err_alloc:
    return NULL;
}
