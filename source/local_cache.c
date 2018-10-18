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
#include <aws/cryptosdk/private/cipher.h>
#include <aws/cryptosdk/private/enc_context.h>
#include <aws/cryptosdk/enc_context.h>

#include <aws/common/linked_list.h>
#include <aws/common/array_list.h>
#include <aws/common/priority_queue.h>
#include <aws/common/mutex.h>

#define CACHE_ID_MD_ALG AWS_CRYPTOSDK_MD_SHA512
#define TTL_EXPIRATION_BATCH_SIZE 8
#define NO_EXPIRY UINT64_MAX

/*
 * An entry in the local cache. This is what the aws_cryptosdk_mat_cache_entry pointers actually
 * point to.
 */
struct local_cache_entry {
    /* This refcount includes a count for the hashtable, if !zombie */
    struct aws_atomic_var refcount;

    /* The owning cache */
    struct aws_cryptosdk_local_cache *owner;

    /*
     * The cache ID is stored in this inline array.
     * cache_id then points back into this array, and is used as the key for the entries
     * hash table.
     */
    uint8_t cache_id_arr[AWS_CRYPTOSDK_MD_MAX_SIZE];
    struct aws_byte_buf cache_id;

    /*
     * expiry_time is NO_EXPIRY if no TTL has been configured
     */
    uint64_t expiry_time, creation_time;

    union {
        struct aws_cryptosdk_encryption_materials enc_materials;
        struct aws_cryptosdk_decryption_materials dec_materials;
    } u;
    /* Initialized for encrypt-mode entries only */
    struct aws_hash_table enc_context;

    /*
     * we extract the public or private key out of the enc/dec materials and store it
     * separately, in order to initialize the signing context later on
     */
    struct aws_string *key_materials;

    struct aws_cryptosdk_cache_usage_stats usage_stats;

    /*
     * Cache entries are organized into a binary heap sorted by (expiration timestamp, thisptr)
     *
     * Note: If expiry_time = NO_EXPIRY, then this entry is not part of the heap.
     */
    struct aws_priority_queue_node heap_node;

    /* For LRU purposes, we also include an intrusive doubly-linked-list */
    struct aws_linked_list_node lru_node;

    /*
     * After an entry is invalidated, it's possible that one or more references to it
     * remain via entry pointers returned to callers. In this case, we set the zombie
     * flag.
     *
     * When the zombie flag is set:
     *   * The dec/enc_materials structures are cleaned up
     *   * enc_context is cleaned up
     *   * The entry is not in the TTL heap (expiry_time = NO_EXPIRY)
     *   * lru_node is not in the LRU list
     */
    bool zombie : 1;
    bool is_encrypt : 1;
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
     * the root of a _circular_ linked list. lru_head->next is the MOST recently used;
     * lru_head->prev is the LEAST recently used.
     */
    struct aws_linked_list_node lru_head;
};

/********** General helpers **********/

static void locked_invalidate_entry(struct aws_cryptosdk_local_cache *cache, struct local_cache_entry *entry, bool skip_hash);
static void locked_release_entry(struct aws_cryptosdk_local_cache *cache, struct local_cache_entry *entry, bool invalidate);
static void locked_clean_entry(struct local_cache_entry *entry);

static uint64_t hash_cache_id(const void *vp_buf) {
    const struct aws_byte_buf *buf = vp_buf;

    /*
     * Our cache IDs are already (large) hashes, so we can just take a subset of the hash
     * as our cache ID.
     * TODO: Should we re-hash to deal with CMMs which don't pre-hash?
     */
    uint64_t hash_code = 0;
    memcpy(&hash_code, buf->buffer, buf->len < sizeof(hash_code) ? buf->len : sizeof(hash_code));

    return hash_code;
}

static bool eq_cache_id(const void *vp_a, const void *vp_b) {
    const struct aws_byte_buf *a = vp_a;
    const struct aws_byte_buf *b = vp_b;

    return aws_byte_buf_eq(a, b);
}

static inline int ttl_heap_cmp(const void *vpa, const void *vpb) {
    const struct local_cache_entry *a = vpa;
    const struct local_cache_entry *b = vpb;

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

/*
 * The normal pattern for the encryption_materials and decryption_materials structures is to
 * allocate them on the heap. In our case we inline them in the larger cache entry structure,
 * so we can't use aws_cryptosdk_[de/en]cryption_materials_destroy. Instead, we have our own
 * clean_up routines here.
 */
static void aws_cryptosdk_encryption_materials_clean_up(
    struct aws_cryptosdk_encryption_materials *materials
) {
    if (materials) {
        aws_cryptosdk_sig_abort(materials->signctx);
        aws_byte_buf_clean_up_secure(&materials->unencrypted_data_key);
        aws_cryptosdk_edk_list_clean_up(&materials->encrypted_data_keys);
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
 */
static void locked_invalidate_entry(struct aws_cryptosdk_local_cache *cache, struct local_cache_entry *entry, bool skip_hash) {
    assert(entry->owner == cache);

    if (entry->zombie) {
        return;
    }

    if (entry->expiry_time != NO_EXPIRY) {
        aws_priority_queue_remove(&cache->ttl_heap, entry, &entry->heap_node);
    }

    if (!skip_hash) {
        struct aws_hash_element element;
        /*
         * Note: Because we accept the old value into element, ht_entry_destructor
         * is not called.
         */
        aws_hash_table_remove(&cache->entries, &entry->cache_id, &element, NULL);
        assert(element.value == entry);
    }

    locked_clean_entry(entry);
}

/**
 * Called when an entry has been removed from the hashtable and priority queue, to clean up
 * various allocated datastructures that are not needed on an invalidated entry (and possibly
 * to free the entry itself).
 *
 * This also moves the entry to the zombie list.
 */
static void locked_clean_entry(struct local_cache_entry *entry) {
    if (entry->is_encrypt) {
        aws_cryptosdk_encryption_materials_clean_up(&entry->u.enc_materials);
    } else {
        // TODO
//        aws_cryptosdk_decryption_materials_clean_up(&entry->u.dec_materials);
        abort();
    }

    memset(&entry->u, 0, sizeof(entry->u));

    aws_string_destroy_secure(entry->key_materials);
    aws_cryptosdk_enc_context_clean_up(&entry->enc_context);

    entry->zombie = true;

    aws_linked_list_remove(&entry->lru_node);
    entry->lru_node.next = entry->lru_node.prev = &entry->lru_node;

    locked_release_entry(entry->owner, entry, false);
}

static void ht_entry_destructor(void *vp_entry) {
    /*
     * We enter this function already holding the cache mutex; because aws-common mutexes are non-reentrant,
     * and because we're actively manipulating the hash table, we can't safely re-use the release_entry invalidation
     * logic.
     *
     * Instead, we'll just set expiry_time to NO_EXPIRY (the priority queue will be cleared en masse later) and clean
     * the entry itself.
     */
    struct local_cache_entry *entry = vp_entry;

    entry->expiry_time = NO_EXPIRY;
    locked_clean_entry(entry);
}

static void destroy_cache(struct aws_cryptosdk_mat_cache *generic_cache) {
    struct aws_cryptosdk_local_cache *cache = (struct aws_cryptosdk_local_cache *)generic_cache;

    /* No need to take a lock - we're the only thread with a reference now */

    aws_hash_table_clean_up(&cache->entries);
    aws_priority_queue_clean_up(&cache->ttl_heap);
    aws_mutex_clean_up(&cache->mutex);

    aws_mem_release(cache->allocator, cache);
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

    if (aws_sys_clock_get_ticks(&now)) {
        return AWS_OP_ERR;
    }

    while (max_items_to_expire--
        && aws_priority_queue_size(&cache->ttl_heap)
        && !aws_priority_queue_top(&cache->ttl_heap, &vp_item)
        && (entry = vp_item)->expiry_time <= now
    ) {
        locked_invalidate_entry(cache, entry, false);
    }

    return AWS_OP_SUCCESS;
}

static bool locked_find_entry(
    struct aws_cryptosdk_local_cache *cache,
    struct local_cache_entry **entry,
    const struct aws_byte_buf *cache_id
) {
    struct aws_hash_element *element;

    locked_process_ttls(cache);

    if (aws_hash_table_find(&cache->entries, cache_id, &element) || !element) {
        return false;
    }

    *entry = element->value;

    locked_lru_move_to_head(&cache->lru_head, &(*entry)->lru_node);

    return true;
}

static int locked_insert_entry(
    struct aws_cryptosdk_local_cache *cache,
    struct local_cache_entry *entry
) {
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
    element->key = &entry->cache_id;
    element->value = entry;

    aws_linked_list_insert_after(&cache->lru_head, &entry->lru_node);

    while (aws_hash_table_get_entry_count(&cache->entries) > cache->capacity) {
        assert(cache->lru_head.prev != &cache->lru_head);
        assert(cache->lru_head.prev != &entry->lru_node);

        locked_invalidate_entry(cache, AWS_CONTAINER_OF(cache->lru_head.prev, struct local_cache_entry, lru_node), false);
    }

    return AWS_OP_SUCCESS;
}

static struct local_cache_entry *new_entry(struct aws_cryptosdk_local_cache *cache, const struct aws_byte_buf *cache_id) {
    uint64_t now;

    if (aws_sys_clock_get_ticks(&now)) {
        return NULL;
    }

    struct local_cache_entry *entry = aws_mem_acquire(cache->allocator, sizeof(*entry));

    if (!entry) {
        return NULL;
    }

    memset(entry, 0, sizeof(*entry));

    aws_atomic_init_int(&entry->refcount, 1);
    entry->owner = cache;

    size_t id_length = cache_id->len;
    if (id_length > AWS_CRYPTOSDK_MD_MAX_SIZE) {
        id_length = AWS_CRYPTOSDK_MD_MAX_SIZE;
    }

    /* TODO: Dynamically allocate the cache ID if it's large? Rehash? */
    memcpy(entry->cache_id_arr, cache_id->buffer, id_length);
    entry->cache_id = aws_byte_buf_from_array(entry->cache_id_arr, id_length);
    entry->creation_time = now;

    entry->lru_node.next = entry->lru_node.prev = &entry->lru_node;

    return entry;
}

static int clone_edk(struct aws_allocator *alloc, struct aws_cryptosdk_edk *out, const struct aws_cryptosdk_edk *in) {
    memset(out, 0, sizeof(*out));

    if (
        aws_byte_buf_init_copy(alloc, &out->provider_id, &in->provider_id)
     || aws_byte_buf_init_copy(alloc, &out->provider_info, &in->provider_info)
     || aws_byte_buf_init_copy(alloc, &out->enc_data_key, &in->enc_data_key)
    ) {
        return AWS_OP_ERR;
    }

    return AWS_OP_SUCCESS;
}

static int encryption_materials_init(struct aws_allocator *alloc, struct aws_cryptosdk_encryption_materials *materials) {
    memset(materials, 0, sizeof(*materials));

    materials->alloc = alloc;

    return aws_cryptosdk_edk_list_init(alloc, &materials->encrypted_data_keys);
}

static int copy_encryption_materials(struct aws_allocator *alloc, struct aws_cryptosdk_encryption_materials *out, const struct aws_cryptosdk_encryption_materials *in) {
    size_t edk_count = aws_array_list_length(&in->encrypted_data_keys);

    if (aws_byte_buf_init_copy(alloc, &out->unencrypted_data_key, &in->unencrypted_data_key)) {
        goto err;
    }

    for (size_t i = 0; i < edk_count; i++) {
        void *edk_in;
        struct aws_cryptosdk_edk edk_out;

        if (aws_array_list_get_at_ptr(&in->encrypted_data_keys, &edk_in, i)) {
            /* Shouldn't happen */
            goto err;
        }

        if (clone_edk(alloc, &edk_out, edk_in)) {
            goto err;
        }

        if (aws_array_list_push_back(&out->encrypted_data_keys, &edk_out)) {
            aws_cryptosdk_edk_clean_up(&edk_out);
            goto err;
        }
    }

    /* We do not clone the signing context itself, but instead we save the public or private keys elsewhere */
    out->signctx = NULL;
    out->alg = in->alg;

    return AWS_OP_SUCCESS;
err:
    return AWS_OP_ERR;
}

/********** Local cache vtable methods **********/

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


static int get_entry_for_encrypt(
    struct aws_allocator *request_allocator,
    struct aws_cryptosdk_mat_cache *generic_cache,
    struct aws_cryptosdk_mat_cache_entry **entry,
    struct aws_cryptosdk_encryption_materials **materials_out,
    struct aws_hash_table *enc_context,
    const struct aws_byte_buf *cache_id,
    struct aws_cryptosdk_cache_usage_stats *usage_stats
) {
    struct aws_cryptosdk_local_cache *cache = (struct aws_cryptosdk_local_cache *)generic_cache;
    struct aws_cryptosdk_encryption_materials *materials = NULL;

    *entry = NULL;
    *materials_out = NULL;

    if (aws_mutex_lock(&cache->mutex)) {
        return AWS_OP_ERR;
    }

    int rv = AWS_OP_ERR;

    struct local_cache_entry *local_entry;
    if (locked_find_entry(cache, &local_entry, cache_id) && local_entry->is_encrypt) {
        local_entry->usage_stats.bytes_encrypted += usage_stats->bytes_encrypted;
        local_entry->usage_stats.messages_encrypted += usage_stats->messages_encrypted;

        *usage_stats = local_entry->usage_stats;

        materials = aws_cryptosdk_encryption_materials_new(request_allocator, local_entry->u.enc_materials.alg);

        if (copy_encryption_materials(request_allocator, materials, &local_entry->u.enc_materials)) {
            goto out;
        }

        if (aws_cryptosdk_enc_context_clone(request_allocator, enc_context, &local_entry->enc_context)) {
            goto out;
        }

        if (local_entry->key_materials
            && aws_cryptosdk_sig_sign_start(
                &materials->signctx,
                request_allocator,
                NULL,
                aws_cryptosdk_alg_props(materials->alg),
                local_entry->key_materials
        )) {
            goto out;
        }

        aws_atomic_fetch_add_explicit(&local_entry->refcount, 1, aws_memory_order_relaxed);
        *entry = (struct aws_cryptosdk_mat_cache_entry *)local_entry;
        *materials_out = materials;
        materials = NULL;
    }

    rv = AWS_OP_SUCCESS;

    goto unlock;

out:
    aws_cryptosdk_encryption_materials_destroy(materials);

unlock:
    if (aws_mutex_unlock(&cache->mutex)) {
        abort();
    }

    return rv;
}

static void put_entry_for_encrypt(
    struct aws_cryptosdk_mat_cache *generic_cache,
    struct aws_cryptosdk_mat_cache_entry **ret_entry,
    const struct aws_byte_buf *cache_id,
    const struct aws_cryptosdk_encryption_materials *materials,
    const struct aws_hash_table *enc_context,
    struct aws_cryptosdk_cache_usage_stats initial_usage
) {
    struct aws_cryptosdk_local_cache *cache = (struct aws_cryptosdk_local_cache *)generic_cache;
    *ret_entry = NULL;

    if (aws_mutex_lock(&cache->mutex)) {
        return;
    }

    struct local_cache_entry *entry = new_entry(cache, cache_id);
    if (!entry) {
        goto out;
    }

    entry->is_encrypt = true;
    entry->usage_stats = initial_usage;

    if (encryption_materials_init(cache->allocator, &entry->u.enc_materials)) {
        goto out;
    }

    if (copy_encryption_materials(cache->allocator, &entry->u.enc_materials, materials)) {
        goto out;
    }

    if (aws_cryptosdk_enc_context_init(cache->allocator, &entry->enc_context)) {
        goto out;
    }

    if (aws_cryptosdk_enc_context_clone(cache->allocator, &entry->enc_context, enc_context)) {
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
        locked_clean_entry(entry);
    }

    if (aws_mutex_unlock(&cache->mutex)) {
        abort();
    }
}

static void get_entry_for_decrypt(
    struct aws_allocator *request_allocator,
    struct aws_cryptosdk_mat_cache *cache,
    struct aws_cryptosdk_mat_cache_entry **entry,
    struct aws_cryptosdk_decryption_materials **materials,
    const struct aws_byte_buf *cache_id
) {
    // TODO
    (void)request_allocator;
    (void)cache; (void)cache_id;
    *entry = NULL;
    *materials = NULL;
}

static void put_entry_for_decrypt(
    struct aws_cryptosdk_mat_cache *cache,
    struct aws_cryptosdk_mat_cache_entry **entry,
    const struct aws_byte_buf *cache_id,
    const struct aws_cryptosdk_decryption_materials *materials
) {
    // TODO
    (void)cache; (void)materials; (void)cache_id;
    *entry = NULL;
}


static uint64_t get_creation_time(
    const struct aws_cryptosdk_mat_cache *cache,
    const struct aws_cryptosdk_mat_cache_entry *generic_entry
) {
    const struct local_cache_entry *entry = (const struct local_cache_entry *)generic_entry;

    assert(&entry->owner->base == cache);

    return entry->creation_time;
}

static void set_expiration_hint(
    struct aws_cryptosdk_mat_cache *generic_cache,
    struct aws_cryptosdk_mat_cache_entry *generic_entry,
    uint64_t expiry_time
) {
    struct local_cache_entry *entry = (struct local_cache_entry *)generic_entry;
    struct aws_cryptosdk_local_cache *cache = entry->owner;
    assert(&cache->base == generic_cache);

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
        /* Remove from the heap before we muck with the heap order */
        int rv = aws_priority_queue_remove(&cache->ttl_heap, entry, &entry->heap_node);
        assert(!rv);
        /* Suppress unused rv warnings when NDEBUG is set */
        (void)rv;
    }

    entry->expiry_time = expiry_time;
    if (aws_priority_queue_push_ref(&cache->ttl_heap, entry, &entry->heap_node)) {
        /* Heap insertion failed - should be impossible, but deal with it anyway */
        entry->expiry_time = NO_EXPIRY;
    }

out:
    if (aws_mutex_unlock(&cache->mutex)) {
        /* Failed to release a lock - no recovery is possible */
        abort();
    }
}

static void locked_release_entry(
    struct aws_cryptosdk_local_cache *cache,
    struct local_cache_entry *entry,
    bool invalidate
) {
    /*
     * We must use release order here, to guard against a race where two threads release the last
     * two references simultaneously, and then pending writes to the entry are processed on one
     * thread while the other is destroying the entry.
     *
     * By using release order, we ensure that these pending writes are ordered before the final
     * release operation on the entry.
     */
    size_t old_count = aws_atomic_fetch_sub_explicit(&entry->refcount, 1, aws_memory_order_release);
    assert(old_count != 0);

    if (old_count == 1) {
        assert(entry->zombie);

        aws_mem_release(cache->allocator, entry);

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

static void release_entry(
    struct aws_cryptosdk_mat_cache *generic_cache,
    struct aws_cryptosdk_mat_cache_entry *generic_entry,
    bool invalidate
) {
    struct aws_cryptosdk_local_cache *cache = (struct aws_cryptosdk_local_cache *)generic_cache;
    struct local_cache_entry *entry = (struct local_cache_entry *)generic_entry;

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
     * We must use release order here, to guard against a race where two threads release the last
     * two references simultaneously, and then pending writes to the entry are processed on one
     * thread while the other is destroying the entry.
     *
     * By using release order, we ensure that these pending writes are ordered before the final
     * release operation on the entry.
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
        aws_mem_release(cache->allocator, entry);
    }
}

static const struct aws_cryptosdk_mat_cache_vt local_cache_vt = {
    .vt_size = sizeof(local_cache_vt),
    .name = "Local materials cache",
    .get_entry_for_encrypt = get_entry_for_encrypt,
    .put_entry_for_encrypt = put_entry_for_encrypt,
    .get_entry_for_decrypt = get_entry_for_decrypt,
    .put_entry_for_decrypt = put_entry_for_decrypt,
    .destroy = destroy_cache,
    .entry_count = entry_count,
    .entry_release = release_entry,
    .entry_ctime = get_creation_time,
    .entry_ttl_hint = set_expiration_hint
};

struct aws_cryptosdk_mat_cache *aws_cryptosdk_mat_cache_local_new(
    struct aws_allocator *alloc,
    size_t capacity
) {
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
    cache->allocator = alloc;
    cache->lru_head.next = cache->lru_head.prev = &cache->lru_head;
    cache->capacity = capacity;

    if (aws_mutex_init(&cache->mutex)) {
        goto err_mutex;
    }

    if (aws_hash_table_init(
        &cache->entries,
        alloc,
        capacity,
        hash_cache_id, eq_cache_id,
        NULL, ht_entry_destructor
    )) {
        goto err_hash_table;
    }

    if (aws_priority_queue_init_dynamic(&cache->ttl_heap, alloc, capacity, sizeof(struct local_cache_entry *), ttl_heap_cmp)) {
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
