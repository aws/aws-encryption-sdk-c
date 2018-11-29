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

#ifndef AWS_CRYPTOSDK_CACHE_H

#include <aws/common/clock.h>

#include <aws/cryptosdk/materials.h>
#include <aws/cryptosdk/vtable.h>
#include <aws/cryptosdk/exports.h>

#define AWS_CRYPTOSDK_CACHE_MAX_LIMIT_MESSAGES ((uint64_t)1 << 32)

struct aws_cryptosdk_cache_usage_stats {
    uint64_t bytes_encrypted, messages_encrypted;
};

/**
 * The backing materials cache that stores the cached materials for one or more caching CMMs.
 */
struct aws_cryptosdk_mat_cache {
    struct aws_atomic_var refcount;
    const struct aws_cryptosdk_mat_cache_vt *vt;
};

/**
 * Represents an opaque handle to an entry in the materials cache. These handles are returned
 * when putting or getting entries in the materials cache; the caller must release these handles
 * once done with the entry to avoid memory leaks.
 *
 * Entry handles are not necessarily reference counted; callers should assume that they are simply
 * freeable data structures.
 */
struct aws_cryptosdk_mat_cache_entry;

AWS_CRYPTOSDK_STATIC_INLINE
void aws_cryptosdk_mat_cache_base_init(
    struct aws_cryptosdk_mat_cache *cache,
    const struct aws_cryptosdk_mat_cache_vt *vt
) {
    cache->vt = vt;
    aws_atomic_init_int(&cache->refcount, 1);
}


struct aws_cryptosdk_mat_cache_vt {
    /**
     * Must be set to sizeof(struct aws_cryptosdk_mat_cache_vt)
     */
    size_t vt_size;

    /**
     * Identifier for debugging purposes
     */
    const char *name;

    /**
     * Attempts to find an entry in the cache. If found, returns a
     * handle to the cache entry in *entry Otherwise, *entry is set to NULL.
     *
     * If is_encrypt is non-NULL, *is_encrypt is set to TRUE if the found
     * materials are encryption materials, or FALSE if they are decryption
     * materials. If no entry was found, the value of *is_encrypt is undefined.
     *
     * This function returns AWS_OP_SUCCESS on a successful cache hit or miss.
     *
     * Parameters:
     *
     * @param cache - The cache to perform the lookup against
     * @param entry - Out-parameter that receives a handle to the cache entry, if found
     * @param is_encrypt - If an entry is found, set to true if the entry is for encryption,
     *  or false if for decryption.
     * @param cache_id - The cache identifier to look up.
     */

    int (*find_entry)(
        struct aws_cryptosdk_mat_cache *cache,
        struct aws_cryptosdk_mat_cache_entry **entry,
        bool *is_encrypt,
        const struct aws_byte_buf *cache_id
    );

    /**
     * Performs an atomic add-and-fetch on this entry's usage stats. The value
     * passed in via *usage_stats is added to the entry's usage stats; then, atomically
     * with the add, the new sum is read and returned via *usage_stats.
     *
     * In other words, this operation effectively does:
     *   *usage_stats = entry->stats = entry->stats + *usage_stats
     *
     * This operation is atomic with respect to each component of usage_stats, but may
     * not be atomic with respect to the overall usage_stats structure; this means that,
     * for example, if we start with (messages=1, bytes=1), and we have two threads
     * adding (1,1), one thread might observe (3,2) and the other might observe (2,3), but
     * we won't ever have both threads observing the same value.
     * 
     * If the cache entry is not an encrypt entry, or if the entry has been invalidated,
     * or if an internal error occurs during processing, the returned value of *usage_stats
     * is unspecified, and an error may be raised (AWS_OP_ERR returned).
     */
    int (*update_usage_stats)(
        struct aws_cryptosdk_mat_cache *cache,
        struct aws_cryptosdk_mat_cache_entry *entry,
        struct aws_cryptosdk_cache_usage_stats *usage_stats
    );

    /**
     * Retrieves the cached encryption materials from the cache.
     * 
     * On success, (1) `*materials` is overwritten with a newly allocated encryption
     * materials object, and (2) `enc_context` is updated to match the cached encryption
     * context (adding and removing entries to make it match the cached value).
     * 
     * On failure (e.g., out of memory), `*materials` will be set to NULL; `enc_context`
     * remains an allocated encryption context hash table, but the contents of the hash
     * table are unspecified, as we may have been forced to abort partway through updating
     * the contents of the hash table.
     *
     * This function will always fail if called on cached decryption materials. It MAY fail
     * when called on an invalidated entry, but this is not guaranteed.
     */
    int (*get_encryption_materials)(
        struct aws_cryptosdk_mat_cache *cache,
        struct aws_allocator *allocator,
        struct aws_cryptosdk_encryption_materials **materials,
        struct aws_hash_table *enc_context,
        struct aws_cryptosdk_mat_cache_entry *entry
    );

    /**
     * Attempts to put a copy of *encryption_materials into the cache, under the
     * given cache ID, and with the specified initial usage.
     *
     * If this method fails for any reason, the entry is simply not added to the cache,
     * and *entry is set to NULL.
     *
     * Parameters:
     * @param cache - The cache to insert into
     * @param entry - Out-parameter which receives a handle to the created cache entry.
     *                On failure, *entry will be set to NULL.
     * @param encryption_materials - The encryption materials to insert; a copy will be
     * made using the cache's allocator
     * @param initial_usage - The usage stats to initially record against this cache entry
     * @param enc_context - The encryption context associated with the cache entry;
     *  a copy will be made using the cache's allocator
     * @param cache_id - The cache identifier to insert into
     */
    void (*put_entry_for_encrypt)(
        struct aws_cryptosdk_mat_cache *cache,
        struct aws_cryptosdk_mat_cache_entry **entry,
        const struct aws_cryptosdk_encryption_materials *encryption_materials,
        struct aws_cryptosdk_cache_usage_stats initial_usage,
        const struct aws_hash_table *enc_context,
        const struct aws_byte_buf *cache_id
    );

    /**
     * Attempts to find an entry in the cache. If found, returns a handle to the
     * cache entry in *entry, and the decryption materials in *decryption_materials.
     * If the entry is not found, or an error occurs, sets *entry and *materials to NULL.
     *
     * If the entry contains encryption materials, this method will behave as if
     * the entry was not present.
     *
     * Parameters:
     *
     * @param cache - The cache to perform the lookup against
     * @param request_allocator - The allocator to use to allocate the output decryption materials
     * @param entry - Out-parameter that receives the cache entry, if found
     * @param decryption_materials - Out-parameter that receives the decryption materials, if found.
     * @param cache_id - The cache identifier to look up.
     */
    void (*get_entry_for_decrypt)(
        struct aws_cryptosdk_mat_cache *cache,
        struct aws_allocator *request_allocator,
        struct aws_cryptosdk_mat_cache_entry **entry,
        struct aws_cryptosdk_decryption_materials **decryption_materials,
        const struct aws_byte_buf *cache_id
    );

    /**
     * Attempts to put a copy of *decryption_materials into the cache, under the
     * given cache ID.
     *
     * If this method fails for any reason, the entry is simply not added to the cache,
     * and *entry is set to NULL.
     *
     * Parameters:
     * @param cache - The cache to insert into
     * @param entry - Out-parameter that receives the cache entry, if found
     * @param cache_id - The cache identifier to insert into
     * @param decryption_materials - The encryption materials to insert; a copy will be
     * made using the cache's allocator
     */
    void (*put_entry_for_decrypt)(
        struct aws_cryptosdk_mat_cache *cache,
        struct aws_cryptosdk_mat_cache_entry **entry,
        const struct aws_cryptosdk_decryption_materials *decryption_materials,
        const struct aws_byte_buf *cache_id
    );

    /**
     * Invoked when the materials cache reference count reaches zero.
     *
     * It is the caller's responsibility to release all entry handles before the last
     * reference to the cache itself is removed; failure to do so may result in a memory leak.
     */
    void (*destroy)(struct aws_cryptosdk_mat_cache *cache);

    /**
     * Returns an estimate of the number of entries in the cache. If a size estimate is not available,
     * returns SIZE_MAX.
     */
    size_t (*entry_count)(const struct aws_cryptosdk_mat_cache *cache);

    /**
     * Releases a reference to a cache entry returned by one of the get or put methods.
     * If invalidate is true, this method attempts to invalidate the entry from the cache;
     * this is not guaranteed to be successful.
     */
    void (*entry_release)(
        struct aws_cryptosdk_mat_cache *cache,
        struct aws_cryptosdk_mat_cache_entry *entry,
        bool invalidate
    );

    /**
     * Returns the creation time of the given cache entry.
     * If the creation time is unknown or an error occurs, returns 0.
     */
    uint64_t (*entry_get_creation_time)(
        const struct aws_cryptosdk_mat_cache *cache,
        const struct aws_cryptosdk_mat_cache_entry *entry
    );

    /**
     * Advises the cache that the selected entry is not needed after the specified time.
     * The cache may (but is not required to) invalidate the entry automatically at this
     * time.
     */
    void (*entry_ttl_hint)(
        struct aws_cryptosdk_mat_cache *cache,
        struct aws_cryptosdk_mat_cache_entry *entry,
        uint64_t exp_time
    );

    /**
     * Attempts to clear all entries in the cache. This method is threadsafe and may be called
     * when outstanding references to entries exist; the cache will be cleared, but some memory
     * may be used by referenced entries until released.
     */
    void (*clear)(struct aws_cryptosdk_mat_cache *cache);
};

/**
 * Creates a new instance of the built-in local materials cache. This cache is thread safe, and uses a simple
 * LRU policy (with capacity shared between encrypt and decrypt) to evict entries.
 */
struct aws_cryptosdk_mat_cache *aws_cryptosdk_mat_cache_local_new(
    struct aws_allocator *alloc,
    size_t capacity
);

AWS_CRYPTOSDK_STATIC_INLINE
int aws_cryptosdk_mat_cache_find_entry(
    struct aws_cryptosdk_mat_cache *cache,
    struct aws_cryptosdk_mat_cache_entry **entry,
    bool *is_encrypt,
    const struct aws_byte_buf *cache_id
) {
    int (*find_entry)(
        struct aws_cryptosdk_mat_cache *cache,
        struct aws_cryptosdk_mat_cache_entry **entry,
        bool *is_encrypt,
        const struct aws_byte_buf *cache_id
    ) = AWS_CRYPTOSDK_PRIVATE_VT_GET_NULL(cache->vt, find_entry);

    *entry = NULL;
    if (find_entry) {
        return find_entry(cache, entry, is_encrypt, cache_id);
    }

    return AWS_OP_SUCCESS;
}

AWS_CRYPTOSDK_STATIC_INLINE
int aws_cryptosdk_mat_cache_update_usage_stats(
    struct aws_cryptosdk_mat_cache *cache,
    struct aws_cryptosdk_mat_cache_entry *entry,
    struct aws_cryptosdk_cache_usage_stats *usage_stats
) {
    int (*update_usage_stats)(
        struct aws_cryptosdk_mat_cache *cache,
        struct aws_cryptosdk_mat_cache_entry *entry,
        struct aws_cryptosdk_cache_usage_stats *usage_stats
    ) = AWS_CRYPTOSDK_PRIVATE_VT_GET_NULL(cache->vt, update_usage_stats);

    if (!update_usage_stats) {
        return aws_raise_error(AWS_ERROR_UNSUPPORTED_OPERATION);
    }

    return update_usage_stats(cache, entry, usage_stats);
}


AWS_CRYPTOSDK_STATIC_INLINE
int aws_cryptosdk_mat_cache_get_encryption_materials(
    struct aws_cryptosdk_mat_cache *cache,
    struct aws_allocator *allocator,
    struct aws_cryptosdk_encryption_materials **materials,
    struct aws_hash_table *enc_context,
    struct aws_cryptosdk_mat_cache_entry *entry
) {
    int (*get_encryption_materials)(
        struct aws_cryptosdk_mat_cache *cache,
        struct aws_allocator *allocator,
        struct aws_cryptosdk_encryption_materials **materials,
        struct aws_hash_table *enc_context,
        struct aws_cryptosdk_mat_cache_entry *entry
    ) = AWS_CRYPTOSDK_PRIVATE_VT_GET_NULL(cache->vt, get_encryption_materials);

    *materials = NULL;
    if (!get_encryption_materials) {
        return aws_raise_error(AWS_ERROR_UNSUPPORTED_OPERATION);
    }

    return get_encryption_materials(cache, allocator, materials, enc_context, entry);
}


AWS_CRYPTOSDK_STATIC_INLINE
void aws_cryptosdk_mat_cache_put_entry_for_encrypt(
    struct aws_cryptosdk_mat_cache *cache,
    struct aws_cryptosdk_mat_cache_entry **entry,
    const struct aws_cryptosdk_encryption_materials *encryption_materials,
    struct aws_cryptosdk_cache_usage_stats initial_usage,
    const struct aws_hash_table *enc_context,
    const struct aws_byte_buf *cache_id
) {
    void (*put_entry_for_encrypt)(
        struct aws_cryptosdk_mat_cache *cache,
        struct aws_cryptosdk_mat_cache_entry **entry,
        const struct aws_cryptosdk_encryption_materials *encryption_materials,
        struct aws_cryptosdk_cache_usage_stats initial_usage,
        const struct aws_hash_table *enc_context,
        const struct aws_byte_buf *cache_id
    ) = AWS_CRYPTOSDK_PRIVATE_VT_GET_NULL(cache->vt, put_entry_for_encrypt);

    *entry = NULL;
    if (put_entry_for_encrypt) {
        put_entry_for_encrypt(cache, entry, encryption_materials, initial_usage, enc_context, cache_id);
    }
}

AWS_CRYPTOSDK_STATIC_INLINE
void aws_cryptosdk_mat_cache_get_entry_for_decrypt(
    struct aws_cryptosdk_mat_cache *cache,
    struct aws_allocator *request_allocator,
    struct aws_cryptosdk_mat_cache_entry **entry,
    struct aws_cryptosdk_decryption_materials **decryption_materials,
    const struct aws_byte_buf *cache_id
) {
    void (*get_entry_for_decrypt)(
        struct aws_cryptosdk_mat_cache *cache,
        struct aws_allocator *request_allocator,
        struct aws_cryptosdk_mat_cache_entry **entry,
        struct aws_cryptosdk_decryption_materials **decryption_materials,
        const struct aws_byte_buf *cache_id
    ) = AWS_CRYPTOSDK_PRIVATE_VT_GET_NULL(cache->vt, get_entry_for_decrypt);

    *entry = NULL;
    if (get_entry_for_decrypt) {
        get_entry_for_decrypt(cache, request_allocator, entry, decryption_materials, cache_id);
    }
}

AWS_CRYPTOSDK_STATIC_INLINE
void aws_cryptosdk_mat_cache_put_entry_for_decrypt(
    struct aws_cryptosdk_mat_cache *cache,
    struct aws_cryptosdk_mat_cache_entry **entry,
    const struct aws_cryptosdk_decryption_materials *decryption_materials,
    const struct aws_byte_buf *cache_id
) {
    void (*put_entry_for_decrypt)(
        struct aws_cryptosdk_mat_cache *cache,
        struct aws_cryptosdk_mat_cache_entry **entry,
        const struct aws_cryptosdk_decryption_materials *decryption_materials,
        const struct aws_byte_buf *cache_id
    ) = AWS_CRYPTOSDK_PRIVATE_VT_GET_NULL(cache->vt, put_entry_for_decrypt);

    *entry = NULL;
    if (put_entry_for_decrypt) {
        put_entry_for_decrypt(cache, entry, decryption_materials, cache_id);
    }
}

AWS_CRYPTOSDK_STATIC_INLINE
size_t aws_cryptosdk_mat_cache_entry_count(const struct aws_cryptosdk_mat_cache *cache) {
    size_t (*entry_count)(const struct aws_cryptosdk_mat_cache *cache)
        = AWS_CRYPTOSDK_PRIVATE_VT_GET_NULL(cache->vt, entry_count);

    if (!entry_count) {
        return SIZE_MAX;
    }

    return entry_count(cache);
}

AWS_CRYPTOSDK_STATIC_INLINE
void aws_cryptosdk_mat_cache_entry_release(
    struct aws_cryptosdk_mat_cache *cache,
    struct aws_cryptosdk_mat_cache_entry *entry,
    bool invalidate
) {
    void (*entry_release)(
        struct aws_cryptosdk_mat_cache *cache,
        struct aws_cryptosdk_mat_cache_entry *entry,
        bool invalidate
    ) = AWS_CRYPTOSDK_PRIVATE_VT_GET_NULL(cache->vt, entry_release);

    if (entry_release) {
        entry_release(cache, entry, invalidate);
    }
}

AWS_CRYPTOSDK_STATIC_INLINE
uint64_t aws_cryptosdk_mat_cache_entry_get_creation_time(
    const struct aws_cryptosdk_mat_cache *cache,
    const struct aws_cryptosdk_mat_cache_entry *entry
) {
    uint64_t (*entry_get_creation_time)(
        const struct aws_cryptosdk_mat_cache *cache,
        const struct aws_cryptosdk_mat_cache_entry *entry
    ) = AWS_CRYPTOSDK_PRIVATE_VT_GET_NULL(cache->vt, entry_get_creation_time);

    if (entry_get_creation_time) {
        return entry_get_creation_time(cache, entry);
    } else {
        return 0;
    }
}

AWS_CRYPTOSDK_STATIC_INLINE
void aws_cryptosdk_mat_cache_entry_ttl_hint(
    struct aws_cryptosdk_mat_cache *cache,
    struct aws_cryptosdk_mat_cache_entry *entry,
    uint64_t exp_time
) {
    void (*entry_ttl_hint)(
        struct aws_cryptosdk_mat_cache *cache,
        struct aws_cryptosdk_mat_cache_entry *entry,
        uint64_t exp_time
    ) = AWS_CRYPTOSDK_PRIVATE_VT_GET_NULL(cache->vt, entry_ttl_hint);

    if (entry_ttl_hint) {
        entry_ttl_hint(cache, entry, exp_time);
    }
}

/**
 * Attempts to clear all entries in the cache
 */
AWS_CRYPTOSDK_STATIC_INLINE
void aws_cryptosdk_mat_cache_clear(struct aws_cryptosdk_mat_cache *cache) {
    void (*clear)(struct aws_cryptosdk_mat_cache *cache)
        = AWS_CRYPTOSDK_PRIVATE_VT_GET_NULL(cache->vt, clear);

    if (clear) {
        clear(cache);
    }
}

/**
 * Decrements the reference count on the cache; if the new reference count is zero, the cache is destroyed.
 */
AWS_CRYPTOSDK_STATIC_INLINE void aws_cryptosdk_mat_cache_release(struct aws_cryptosdk_mat_cache *mat_cache) {
    if (mat_cache && aws_cryptosdk_private_refcount_down(&mat_cache->refcount)) {
        void (*destroy)(struct aws_cryptosdk_mat_cache *cache)
            = AWS_CRYPTOSDK_PRIVATE_VT_GET_NULL(mat_cache->vt, destroy);

        if (!destroy) {
            abort();
        }

        destroy(mat_cache);
    }
}

/**
 * Increments the reference count on the materials cache
 */
AWS_CRYPTOSDK_STATIC_INLINE struct aws_cryptosdk_mat_cache *aws_cryptosdk_mat_cache_retain(struct aws_cryptosdk_mat_cache * mat_cache) {
    aws_cryptosdk_private_refcount_up(&mat_cache->refcount);
    return mat_cache;
}

/**
 * Creates a new instance of the caching crypto materials manager. This CMM will intercept requests for encrypt
 * and decrypt materials, and forward them to the provided materials cache.
 *
 * If multiple caching CMMs are attached to the same mat_cache, they will share entries if and only if the partition_id
 * parameter is set to the same string. Unless you need to use this feature, we recommend passing NULL, in which case
 * the caching CMM will internally generate a random partition ID to ensure it does not collide with any other CMM.
 *
 * Parameters:
 * @param alloc - The allocator to use for the caching CMM itself (not for cache entries, however)
 * @param mat_cache - The backing cache
 * @param upstream - The upstream CMM to query on a cache miss
 * @param partition_id - The partition ID to use to avoid collisions with other CMMs. This string need not remain valid
 *                       once this function returns. If NULL, a random partition ID will be generated and used.
 */
struct aws_cryptosdk_cmm *aws_cryptosdk_caching_cmm_new(
    struct aws_allocator *alloc,
    struct aws_cryptosdk_mat_cache *mat_cache,
    struct aws_cryptosdk_cmm *upstream,
    const struct aws_byte_buf *partition_id
);

enum aws_cryptosdk_caching_cmm_limit_type {
    AWS_CRYPTOSDK_CACHE_LIMIT_MESSAGES = 0x1000,
    AWS_CRYPTOSDK_CACHE_LIMIT_BYTES,
    AWS_CRYPTOSDK_CACHE_LIMIT_TTL
};

/**
 * Configures the usage limis for cached entries when used via this CMM.
 *
 * The caching CMM can be configured to limit cache entry usage by number of messages encrypted,
 * number of bytes encrypted, and/or by the maximum time to live in the cache. For decrypt operations,
 * only the time to live limit is effective.
 *
 * Note that the byte limit is determined based on information available at the time the encrypt operation
 * begins; if the aws_cryptosdk_session_set_message_size function is not called before invoking
 * aws_cryptosdk_session_process for the first time, then this will be based on the
 * aws_cryptosdk_session_set_message_bound value. If neither function is called before the first call to
 * process, then a cache miss will be forced on encrypt, as the message size is completely unknown.
 *
 * By default, all limits are set to their maximum permitted values:
 *   * The message count limit is set to 1 << 32 (AWS_CRYPTOSDK_CACHE_MAX_LIMIT_MESSAGES)
 *   * The byte count limit is set to UINT64_MAX
 *   * The TTL limit is set to UINT64_MAX
 *
 * If you attempt to set a limit to a value higher than the maximum permitted value,
 * it will instead be set to the maximum permitted value.
 *
 * Parameters:
 * @param cmm - The caching CMM to configure.
 * @param type - The type of limit to set
 * @param new_value - The new value of the limit
 */
int aws_cryptosdk_caching_cmm_set_limits(
    struct aws_cryptosdk_cmm *cmm,
    enum aws_cryptosdk_caching_cmm_limit_type type,
    uint64_t new_value
);

#endif
