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
 * freeable datastructures.
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
     * Attempts to find an entry in the encrypt cache. If found, returns a
     * handle to the cache entry in *entry and the actual materials in *materials.
     * Otherwise, *entry and *materials are set to NULL.
     *
     * As part of finding the entry, this method will atomically increment the entry's
     * usage by *usage_stats; the updated usage stats are then returned in *usage_stats
     *
     * This function returns AWS_OP_SUCCESS on a successful cache hit or miss.
     * However, if an internal error occurs during processing, then AWS_OP_ERROR
     * is returned and an error is raised. In this case, the state of the materials
     * object and encryption context is unspecified, but can be safely destroyed and
     * cleaned up, respectively.
     *
     * Parameters:
     *
     * @param cache - The cache to perform the lookup against
     * @param request_allocator - The allocator to use to allocate the output decryption materials
     *  and copied encryption context keys and values
     * @param entry - Out-parameter that receives a handle to the cache entry, if found
     * @param materials - Out-parameter that receives the encryption materials, if found
     * @param enc_context - Out-parameter containing a (pre-initialized) encryption context
     *  hash table. If the cache is a hit, this will be updated with the encryption context
     *  that was cached.
     * @param cache_id - The cache identifier to look up.
     * @param usage_stats - Amount to increment usage stats by; receives final usage stats
     *                      after addition.
     */

    int (*get_entry_for_encrypt)(
        struct aws_cryptosdk_mat_cache *cache,
        struct aws_allocator *request_allocator,
        struct aws_cryptosdk_mat_cache_entry **entry,
        struct aws_cryptosdk_encryption_materials **materials,
        struct aws_hash_table *enc_context,
        const struct aws_byte_buf *cache_id,
        struct aws_cryptosdk_cache_usage_stats *usage_stats
    );

    /**
     * Attempts to put a copy of *materials into the encrypt cache, under the
     * given cache ID, and with the specified initial usage.
     *
     * If this method fails for any reason, the entry is simply not added to the cache,
     * and *entry is set to NULL.
     *
     * Parameters:
     * @param cache - The cache to insert into
     * @param entry - Out-parameter which receives a handle to the created cache entry.
     *                On failure, *entry will be set to NULL.
     * @param cache_id - The cache identifier to insert into
     * @param materials - The encryption materials to insert; a copy will be
     * made using the cache's allocator
     * @param enc_context - The encryption context associated with the cache entry;
     *  a copy will be made using the cache's allocator
     * @param initial_usage - The usage stats to initially record against this cache entry
     */
    void (*put_entry_for_encrypt)(
        struct aws_cryptosdk_mat_cache *cache,
        struct aws_cryptosdk_mat_cache_entry **entry,
        const struct aws_byte_buf *cache_id,
        const struct aws_cryptosdk_encryption_materials *materials,
        const struct aws_hash_table *enc_context,
        struct aws_cryptosdk_cache_usage_stats initial_usage
    );

    /**
     * Attempts to find an entry in the decrypt cache. If found, returns a handle to the
     * cache entry in *entry, and the decryption materials in *materials.
     * If the entry is not found, or an error occurs, sets *entry and *materials to NULL.
     *
     * Parameters:
     *
     * @param cache - The cache to perform the lookup against
     * @param request_allocator - The allocator to use to allocate the output decryption materials
     * @param entry - Out-parameter that receives the cache entry, if found
     * @param materials - Out-parameter that receives the decryption materials, if found.
     * @param cache_id - The cache identifier to look up.
     */
    void (*get_entry_for_decrypt)(
        struct aws_cryptosdk_mat_cache *cache,
        struct aws_allocator *request_allocator,
        struct aws_cryptosdk_mat_cache_entry **entry,
        struct aws_cryptosdk_decryption_materials **materials,
        const struct aws_byte_buf *cache_id
    );

    /**
     * Attempts to put a copy of *materials into the decrypt cache, under the
     * given cache ID.
     *
     * If this method fails for any reason, the entry is simply not added to the cache,
     * and *entry is set to NULL.
     *
     * Parameters:
     * @param cache - The cache to insert into
     * @param entry - Out-parameter that receives the cache entry, if found
     * @param cache_id - The cache identifier to insert into
     * @param materials - The encryption materials to insert; a copy will be
     * made using the cache's allocator
     */
    void (*put_entry_for_decrypt)(
        struct aws_cryptosdk_mat_cache *cache,
        struct aws_cryptosdk_mat_cache_entry **entry,
        const struct aws_byte_buf *cache_id,
        const struct aws_cryptosdk_decryption_materials *materials
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
    uint64_t (*entry_ctime)(
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
        struct aws_cryptosdk_mat_cache_entry *entry_count,
        uint64_t exp_time
    );
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
int aws_cryptosdk_mat_cache_get_entry_for_encrypt(
    struct aws_cryptosdk_mat_cache *cache,
    struct aws_allocator *request_allocator,
    struct aws_cryptosdk_mat_cache_entry **entry,
    struct aws_cryptosdk_encryption_materials **materials,
    struct aws_hash_table *enc_context,
    const struct aws_byte_buf *cache_id,
    struct aws_cryptosdk_cache_usage_stats *usage_stats
) {
    int (*get_entry_for_encrypt)(
        struct aws_cryptosdk_mat_cache *cache,
        struct aws_allocator *request_allocator,
        struct aws_cryptosdk_mat_cache_entry **entry,
        struct aws_cryptosdk_encryption_materials **materials,
        struct aws_hash_table *enc_context,
        const struct aws_byte_buf *cache_id,
        struct aws_cryptosdk_cache_usage_stats *usage_stats
    ) = AWS_CRYPTOSDK_INTERNAL_VT_GET(cache->vt, get_entry_for_encrypt, NULL);

    *entry = NULL;
    if (get_entry_for_encrypt) {
        return get_entry_for_encrypt(cache, request_allocator, entry, materials, enc_context, cache_id, usage_stats);
    }

    /* Emulate a cache miss by default */
    return AWS_OP_SUCCESS;
}

AWS_CRYPTOSDK_STATIC_INLINE
void aws_cryptosdk_mat_cache_put_entry_for_encrypt(
    struct aws_cryptosdk_mat_cache *cache,
    struct aws_cryptosdk_mat_cache_entry **entry,
    const struct aws_byte_buf *cache_id,
    const struct aws_cryptosdk_encryption_materials *materials,
    const struct aws_hash_table *enc_context,
    struct aws_cryptosdk_cache_usage_stats initial_usage
) {
    void (*put_entry_for_encrypt)(
        struct aws_cryptosdk_mat_cache *cache,
        struct aws_cryptosdk_mat_cache_entry **entry,
        const struct aws_byte_buf *cache_id,
        const struct aws_cryptosdk_encryption_materials *materials,
        const struct aws_hash_table *enc_context,
        struct aws_cryptosdk_cache_usage_stats initial_usage
    ) = AWS_CRYPTOSDK_INTERNAL_VT_GET(cache->vt, put_entry_for_encrypt, NULL);

    *entry = NULL;
    if (put_entry_for_encrypt) {
        put_entry_for_encrypt(cache, entry, cache_id, materials, enc_context, initial_usage);
    }
}

AWS_CRYPTOSDK_STATIC_INLINE
void aws_cryptosdk_mat_cache_get_entry_for_decrypt(
    struct aws_cryptosdk_mat_cache *cache,
    struct aws_allocator *request_allocator,
    struct aws_cryptosdk_mat_cache_entry **entry,
    struct aws_cryptosdk_decryption_materials **materials,
    const struct aws_byte_buf *cache_id
) {
    void (*get_entry_for_decrypt)(
        struct aws_cryptosdk_mat_cache *cache,
        struct aws_allocator *request_allocator,
        struct aws_cryptosdk_mat_cache_entry **entry,
        struct aws_cryptosdk_decryption_materials **materials,
        const struct aws_byte_buf *cache_id
    ) = AWS_CRYPTOSDK_INTERNAL_VT_GET(cache->vt, get_entry_for_decrypt, NULL);

    *entry = NULL;
    if (get_entry_for_decrypt) {
        get_entry_for_decrypt(cache, request_allocator, entry, materials, cache_id);
    }
}

AWS_CRYPTOSDK_STATIC_INLINE
void aws_cryptosdk_mat_cache_put_entry_for_decrypt(
    struct aws_cryptosdk_mat_cache *cache,
    struct aws_cryptosdk_mat_cache_entry **entry,
    const struct aws_byte_buf *cache_id,
    const struct aws_cryptosdk_decryption_materials *materials
) {
    void (*put_entry_for_decrypt)(
        struct aws_cryptosdk_mat_cache *cache,
        struct aws_cryptosdk_mat_cache_entry **entry,
        const struct aws_byte_buf *cache_id,
        const struct aws_cryptosdk_decryption_materials *materials
    ) = AWS_CRYPTOSDK_INTERNAL_VT_GET(cache->vt, put_entry_for_decrypt, NULL);

    *entry = NULL;
    if (put_entry_for_decrypt) {
        put_entry_for_decrypt(cache, entry, cache_id, materials);
    }
}

AWS_CRYPTOSDK_STATIC_INLINE
size_t aws_cryptosdk_mat_cache_entry_count(const struct aws_cryptosdk_mat_cache *cache) {
    size_t (*entry_count)(const struct aws_cryptosdk_mat_cache *cache)
        = AWS_CRYPTOSDK_INTERNAL_VT_GET(cache->vt, entry_count, NULL);

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
    ) = AWS_CRYPTOSDK_INTERNAL_VT_GET(cache->vt, entry_release, NULL);

    if (entry_release) {
        entry_release(cache, entry, invalidate);
    }
}

AWS_CRYPTOSDK_STATIC_INLINE
uint64_t aws_cryptosdk_mat_cache_entry_ctime(
    const struct aws_cryptosdk_mat_cache *cache,
    const struct aws_cryptosdk_mat_cache_entry *entry
) {
    uint64_t (*entry_ctime)(
        const struct aws_cryptosdk_mat_cache *cache,
        const struct aws_cryptosdk_mat_cache_entry *entry
    ) = AWS_CRYPTOSDK_INTERNAL_VT_GET(cache->vt, entry_ctime, NULL);

    if (entry_ctime) {
        return entry_ctime(cache, entry);
    } else {
        return 0;
    }
}

AWS_CRYPTOSDK_STATIC_INLINE
void aws_cryptosdk_mat_cache_entry_ttl_hint(
    struct aws_cryptosdk_mat_cache *cache,
    struct aws_cryptosdk_mat_cache_entry *entry_count,
    uint64_t exp_time
) {
    void (*entry_ttl_hint)(
        struct aws_cryptosdk_mat_cache *cache,
        struct aws_cryptosdk_mat_cache_entry *entry_count,
        uint64_t exp_time
    ) = AWS_CRYPTOSDK_INTERNAL_VT_GET(cache->vt, entry_ttl_hint, NULL);

    if (entry_ttl_hint) {
        entry_ttl_hint(cache, entry_count, exp_time);
    }
}

/**
 * Decrements the reference count on the cache; if the new reference count is zero, the cache is destroyed.
 */
AWS_CRYPTOSDK_STATIC_INLINE void aws_cryptosdk_mat_cache_release(struct aws_cryptosdk_mat_cache *mat_cache) {
    if (mat_cache && aws_cryptosdk_private_refcount_down(&mat_cache->refcount)) {
        void (*destroy)(struct aws_cryptosdk_mat_cache *cache)
            = AWS_CRYPTOSDK_INTERNAL_VT_GET(mat_cache->vt, destroy, NULL);

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



#endif
