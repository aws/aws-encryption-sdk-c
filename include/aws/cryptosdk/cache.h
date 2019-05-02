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
#define AWS_CRYPTOSDK_CACHE_H

#include <aws/common/clock.h>

#include <aws/cryptosdk/exports.h>
#include <aws/cryptosdk/materials.h>
#include <aws/cryptosdk/vtable.h>

AWS_EXTERN_C_BEGIN

/**
 * @defgroup caching Caching APIs
 *
 * The caching CMM caches the results of encryption and decryption operations
 * to reduce the number of calls made to backing keyrings (e.g. KMS).
 *
 * To use the caching API, construct a local cache (using @ref
 * aws_cryptosdk_materials_cache_local_new) and pass it to the constructor of a
 * caching cmm (@ref aws_cryptosdk_caching_cmm_new), along with a delegate CMM
 * that generates the encryption and decryption materials that are cached.
 *
 * When constructing a caching CMM, you are required to set a time-to-live (TTL)
 * for data keys in the cache. We also recommend setting one of the two additional
 * security thresholds using @ref aws_cryptosdk_caching_cmm_set_limit_bytes or
 * @ref aws_cryptosdk_caching_cmm_set_limit_messages to ensure that data keys expire
 * and are refreshed periodically.
 *
 * As with CMMs and keyrings, the local cache is reference-counted. In simple use
 * cases where there is only one local cache and one CMM, you can immediately call
 * @ref aws_cryptosdk_materials_cache_release on the local cache after constructing the
 * CMM.
 *
 * Multiple caching CMMs can share the same local cache, but by default will
 * not use each other's entries. (They share the entry count limit, but otherwise
 * are partitioned from each other.) This is to avoid unexpected behavior
 * in case the cache-miss delegate CMMs are different. If you want two caching CMMs
 * to share their entries, pass the same partition ID to both calls to @ref
 * aws_cryptosdk_caching_cmm_new .
 * @{
 */

#define AWS_CRYPTOSDK_CACHE_MAX_LIMIT_MESSAGES ((uint64_t)1 << 32)

/**
 * The backing materials cache that stores the cached materials for one or more caching CMMs.
 */
#ifdef AWS_CRYPTOSDK_DOXYGEN
struct aws_cryptosdk_materials_cache;
#else
struct aws_cryptosdk_materials_cache {
    struct aws_atomic_var refcount;
    const struct aws_cryptosdk_materials_cache_vt *vt;
};
#endif

#ifndef AWS_CRYPTOSDK_DOXYGEN
/**
 * NOTE: The extension API for defining new materials cache is currently considered unstable and
 * may change in the future.
 */

/**
 * Represents an opaque handle to an entry in the materials cache. These handles are returned
 * when putting or getting entries in the materials cache; the caller must release these handles
 * once done with the entry to avoid memory leaks.
 *
 * Entry handles are not necessarily reference counted; callers should assume that they are simply
 * freeable data structures.
 */
struct aws_cryptosdk_materials_cache_entry;

struct aws_cryptosdk_cache_usage_stats {
    uint64_t bytes_encrypted, messages_encrypted;
};

AWS_CRYPTOSDK_STATIC_INLINE
void aws_cryptosdk_materials_cache_base_init(
    struct aws_cryptosdk_materials_cache *cache, const struct aws_cryptosdk_materials_cache_vt *vt) {
    cache->vt = vt;
    aws_atomic_init_int(&cache->refcount, 1);
}

struct aws_cryptosdk_materials_cache_vt {
    /**
     * Must be set to sizeof(struct aws_cryptosdk_materials_cache_vt)
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
     * @param cache The cache to perform the lookup against
     * @param entry Out-parameter that receives a handle to the cache entry, if found
     * @param is_encrypt If an entry is found, set to true if the entry is for encryption,
     *  or false if for decryption.
     * @param cache_id The cache identifier to look up.
     */

    int (*find_entry)(
        struct aws_cryptosdk_materials_cache *cache,
        struct aws_cryptosdk_materials_cache_entry **entry,
        bool *is_encrypt,
        const struct aws_byte_buf *cache_id);

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
        struct aws_cryptosdk_materials_cache *cache,
        struct aws_cryptosdk_materials_cache_entry *entry,
        struct aws_cryptosdk_cache_usage_stats *usage_stats);

    /**
     * Retrieves the cached encryption materials from the cache.
     *
     * On success, (1) `*materials` is overwritten with a newly allocated encryption
     * materials object, and (2) `enc_ctx` is updated to match the cached encryption
     * context (adding and removing entries to make it match the cached value).
     *
     * On failure (e.g., out of memory), `*materials` will be set to NULL; `enc_ctx`
     * remains an allocated encryption context hash table, but the contents of the hash
     * table are unspecified, as we may have been forced to abort partway through updating
     * the contents of the hash table.
     *
     * This function will always fail if called on cached decryption materials. It MAY fail
     * when called on an invalidated entry, but this is not guaranteed.
     */
    int (*get_enc_materials)(
        struct aws_cryptosdk_materials_cache *cache,
        struct aws_allocator *allocator,
        struct aws_cryptosdk_enc_materials **materials,
        struct aws_hash_table *enc_ctx,
        struct aws_cryptosdk_materials_cache_entry *entry);

    /**
     * Retrieves the cached decryption materials from the cache.
     *
     * On success, `*materials` is overwritten with a newly allocated decryption
     * materials object.
     *
     * On failure (e.g., out of memory), `*materials` will be set to NULL.
     *
     * This function will always fail if called on cached encryption materials. It MAY fail
     * when called on an invalidated entry, but this is not guaranteed.
     */
    int (*get_dec_materials)(
        const struct aws_cryptosdk_materials_cache *cache,
        struct aws_allocator *allocator,
        struct aws_cryptosdk_dec_materials **materials,
        const struct aws_cryptosdk_materials_cache_entry *entry);

    /**
     * Attempts to put a copy of *enc_materials into the cache, under the
     * given cache ID, and with the specified initial usage.
     *
     * If this method fails for any reason, the entry is simply not added to the cache,
     * and *entry is set to NULL.
     *
     * Parameters:
     * @param cache The cache to insert into
     * @param entry Out-parameter which receives a handle to the created cache entry.
     *                On failure, *entry will be set to NULL.
     * @param enc_materials The encryption materials to insert; a copy will be
     * made using the cache's allocator
     * @param initial_usage The usage stats to initially record against this cache entry
     * @param enc_ctx The encryption context associated with the cache entry;
     *  a copy will be made using the cache's allocator
     * @param cache_id The cache identifier to insert into
     */
    void (*put_entry_for_encrypt)(
        struct aws_cryptosdk_materials_cache *cache,
        struct aws_cryptosdk_materials_cache_entry **entry,
        const struct aws_cryptosdk_enc_materials *enc_materials,
        struct aws_cryptosdk_cache_usage_stats initial_usage,
        const struct aws_hash_table *enc_ctx,
        const struct aws_byte_buf *cache_id);

    /**
     * Attempts to put a copy of *dec_materials into the cache, under the
     * given cache ID.
     *
     * If this method fails for any reason, the entry is simply not added to the cache,
     * and *entry is set to NULL.
     *
     * Parameters:
     * @param cache The cache to insert into
     * @param entry Out-parameter that receives the cache entry, if found
     * @param cache_id The cache identifier to insert into
     * @param dec_materials The encryption materials to insert; a copy will be
     * made using the cache's allocator
     */
    void (*put_entry_for_decrypt)(
        struct aws_cryptosdk_materials_cache *cache,
        struct aws_cryptosdk_materials_cache_entry **entry,
        const struct aws_cryptosdk_dec_materials *dec_materials,
        const struct aws_byte_buf *cache_id);

    /**
     * Invoked when the materials cache reference count reaches zero.
     *
     * It is the caller's responsibility to release all entry handles before the last
     * reference to the cache itself is removed; failure to do so may result in a memory leak.
     */
    void (*destroy)(struct aws_cryptosdk_materials_cache *cache);

    size_t (*entry_count)(const struct aws_cryptosdk_materials_cache *cache);

    /**
     * Releases a reference to a cache entry returned by one of the get or put methods.
     * If invalidate is true, this method attempts to invalidate the entry from the cache;
     * this is not guaranteed to be successful.
     */
    void (*entry_release)(
        struct aws_cryptosdk_materials_cache *cache,
        struct aws_cryptosdk_materials_cache_entry *entry,
        bool invalidate);

    /**
     * Returns the creation time of the given cache entry.
     * If the creation time is unknown or an error occurs, returns 0.
     */
    uint64_t (*entry_get_creation_time)(
        const struct aws_cryptosdk_materials_cache *cache, const struct aws_cryptosdk_materials_cache_entry *entry);

    /**
     * Advises the cache that the selected entry is not needed after the specified time.
     * The cache may (but is not required to) invalidate the entry automatically at this
     * time.
     */
    void (*entry_ttl_hint)(
        struct aws_cryptosdk_materials_cache *cache,
        struct aws_cryptosdk_materials_cache_entry *entry,
        uint64_t exp_time);

    /**
     * Attempts to clear all entries in the cache. This method is threadsafe and may be called
     * when outstanding references to entries exist; the cache will be cleared, but some memory
     * may be used by referenced entries until released.
     */
    void (*clear)(struct aws_cryptosdk_materials_cache *cache);
};

AWS_CRYPTOSDK_STATIC_INLINE
int aws_cryptosdk_materials_cache_find_entry(
    struct aws_cryptosdk_materials_cache *cache,
    struct aws_cryptosdk_materials_cache_entry **entry,
    bool *is_encrypt,
    const struct aws_byte_buf *cache_id) {
    int (*find_entry)(
        struct aws_cryptosdk_materials_cache * cache,
        struct aws_cryptosdk_materials_cache_entry * *entry,
        bool *is_encrypt,
        const struct aws_byte_buf *cache_id) = AWS_CRYPTOSDK_PRIVATE_VT_GET_NULL(cache->vt, find_entry);

    *entry = NULL;
    if (find_entry) {
        return find_entry(cache, entry, is_encrypt, cache_id);
    }

    return AWS_OP_SUCCESS;
}

AWS_CRYPTOSDK_STATIC_INLINE
int aws_cryptosdk_materials_cache_update_usage_stats(
    struct aws_cryptosdk_materials_cache *cache,
    struct aws_cryptosdk_materials_cache_entry *entry,
    struct aws_cryptosdk_cache_usage_stats *usage_stats) {
    int (*update_usage_stats)(
        struct aws_cryptosdk_materials_cache * cache,
        struct aws_cryptosdk_materials_cache_entry * entry,
        struct aws_cryptosdk_cache_usage_stats * usage_stats) =
        AWS_CRYPTOSDK_PRIVATE_VT_GET_NULL(cache->vt, update_usage_stats);

    if (!update_usage_stats) {
        return aws_raise_error(AWS_ERROR_UNSUPPORTED_OPERATION);
    }

    return update_usage_stats(cache, entry, usage_stats);
}

AWS_CRYPTOSDK_STATIC_INLINE
int aws_cryptosdk_materials_cache_get_enc_materials(
    struct aws_cryptosdk_materials_cache *cache,
    struct aws_allocator *allocator,
    struct aws_cryptosdk_enc_materials **materials,
    struct aws_hash_table *enc_ctx,
    struct aws_cryptosdk_materials_cache_entry *entry) {
    int (*get_enc_materials)(
        struct aws_cryptosdk_materials_cache * cache,
        struct aws_allocator * allocator,
        struct aws_cryptosdk_enc_materials * *materials,
        struct aws_hash_table * enc_ctx,
        struct aws_cryptosdk_materials_cache_entry * entry) =
        AWS_CRYPTOSDK_PRIVATE_VT_GET_NULL(cache->vt, get_enc_materials);

    *materials = NULL;
    if (!get_enc_materials) {
        return aws_raise_error(AWS_ERROR_UNSUPPORTED_OPERATION);
    }

    return get_enc_materials(cache, allocator, materials, enc_ctx, entry);
}

AWS_CRYPTOSDK_STATIC_INLINE
int aws_cryptosdk_materials_cache_get_dec_materials(
    const struct aws_cryptosdk_materials_cache *cache,
    struct aws_allocator *allocator,
    struct aws_cryptosdk_dec_materials **materials,
    const struct aws_cryptosdk_materials_cache_entry *entry) {
    int (*get_dec_materials)(
        const struct aws_cryptosdk_materials_cache *cache,
        struct aws_allocator *allocator,
        struct aws_cryptosdk_dec_materials **materials,
        const struct aws_cryptosdk_materials_cache_entry *entry) =
        AWS_CRYPTOSDK_PRIVATE_VT_GET_NULL(cache->vt, get_dec_materials);

    *materials = NULL;
    if (!get_dec_materials) {
        return aws_raise_error(AWS_ERROR_UNSUPPORTED_OPERATION);
    }

    return get_dec_materials(cache, allocator, materials, entry);
}

AWS_CRYPTOSDK_STATIC_INLINE
void aws_cryptosdk_materials_cache_put_entry_for_encrypt(
    struct aws_cryptosdk_materials_cache *cache,
    struct aws_cryptosdk_materials_cache_entry **entry,
    const struct aws_cryptosdk_enc_materials *enc_materials,
    struct aws_cryptosdk_cache_usage_stats initial_usage,
    const struct aws_hash_table *enc_ctx,
    const struct aws_byte_buf *cache_id) {
    void (*put_entry_for_encrypt)(
        struct aws_cryptosdk_materials_cache * cache,
        struct aws_cryptosdk_materials_cache_entry * *entry,
        const struct aws_cryptosdk_enc_materials *enc_materials,
        struct aws_cryptosdk_cache_usage_stats initial_usage,
        const struct aws_hash_table *enc_ctx,
        const struct aws_byte_buf *cache_id) = AWS_CRYPTOSDK_PRIVATE_VT_GET_NULL(cache->vt, put_entry_for_encrypt);

    *entry = NULL;
    if (put_entry_for_encrypt) {
        put_entry_for_encrypt(cache, entry, enc_materials, initial_usage, enc_ctx, cache_id);
    }
}

AWS_CRYPTOSDK_STATIC_INLINE
void aws_cryptosdk_materials_cache_put_entry_for_decrypt(
    struct aws_cryptosdk_materials_cache *cache,
    struct aws_cryptosdk_materials_cache_entry **entry,
    const struct aws_cryptosdk_dec_materials *dec_materials,
    const struct aws_byte_buf *cache_id) {
    void (*put_entry_for_decrypt)(
        struct aws_cryptosdk_materials_cache * cache,
        struct aws_cryptosdk_materials_cache_entry * *entry,
        const struct aws_cryptosdk_dec_materials *dec_materials,
        const struct aws_byte_buf *cache_id) = AWS_CRYPTOSDK_PRIVATE_VT_GET_NULL(cache->vt, put_entry_for_decrypt);

    *entry = NULL;
    if (put_entry_for_decrypt) {
        put_entry_for_decrypt(cache, entry, dec_materials, cache_id);
    }
}

AWS_CRYPTOSDK_STATIC_INLINE
void aws_cryptosdk_materials_cache_entry_release(
    struct aws_cryptosdk_materials_cache *cache, struct aws_cryptosdk_materials_cache_entry *entry, bool invalidate) {
    void (*entry_release)(
        struct aws_cryptosdk_materials_cache * cache,
        struct aws_cryptosdk_materials_cache_entry * entry,
        bool invalidate) = AWS_CRYPTOSDK_PRIVATE_VT_GET_NULL(cache->vt, entry_release);

    if (entry_release) {
        entry_release(cache, entry, invalidate);
    }
}

AWS_CRYPTOSDK_STATIC_INLINE
uint64_t aws_cryptosdk_materials_cache_entry_get_creation_time(
    const struct aws_cryptosdk_materials_cache *cache, const struct aws_cryptosdk_materials_cache_entry *entry) {
    uint64_t (*entry_get_creation_time)(
        const struct aws_cryptosdk_materials_cache *cache, const struct aws_cryptosdk_materials_cache_entry *entry) =
        AWS_CRYPTOSDK_PRIVATE_VT_GET_NULL(cache->vt, entry_get_creation_time);

    if (entry_get_creation_time) {
        return entry_get_creation_time(cache, entry);
    } else {
        return 0;
    }
}

AWS_CRYPTOSDK_STATIC_INLINE
void aws_cryptosdk_materials_cache_entry_ttl_hint(
    struct aws_cryptosdk_materials_cache *cache, struct aws_cryptosdk_materials_cache_entry *entry, uint64_t exp_time) {
    void (*entry_ttl_hint)(
        struct aws_cryptosdk_materials_cache * cache,
        struct aws_cryptosdk_materials_cache_entry * entry,
        uint64_t exp_time) = AWS_CRYPTOSDK_PRIVATE_VT_GET_NULL(cache->vt, entry_ttl_hint);

    if (entry_ttl_hint) {
        entry_ttl_hint(cache, entry, exp_time);
    }
}

#endif  // AWS_CRYPTOSDK_DOXYGEN (unstable APIs excluded from docs)

/**
 * Creates a new instance of the built-in local materials cache. This cache is thread safe, and uses a simple
 * LRU policy (with capacity shared between encrypt and decrypt) to evict entries.
 */
AWS_CRYPTOSDK_API
struct aws_cryptosdk_materials_cache *aws_cryptosdk_materials_cache_local_new(
    struct aws_allocator *alloc, size_t capacity);

/**
 * Returns an estimate of the number of entries in the cache. If a size estimate is not available,
 * returns SIZE_MAX.
 */
AWS_CRYPTOSDK_STATIC_INLINE
size_t aws_cryptosdk_materials_cache_entry_count(const struct aws_cryptosdk_materials_cache *cache) {
    size_t (*entry_count)(const struct aws_cryptosdk_materials_cache *cache) =
        AWS_CRYPTOSDK_PRIVATE_VT_GET_NULL(cache->vt, entry_count);

    if (!entry_count) {
        return SIZE_MAX;
    }

    return entry_count(cache);
}

/**
 * Attempts to clear all entries in the cache. This method is threadsafe, though any entries
 * being inserted in parallel with the clear operation may not end up being cleared.
 */
AWS_CRYPTOSDK_STATIC_INLINE
void aws_cryptosdk_materials_cache_clear(struct aws_cryptosdk_materials_cache *cache) {
    void (*clear)(struct aws_cryptosdk_materials_cache * cache) = AWS_CRYPTOSDK_PRIVATE_VT_GET_NULL(cache->vt, clear);

    if (clear) {
        clear(cache);
    }
}

/**
 * Increments the reference count on the materials cache
 */
AWS_CRYPTOSDK_STATIC_INLINE struct aws_cryptosdk_materials_cache *aws_cryptosdk_materials_cache_retain(
    struct aws_cryptosdk_materials_cache *materials_cache) {
    aws_cryptosdk_private_refcount_up(&materials_cache->refcount);
    return materials_cache;
}

/**
 * Decrements the reference count on the cache; if the new reference count is zero, the cache is destroyed.
 */
AWS_CRYPTOSDK_STATIC_INLINE void aws_cryptosdk_materials_cache_release(
    struct aws_cryptosdk_materials_cache *materials_cache) {
    if (materials_cache && aws_cryptosdk_private_refcount_down(&materials_cache->refcount)) {
        void (*destroy)(struct aws_cryptosdk_materials_cache * cache) =
            AWS_CRYPTOSDK_PRIVATE_VT_GET_NULL(materials_cache->vt, destroy);

        if (!destroy) {
            abort();
        }

        destroy(materials_cache);
    }
}

/**
 * Creates a new instance of the caching crypto materials manager. This CMM will intercept requests
 * for encrypt and decrypt materials, and forward them to the provided materials cache.
 *
 * If multiple caching CMMs are attached to the same materials_cache, they will share entries if and
 * only if the partition_id parameter is set to the same string. Unless you need to use this feature,
 * we recommend passing NULL, in which case the caching CMM will internally generate a random partition
 * ID to ensure it does not collide with any other CMM.
 *
 * Parameters:
 * @param alloc The allocator to use for the caching CMM itself (not for cache entries, however)
 * @param materials_cache The backing cache
 * @param upstream The upstream CMM to query on a cache miss
 * @param partition_id The partition ID to use to avoid collisions with other CMMs. This string need
 *                     not remain valid once this function returns. If NULL, a random partition ID will
 *                     be generated and used.
 * @param cache_limit_ttl The amount of time that a data key can be used for.
 * @param cache_limit_ttl_units The units of cache_limit_ttl. Allowable values are defined in
 *                              aws/common/clock.h
 */
AWS_CRYPTOSDK_API
struct aws_cryptosdk_cmm *aws_cryptosdk_caching_cmm_new_from_cmm(
    struct aws_allocator *alloc,
    struct aws_cryptosdk_materials_cache *materials_cache,
    struct aws_cryptosdk_cmm *upstream,
    const struct aws_byte_buf *partition_id,
    uint64_t cache_limit_ttl,
    enum aws_timestamp_unit cache_limit_ttl_units);

/**
 * Creates a new instance of the caching crypto materials manager. This CMM will intercept requests
 * for encrypt and decrypt materials, and forward them to the provided materials cache.
 *
 * If multiple caching CMMs are attached to the same materials_cache, they will share entries if and
 * only if the partition_id parameter is set to the same string. Unless you need to use this feature,
 * we recommend passing NULL, in which case the caching CMM will internally generate a random partition
 * ID to ensure it does not collide with any other CMM.
 *
 * Parameters:
 * @param alloc The allocator to use for the caching CMM itself (not for cache entries, however)
 * @param materials_cache The backing cache
 * @param keyring The keyring that will encrypt or decrypt data keys on a cache miss. This function
 *                uses a default CMM that is configured with the provided keyring as the upstream CMM.
 * @param partition_id The partition ID to use to avoid collisions with other CMMs. This string need
 *                     not remain valid once this function returns. If NULL, a random partition ID will
 *                     be generated and used.
 * @param cache_limit_ttl The amount of time that a data key can be used for.
 * @param cache_limit_ttl_units The units of cache_limit_ttl. Allowable values are defined in
 *                              aws/common/clock.h
 */
AWS_CRYPTOSDK_API
struct aws_cryptosdk_cmm *aws_cryptosdk_caching_cmm_new_from_keyring(
    struct aws_allocator *alloc,
    struct aws_cryptosdk_materials_cache *materials_cache,
    struct aws_cryptosdk_keyring *keyring,
    const struct aws_byte_buf *partition_id,
    uint64_t cache_limit_ttl,
    enum aws_timestamp_unit cache_limit_ttl_units);

/**
 * Configures the amount of time that a data key can be used for. This value must be greater than zero.
 */
AWS_CRYPTOSDK_API
int aws_cryptosdk_caching_cmm_set_ttl(struct aws_cryptosdk_cmm *cmm, uint64_t ttl, enum aws_timestamp_unit ttl_units);

/**
 * Configures the maximum number of bytes that may be encrypted by a single data key.
 * This value has a maximum of 2^63 - 1 (i.e., INT64_MAX, *not* UINT64_MAX)
 */
AWS_CRYPTOSDK_API
int aws_cryptosdk_caching_cmm_set_limit_bytes(struct aws_cryptosdk_cmm *cmm, uint64_t limit_bytes);

/**
 * Configures the maximum number of messages that may be encrypted by a single data key.
 * This value cannot be zero and has a maximum of 2^32 (i.e., AWS_CRYPTOSDK_CACHE_MAX_LIMIT_MESSAGES)
 */
AWS_CRYPTOSDK_API
int aws_cryptosdk_caching_cmm_set_limit_messages(struct aws_cryptosdk_cmm *cmm, uint64_t limit_messages);

AWS_EXTERN_C_END

/** @} */  // doxygen group caching

#endif
