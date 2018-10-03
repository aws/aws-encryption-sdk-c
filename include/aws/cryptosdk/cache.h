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
struct aws_cryptosdk_mat_cache_entry {
    const struct aws_cryptosdk_mat_cache_entry_vt *vt;
};

struct aws_cryptosdk_mat_cache_entry_vt {
    /**
     * Must be set to sizeof(struct aws_cryptosdk_mat_cache_entry_vt)
     */
    size_t vt_size;
    
    /**
     * Identifier for debugging purposes
     */
    const char *name;

    /**
     * Releases this handle. If invalidate is true, _attempts_ to invalidate the cache entry.
     */
    void (*release)(struct aws_cryptosdk_mat_cache_entry *entry, bool invalidate);

    /**
     * Gets the creation timestamp for this entry, in nanoseconds since the unix epoch.
     */
    uint64_t (*get_creation_time)(struct aws_cryptosdk_mat_cache_entry *entry);

    /**
     * Advises the cache that this entry is not useful after the specified timestamp.
     * The cache may (but is not required to) actively expire the entry after this timestamp,
     * to free up space for other entries.
     */
    void (*set_expiration_hint)(struct aws_cryptosdk_mat_cache_entry *entry, uint64_t expiration_time);
};

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
     * 
     * As part of finding the entry, this method will atomically increment the entry's
     * usage by *usage_stats; the updated usage stats are then returned in *usage_stats
     * 
     * Parameters:
     * 
     * @param cache - The cache to perform the lookup against
     * @param entry - Out-parameter that receives a handle to the cache entry, if found
     * @param materials - Out-parameter that receives the encryption materials, if found
     * @param cache_id - The cache identifier to look up.
     * @param usage_stats - Amount to increment usage stats by; receives final usage stats
     *                      after addition.
     */

    int (*get_entry_for_encrypt)(
        struct aws_cryptosdk_mat_cache *cache,
        struct aws_cryptosdk_mat_cache_entry **entry,
        struct aws_cryptosdk_encryption_materials *materials,
        const struct aws_byte_buf *cache_id,
        struct aws_cryptosdk_cache_usage_stats *usage_stats
    );

    /**
     * Attempts to put a copy of *materials into the encrypt cache, under the
     * given cache ID, and with the specified initial usage.
     * 
     * If this method fails for any reason, the entry is simply not added to the cache.
     * 
     * Parameters:
     * @param cache - The cache to insert into
     * @param entry - Out-parameter which receives a handle to the created cache entry.
     *                On failure, *entry will be set to NULL.
     * @param cache_id - The cache identifier to insert into
     * @param materials - The encryption materials to insert; a copy will be
     * made using the cache's allocator
     * @param initial_usage - The usage stats to initially record against this cache entry
     */ 
    void (*put_entry_for_encrypt)(
        struct aws_cryptosdk_mat_cache *cache,
        struct aws_cryptosdk_mat_cache_entry **entry,
        const struct aws_byte_buf *cache_id,
        const struct aws_cryptosdk_encryption_materials *materials,
        struct aws_cryptosdk_cache_usage_stats initial_usage
    );

    /** 
     * Attempts to find an entry in the decrypt cache. If found, returns a handle to the
     * cache entry in *entry, and the decryption materials in *materials.
     * 
     * Parameters:
     * 
     * @param cache - The cache to perform the lookup against
     * @param entry - Out-parameter that receives the cache entry, if found
     * @param materials - Out-parameter that receives the decryption materials, if found.
     * @param cache_id - The cache identifier to look up.
     */
    int (*get_entry_for_decrypt)(
        struct aws_cryptosdk_mat_cache *cache,
        struct aws_cryptosdk_mat_cache_entry **entry,
        struct aws_cryptosdk_decryption_materials *materials,
        const struct aws_byte_buf *cache_id
    );

    /**
     * Attempts to put a copy of *materials into the decrypt cache, under the
     * given cache ID.
     * 
     * If this method fails for any reason, the entry is simply not added to the cache.
     * 
     * Parameters:
     * @param cache - The cache to insert into
     * @param entry - Out-parameter that receives the cache entry, if found
     * @param cache_id - The cache identifier to insert into
     * @param materials - The encryption materials to insert; a copy will be
     * made using the cache's allocator
     */ 
    int (*put_entry_for_decrypt)(
        struct aws_cryptosdk_mat_cache *cache,
        struct aws_cryptosdk_mat_cache_entry **entry,
        const struct aws_byte_buf *cache_id,
        const struct aws_cryptosdk_decryption_materials *materials
    );

    /**
     * Invoked when the materials cache reference count reaches zero. 
     * 
     * Implementation note: Implementations of this function must ensure that any outstanding
     * cache entry handles remain valid (however, mutating operations may become no-ops) before
     * the cache is destroyed. This may be accomplished by incrementing the reference count of the
     * underlying mat_cache object for each outstanding cache entry, or it may otherwise be accomplished
     * by ensuring that the cache entry objects remain usable in some other manner.
     */
    void (*destroy)(struct aws_cryptosdk_mat_cache *cache);

    /**
     * Returns an estimate of the number of entries in the cache. If a size estimate is not available,
     * returns SIZE_MAX.
     */
    size_t (*entry_count)(struct aws_cryptosdk_mat_cache *cache);
};

/**
 * Creates a new instance of the built-in local materials cache. This cache is thread safe, and uses a simple
 * LRU policy (with capacity shared between encrypt and decrypt) to evict entries.
 */
struct aws_cryptosdk_mat_cache *aws_cryptosdk_mat_cache_local_new(
    struct aws_allocator *alloc,
    size_t capacity
);

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