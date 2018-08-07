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

#include <aws/cryptosdk/materials.h>

struct aws_cryptosdk_cache_usage_stats {
    uint64_t bytes_encrypted, messages_encrypted;
};

/**
 * The backing materials cache that stores the cached materials for one or more caching CMMs.
 */
struct aws_cryptosdk_matcache {
    const struct aws_cryptosdk_matcache_vt *vt;
};

/**
 * An encrypt cache entry; this entry has an internal reference count, to allow for it to be
 * invalidated while other threads are still working to copy data out of the entry.
 */
struct aws_cryptosdk_cache_encrypt_entry {
    const struct aws_cryptosdk_cache_encrypt_entry_vt *vt;
};

/**
 * A decrypt cache entry; this entry has an internal reference count, to allow for it to be
 * invalidated while other threads are still working to copy data out of the entry.
 */
struct aws_cryptosdk_cache_decrypt_entry {
    const struct aws_cryptosdk_cache_encrypt_entry_vt *vt;
};

struct aws_cryptosdk_matcache_vt {
    /**
     * Must be set to sizeof(struct aws_cryptosdk_matcache_vt)
     */
    size_t vt_size;
    
    /**
     * Identifier for debugging purposes
     */
    const char *name;

    /** 
     * Attempts to find an entry in the encrypt cache. If found, adds a
     * reference to the entry's refcount and returns the entry in *entry;
     * otherwise, sets *entry to NULL.
     * 
     * As part of finding the entry, this method will increment the entry's
     * usage by usage_stats; if this would result in exceeding the usage limit,
     * the entry is invalidated and not returned.
     * 
     * Parameters:
     * 
     * @param cache - The cache to perform the lookup against
     * @param cache_id - The cache identifier to look up.
     * @param entry - Out-parameter that receives the encrypt entry, if found
     * @param usage_stats - Amount to increment usage stats by
     */

    int get_entry_for_encrypt(
        struct aws_cryptosdk_matcache *cache,
        const struct aws_byte_buf *cache_id,
        struct aws_cryptosdk_cache_encrypt_entry **entry,
        struct aws_cryptosdk_cache_usage_stats usage_stats
    );

    /**
     * Attempts to put a copy of *materials into the encrypt cache, under the
     * given cache ID, and with the specified initial usage.
     * 
     * If this method fails for any reason, the entry is simply not added to the cache.
     * 
     * Parameters:
     * @param cache - The cache to insert into
     * @param cache_id - The cache identifier to insert into
     * @param materials - The encryption materials to insert; a copy will be
     * made using the cache's allocator
     * @param expected_expiry - A hint that recommends to the cache that the entry be
     * discarded shortly after the specified timestamp. The cache might still return
     * it after this time.
     * @param initial_usage - The usage stats to initially record against this cache entry
     */ 
    void put_entry_for_encrypt(
        struct aws_cryptosdk_matcache *cache,
        const struct aws_byte_buf *cache_id,
        const struct aws_cryptosdk_encryption_materials *materials,
        uint64_t expected_expiry,
        struct aws_cryptosdk_cache_usage_stats initial_usage
    );

    /** 
     * Attempts to find an entry in the decrypt cache. If found, adds a
     * reference to the entry's refcount and returns the entry in *entry;
     * otherwise, sets *entry to NULL.
     * 
     * Parameters:
     * 
     * @param cache - The cache to perform the lookup against
     * @param cache_id - The cache identifier to look up.
     * @param entry - Out-parameter that receives the encrypt entry, if found
     */
    int get_entry_for_decrypt(
        struct aws_cryptosdk_matcache *cache,
        const struct aws_byte_buf *cache_id,
        struct aws_cryptosdk_cache_decrypt_entry **entry
    );

    /**
     * Attempts to put a copy of *materials into the decrypt cache, under the
     * given cache ID.
     * 
     * If this method fails for any reason, the entry is simply not added to the cache.
     * 
     * Parameters:
     * @param cache - The cache to insert into
     * @param cache_id - The cache identifier to insert into
     * @param materials - The encryption materials to insert; a copy will be
     * made using the cache's allocator
     * @param expected_expiry - A hint that recommends to the cache that the entry be
     * discarded shortly after the specified timestamp. The cache might still return
     * it after this time.
     */ 
    int put_entry_for_decrypt(
        struct aws_cryptosdk_matcache *cache,
        const struct aws_byte_buf *cache_id,
        const struct aws_cryptosdk_decryption_materials *materials,
        uint64_t expected_expiry
    );

    /**
     * Destroys the cache. Note that any cache entry objects that have references outstanding
     * will not be destroyed until those references are released.
     */
    void destroy(struct aws_cryptosdk_matcache *cache);
    /**
     * Returns an estimate of the number of entries in the cache.
     */
    size_t entry_count(struct aws_cryptosdk_matcache *cache);
};

struct aws_cryptosdk_cache_encrypt_entry_vt {
    /**
     * Must be set to sizeof(struct aws_cryptosdk_cache_encrypt_entry_vt)
     */
    size_t vt_size;
    
    /**
     * Identifier for debugging purposes
     */
    const char *name;

    /**
     * Increments the reference count of this entry.
     */
    void (*addref)(struct aws_cryptosdk_cache_encrypt_entry *entry);

    /**
     * Decrements the reference count of this entry. This may result in the entry being freed.
     */
    void (*release)(struct aws_cryptosdk_cache_encrypt_entry *entry);

    /**
     * Signals to the cache that this entry should be invalidated and removed from the cache.
     * The entry structure remains valid until any remaining references are released.
     */
    void (*invalidate)(struct aws_cryptosdk_cache_encrypt_entry *entry);

    /**
     * Returns a copy of the materials in this cache entry, allocated using the specified allocator.
     * 
     * @returns AWS_OP_SUCCESS or raises an error and returns AWS_OP_ERR
     */
    int (*get_materials)(
        struct aws_cryptosdk_cache_encrypt_entry *entry,
        struct aws_allocator *allocator,
        struct aws_cryptosdk_encryption_materials *out_materials
    );

    /**
     * Returns the usage stats recorded against this cache entry.
     * 
     * @returns AWS_OP_SUCCESS or raises an error and returns AWS_OP_ERR
     */
    int (*get_usage)(struct aws_cryptosdk_cache_encrypt_entry *entry, struct aws_cryptosdk_cache_usage_stats *stats);

    /**
     * Returns the creation timestamp for this cache entry.
     */
    uint64_t (*get_creation_time)(struct aws_cryptosdk_cache_encrypt_entry *entry);
};

struct aws_cryptosdk_cache_decrypt_entry_vt {
    /**
     * Must be set to sizeof(struct aws_cryptosdk_cache_encrypt_entry_vt)
     */
    size_t vt_size;
    
    /**
     * Identifier for debugging purposes
     */
    const char *name;

    /**
     * Increments the reference count of this entry.
     */
    void (*addref)(struct aws_cryptosdk_cache_encrypt_entry *entry);

    /**
     * Decrements the reference count of this entry. This may result in the entry being freed.
     */
    void (*release)(struct aws_cryptosdk_cache_encrypt_entry *entry);

    /**
     * Signals to the cache that this entry should be invalidated and removed from the cache.
     * The entry structure remains valid until any remaining references are released.
     */
    void (*invalidate)(struct aws_cryptosdk_cache_encrypt_entry *entry);

    /**
     * Returns a copy of the materials in this cache entry, allocated using the specified allocator.
     * 
     * @returns AWS_OP_SUCCESS or raises an error and returns AWS_OP_ERR
     */
    int (*get_materials)(
        struct aws_cryptosdk_cache_encrypt_entry *entry,
        struct aws_allocator *allocator,
        struct aws_cryptosdk_encryption_materials *out_materials
    );

    /**
     * Returns the creation timestamp for this cache entry.
     */
    uint64_t (*get_creation_time)(struct aws_cryptosdk_cache_encrypt_entry *entry);
};

/**
 * Creates a new instance of the built-in local materials cache. This cache is thread safe, and uses a simple
 * LRU policy (with capacity shared between encrypt and decrypt) to evict entries.
 */
struct aws_cryptosdk_matcache *aws_cryptosdk_matcache_local_new(
    struct aws_allocator *alloc,
    size_t capacity
);

/**
 * Creates a new instance of the cachine crypto materials manager. This CMM will intercept requests for encrypt
 * and decrypt materials, and forward them to the provided materials cache.
 * 
 * If multiple caching CMMs are attached to the same matcache, they will share entries if and only if the partition_id
 * parameter is set to the same string. Unless you need to use this feature, we recommend passing NULL, in which case
 * the caching CMM will internally generate a random partition ID to ensure it does not collide with any other CMM.
 * 
 * Parameters:
 * @param alloc - The allocator to use for the caching CMM itself (not for cache entries, however)
 * @param matcache - The backing cache
 * @param upstream - The upstream CMM to query on a cache miss
 * @param partition_id - The partition ID to use to avoid collisions with other CMMs.
 */
struct aws_cryptosdk_cmm *aws_cryptosdk_caching_cmm_new(
    struct aws_allocator *alloc,
    struct aws_cryptosdk_matcache *matcache,
    struct aws_cryptosdk_cmm *upstream,
    const struct aws_byte_buf *partition_id
);



#endif