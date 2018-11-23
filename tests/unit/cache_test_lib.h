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

#ifndef CACHE_TEST_LIB_H
#define CACHE_TEST_LIB_H

#include <aws/cryptosdk/materials.h>

/*
 * This mock materials cache is designed to ease testing the caching CMM
 * by emulating a cache with a single entry.
 * 
 * When encryption materials are put into the cache, the cache will
 * update its state (enc/dec_materials, encryption_context, usage_stats,
 * last_cache_id) to match the inserted materials.
 * 
 * When an entry is looked up, the cache will simulate a cache hit if
 * should_hit is true; last_cache_it will be set to the ID that was queried.
 * When the entry is queried for usage stats, creation time, or the
 * actual materials, the appropriate fields from the mock cache will be
 * returned and/or updated.
 */
struct mock_mat_cache {
    struct aws_cryptosdk_mat_cache base;
    struct aws_allocator *alloc;

    /* 
     * The entry pointer returned from cache vtable methods points to this
     * entry_marker field. The value of the field is ignored; we just use
     * this to assert that the correct entry pointer is being passed around.
     */
    uint8_t entry_marker;
    /* True if find_entry should find a cache hit */
    bool should_hit;
    /* True if the call should be made to fail */
    bool should_fail;

    /* 
     * Encryption materials for the cached entry; updated on put_entry_for_encrypt,
     * read on get_encryption_materials. If NULL, get_encryption_materials fails.
     */
    struct aws_cryptosdk_encryption_materials *enc_materials;
    /* 
     * Encryption materials for the cached entry; updated on put_entry_for_decrypt,
     * read on get_decryption_materials. If NULL, get_decryption_materials fails.
     */
    struct aws_cryptosdk_decryption_materials *dec_materials;
    /*
     * Encryption context for the cached entry; updated on put_entry_for_encrypt,
     * read on get_encryption_materials.
     * TODO: Does this need to be used for decrypt entries as well?
     */
    struct aws_hash_table encryption_context;
    /*
     * Usage stats for the cached entry. Set on put_entry_for_encrypt;
     * read and updated on update_usage_stats
     */
    struct aws_cryptosdk_cache_usage_stats usage_stats;

    /*
     * Contains the last cache ID passed to any function that takes a cache ID
     */
    struct aws_byte_buf last_cache_id;

    /*
     * The creation time for the current cache entry. Returned from entry_creation_time.
     */ 
    uint64_t entry_creation_time;
    /*
     * The expiration time for the current cache entry. Set by entry_ttl_hint.
     */ 
    uint64_t entry_ttl_hint;
    /*
     * True if entry_release has been called with invalidate = true.
     */
    bool invalidated;
    /*
     * Outstanding reference count for the entry.
     */
    size_t entry_refcount;
};

struct mock_upstream_cmm {
    struct aws_cryptosdk_cmm base;
    struct aws_allocator *alloc;

    /* Parameters for the returned test materials */
    int materials_index;
    enum aws_cryptosdk_alg_id returned_alg;
    int n_edks;
    /*
     * Contains the last public key generated on a generate materials or decrypt materials mock request.
     */
    struct aws_string *last_pubkey;

    /* Last request pointer passed in */
    struct aws_cryptosdk_encryption_request *last_enc_request;
    struct aws_cryptosdk_decryption_request *last_dec_request;
};

void gen_enc_materials(struct aws_allocator *alloc, struct aws_cryptosdk_encryption_materials **p_materials, int index, enum aws_cryptosdk_alg_id alg, int n_edks);
bool materials_eq(const struct aws_cryptosdk_encryption_materials *a, const struct aws_cryptosdk_encryption_materials *b);
bool same_signing_key(struct aws_cryptosdk_signctx *a, struct aws_cryptosdk_signctx *b);
bool dec_materials_eq(const struct aws_cryptosdk_decryption_materials *a, const struct aws_cryptosdk_decryption_materials *b);

struct mock_mat_cache *mock_mat_cache_new(struct aws_allocator *alloc);
struct mock_upstream_cmm *mock_upstream_cmm_new(struct aws_allocator *alloc);

#endif