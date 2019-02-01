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

#include <aws/common/byte_buf.h>
#include <aws/common/linked_list.h> /* AWS_CONTAINER_OF */
#include <aws/common/math.h>
#include <aws/cryptosdk/cache.h>
#include <aws/cryptosdk/enc_ctx.h>
#include <aws/cryptosdk/private/cipher.h>
#include <aws/cryptosdk/private/enc_ctx.h>

struct caching_cmm {
    struct aws_cryptosdk_cmm base;
    struct aws_allocator *alloc;
    struct aws_cryptosdk_cmm *upstream;
    struct aws_cryptosdk_materials_cache *materials_cache;
    struct aws_string *partition_id;

    int (*clock_get_ticks)(uint64_t *now);

    uint64_t limit_messages, limit_bytes, ttl_nanos;
};

static void destroy_caching_cmm(struct aws_cryptosdk_cmm *generic_cmm);
static int generate_enc_materials(
    struct aws_cryptosdk_cmm *cmm,
    struct aws_cryptosdk_enc_materials **output,
    struct aws_cryptosdk_enc_request *request);
static int decrypt_materials(
    struct aws_cryptosdk_cmm *cmm,
    struct aws_cryptosdk_dec_materials **output,
    struct aws_cryptosdk_dec_request *request);
static const struct aws_cryptosdk_cmm_vt caching_cmm_vt = { .vt_size                = sizeof(caching_cmm_vt),
                                                            .name                   = "Caching CMM",
                                                            .destroy                = destroy_caching_cmm,
                                                            .generate_enc_materials = generate_enc_materials,
                                                            .decrypt_materials      = decrypt_materials };

static void destroy_caching_cmm(struct aws_cryptosdk_cmm *generic_cmm) {
    struct caching_cmm *cmm = AWS_CONTAINER_OF(generic_cmm, struct caching_cmm, base);

    aws_string_destroy(cmm->partition_id);
    aws_cryptosdk_materials_cache_release(cmm->materials_cache);
    aws_cryptosdk_cmm_release(cmm->upstream);
    aws_mem_release(cmm->alloc, cmm);
}

static bool can_cache_algorithm(enum aws_cryptosdk_alg_id alg_id) {
    const struct aws_cryptosdk_alg_properties *props = aws_cryptosdk_alg_props(alg_id);

    /* TODO: Better name for this property? */
    return props->md_name != NULL;
}

AWS_CRYPTOSDK_TEST_STATIC
struct aws_string *hash_or_generate_partition_id(
    struct aws_allocator *alloc, const struct aws_byte_buf *partition_name) {
    uint8_t tmparr[AWS_CRYPTOSDK_MD_MAX_SIZE];

    if (partition_name) {
        struct aws_cryptosdk_md_context *md_context = NULL;

        if (aws_cryptosdk_md_init(alloc, &md_context, AWS_CRYPTOSDK_MD_SHA512) ||
            aws_cryptosdk_md_update(md_context, partition_name->buffer, partition_name->len)) {
            aws_cryptosdk_md_abort(md_context);
            return NULL;
        }

        size_t len;
        if (aws_cryptosdk_md_finish(md_context, tmparr, &len)) {
            return NULL;
        }

        return aws_string_new_from_array(alloc, tmparr, len);
    } else {
        /*
         * Note that other SDKs generate a UUID and hash the UUID, but this is equivalent
         * to simply generating a random internal partition ID, as it's not possible to reverse
         * the hash to find the original UUID.
         */
        if (aws_cryptosdk_genrandom(tmparr, sizeof(tmparr))) {
            return NULL;
        }
        return aws_string_new_from_array(alloc, tmparr, sizeof(tmparr));
    }
}

AWS_CRYPTOSDK_TEST_STATIC
void caching_cmm_set_clock(struct aws_cryptosdk_cmm *generic_cmm, int (*clock_get_ticks)(uint64_t *now)) {
    struct caching_cmm *cmm = AWS_CONTAINER_OF(generic_cmm, struct caching_cmm, base);

    cmm->clock_get_ticks = clock_get_ticks;
}

int aws_cryptosdk_caching_cmm_set_limit_bytes(struct aws_cryptosdk_cmm *generic_cmm, uint64_t limit_bytes) {
    struct caching_cmm *cmm = AWS_CONTAINER_OF(generic_cmm, struct caching_cmm, base);
    if (generic_cmm->vtable != &caching_cmm_vt) {
        return aws_raise_error(AWS_ERROR_UNSUPPORTED_OPERATION);
    }

    if (limit_bytes > INT64_MAX) {
        return aws_raise_error(AWS_ERROR_INVALID_ARGUMENT);
    }

    cmm->limit_bytes = limit_bytes;
    return AWS_OP_SUCCESS;
}

int aws_cryptosdk_caching_cmm_set_limit_messages(struct aws_cryptosdk_cmm *generic_cmm, uint64_t limit_messages) {
    struct caching_cmm *cmm = AWS_CONTAINER_OF(generic_cmm, struct caching_cmm, base);
    if (generic_cmm->vtable != &caching_cmm_vt) {
        return aws_raise_error(AWS_ERROR_UNSUPPORTED_OPERATION);
    }

    if (!limit_messages || limit_messages > AWS_CRYPTOSDK_CACHE_MAX_LIMIT_MESSAGES) {
        return aws_raise_error(AWS_ERROR_INVALID_ARGUMENT);
    }

    cmm->limit_messages = limit_messages;
    return AWS_OP_SUCCESS;
}

/* Returns zero if any of the arguments have invalid values
 * and returns UINT64_MAX if there would be an overflow.
 */
AWS_CRYPTOSDK_TEST_STATIC
uint64_t convert_ttl_to_nanos(uint64_t ttl, enum aws_timestamp_unit ttl_units) {
    if (!ttl || (ttl_units != AWS_TIMESTAMP_SECS && ttl_units != AWS_TIMESTAMP_MILLIS &&
                 ttl_units != AWS_TIMESTAMP_MICROS && ttl_units != AWS_TIMESTAMP_NANOS)) {
        return 0UL;
    }
    return aws_mul_u64_saturating(AWS_TIMESTAMP_NANOS / ttl_units, ttl);
}

int aws_cryptosdk_caching_cmm_set_ttl(
    struct aws_cryptosdk_cmm *generic_cmm, uint64_t ttl, enum aws_timestamp_unit ttl_units) {
    struct caching_cmm *cmm = AWS_CONTAINER_OF(generic_cmm, struct caching_cmm, base);
    if (generic_cmm->vtable != &caching_cmm_vt) {
        return aws_raise_error(AWS_ERROR_UNSUPPORTED_OPERATION);
    }

    uint64_t ttl_nanos = convert_ttl_to_nanos(ttl, ttl_units);
    if (!ttl_nanos) return aws_raise_error(AWS_ERROR_INVALID_ARGUMENT);

    cmm->ttl_nanos = ttl_nanos;
    return AWS_OP_SUCCESS;
}

struct aws_cryptosdk_cmm *aws_cryptosdk_caching_cmm_new(
    struct aws_allocator *alloc,
    struct aws_cryptosdk_materials_cache *materials_cache,
    struct aws_cryptosdk_cmm *upstream,
    const struct aws_byte_buf *partition_name,
    uint64_t ttl,
    enum aws_timestamp_unit ttl_units) {
    uint64_t ttl_nanos = convert_ttl_to_nanos(ttl, ttl_units);
    if (!ttl_nanos) {
        aws_raise_error(AWS_ERROR_INVALID_ARGUMENT);
        return NULL;
    }

    struct aws_string *partition_id_str = hash_or_generate_partition_id(alloc, partition_name);

    if (!partition_id_str) {
        return NULL;
    }

    struct caching_cmm *cmm = aws_mem_acquire(alloc, sizeof(*cmm));
    if (!cmm) {
        return NULL;
    }

    aws_cryptosdk_cmm_base_init(&cmm->base, &caching_cmm_vt);

    cmm->alloc           = alloc;
    cmm->upstream        = aws_cryptosdk_cmm_retain(upstream);
    cmm->materials_cache = aws_cryptosdk_materials_cache_retain(materials_cache);
    cmm->partition_id    = partition_id_str;

    // We use the test helper here just to ensure we don't get unused static function warnings
    caching_cmm_set_clock(&cmm->base, aws_sys_clock_get_ticks);

    cmm->limit_messages = AWS_CRYPTOSDK_CACHE_MAX_LIMIT_MESSAGES;
    cmm->limit_bytes    = INT64_MAX;
    cmm->ttl_nanos      = ttl_nanos;

    return &cmm->base;
}

/*
 * Checks the TTL on the entry given. Returns true if the TTL has not yet expired, or false if it has expired.
 * Additionally, sets the TTL hint on the entry if it has not expired.
 */
static bool check_ttl(struct caching_cmm *cmm, struct aws_cryptosdk_materials_cache_entry *entry) {
    if (cmm->ttl_nanos == UINT64_MAX) {
        /* Entries never expire, because their expiration time is beyond the maximum time we can represent */
        return true;
    }

    uint64_t creation_time = aws_cryptosdk_materials_cache_entry_get_creation_time(cmm->materials_cache, entry);
    uint64_t expiration    = creation_time + cmm->ttl_nanos;
    uint64_t now;

    if (expiration < creation_time) {
        /*
         * The add overflowed, so the expiration time is so far out that we can't represent it.
         * Therefore, it will never expire.
         */
        return true;
    }

    if (cmm->clock_get_ticks(&now) || now >= expiration) {
        return false;
    }

    aws_cryptosdk_materials_cache_entry_ttl_hint(cmm->materials_cache, entry, expiration);

    return true;
}

AWS_CRYPTOSDK_TEST_STATIC
int hash_enc_request(
    struct aws_string *partition_id, struct aws_byte_buf *out, const struct aws_cryptosdk_enc_request *req) {
    /*
     * Here, we hash the relevant aspects of the request structure to use as a cache identifier.
     * The hash is intended to match Java and Python, but since we've not yet committed to maintaining
     * that parity indefinitely, we don't include this structure as part of the header API docs.
     * The structure, internally, is:
     *   [partition ID hash]
     *   [0x01 if the request alg id is set, otherwise 0x00]
     *   [request alg id, if set]
     *   [serialized encryption context]
     */
    struct aws_byte_buf context_buf              = { 0 };
    uint8_t digestbuf[AWS_CRYPTOSDK_MD_MAX_SIZE] = { 0 };

    if (out->capacity < AWS_CRYPTOSDK_MD_MAX_SIZE) {
        return aws_raise_error(AWS_ERROR_INVALID_BUFFER_SIZE);
    }

    struct aws_cryptosdk_md_context *md_context, *enc_ctx_md;
    if (aws_cryptosdk_md_init(req->alloc, &md_context, AWS_CRYPTOSDK_MD_SHA512)) {
        return AWS_OP_ERR;
    }

    if (aws_cryptosdk_md_init(req->alloc, &enc_ctx_md, AWS_CRYPTOSDK_MD_SHA512)) {
        return AWS_OP_ERR;
    }

    if (aws_cryptosdk_md_update(md_context, aws_string_bytes(partition_id), partition_id->len)) {
        goto md_err;
    }

    uint8_t requested_alg_present = req->requested_alg != 0;
    if (aws_cryptosdk_md_update(md_context, &requested_alg_present, 1)) {
        goto md_err;
    }

    if (requested_alg_present) {
        uint16_t alg_id = aws_hton16(req->requested_alg);
        if (aws_cryptosdk_md_update(md_context, &alg_id, sizeof(alg_id))) {
            goto md_err;
        }
    }

    size_t context_size;
    if (aws_cryptosdk_enc_ctx_size(&context_size, req->enc_ctx) ||
        aws_byte_buf_init(&context_buf, req->alloc, context_size) ||
        aws_cryptosdk_enc_ctx_serialize(req->alloc, &context_buf, req->enc_ctx) ||
        aws_cryptosdk_md_update(enc_ctx_md, context_buf.buffer, context_buf.len)) {
        goto md_err;
    }

    size_t enc_ctx_digest_len;
    if (aws_cryptosdk_md_finish(enc_ctx_md, digestbuf, &enc_ctx_digest_len)) {
        enc_ctx_md = NULL;
        goto md_err;
    }
    enc_ctx_md = NULL;

    if (aws_cryptosdk_md_update(md_context, digestbuf, enc_ctx_digest_len)) {
        goto md_err;
    }

    aws_byte_buf_clean_up(&context_buf);
    return aws_cryptosdk_md_finish(md_context, out->buffer, &out->len);

md_err:
    aws_byte_buf_clean_up(&context_buf);
    aws_cryptosdk_md_abort(md_context);
    aws_cryptosdk_md_abort(enc_ctx_md);

    return AWS_OP_ERR;
}

struct edk_hash_entry {
    uint8_t hash_data[AWS_CRYPTOSDK_MD_MAX_SIZE];
};

static int edk_hash_entry_cmp(const void *vp_a, const void *vp_b) {
    const struct edk_hash_entry *a = vp_a, *b = vp_b;

    return memcmp(a->hash_data, b->hash_data, sizeof(a->hash_data));
}

static int hash_edk_field(struct aws_cryptosdk_md_context *md_context, const struct aws_byte_buf *field) {
    uint16_t field_len;

    if (field->len > UINT16_MAX) {
        return aws_raise_error(AWS_CRYPTOSDK_ERR_LIMIT_EXCEEDED);
    }

    field_len = aws_ntoh16(field->len);
    if (aws_cryptosdk_md_update(md_context, &field_len, sizeof(field_len)) ||
        aws_cryptosdk_md_update(md_context, field->buffer, field->len)) {
        return AWS_OP_ERR;
    }

    return AWS_OP_SUCCESS;
}

AWS_CRYPTOSDK_TEST_STATIC
int hash_edk_for_decrypt(
    struct aws_allocator *alloc, struct edk_hash_entry *entry, const struct aws_cryptosdk_edk *edk) {
    struct aws_cryptosdk_md_context *md_context = NULL;
    if (aws_cryptosdk_md_init(alloc, &md_context, AWS_CRYPTOSDK_MD_SHA512)) {
        return AWS_OP_ERR;
    }

    if (hash_edk_field(md_context, &edk->provider_id) || hash_edk_field(md_context, &edk->provider_info) ||
        hash_edk_field(md_context, &edk->ciphertext)) {
        aws_cryptosdk_md_abort(md_context);
        return AWS_OP_ERR;
    }

    memset(entry->hash_data, 0, sizeof(entry->hash_data));

    size_t ignored_length;
    return aws_cryptosdk_md_finish(md_context, entry->hash_data, &ignored_length);
}

AWS_CRYPTOSDK_TEST_STATIC
int hash_dec_request(
    const struct aws_string *partition_id, struct aws_byte_buf *out, const struct aws_cryptosdk_dec_request *req) {
    static const struct edk_hash_entry zero_entry = { { 0 } };

    int rv             = AWS_OP_ERR;
    size_t md_length   = aws_cryptosdk_md_size(AWS_CRYPTOSDK_MD_SHA512);
    uint16_t alg_id_be = aws_hton16(req->alg);

    struct aws_byte_buf context_buf                       = { 0 };
    uint8_t context_digest_arr[AWS_CRYPTOSDK_MD_MAX_SIZE] = { 0 };
    struct aws_byte_buf context_digest_buf = aws_byte_buf_from_array(context_digest_arr, sizeof(context_digest_arr));
    struct aws_cryptosdk_md_context *md_context = NULL;
    struct aws_array_list edk_hash_list;

    if (out->capacity < AWS_CRYPTOSDK_MD_MAX_SIZE) {
        return aws_raise_error(AWS_ERROR_INVALID_BUFFER_SIZE);
    }

    if (aws_array_list_init_dynamic(
            &edk_hash_list,
            req->alloc,
            aws_array_list_length(&req->encrypted_data_keys),
            sizeof(struct edk_hash_entry))) {
        return AWS_OP_ERR;
    }

    size_t context_size;
    if (aws_cryptosdk_md_init(req->alloc, &md_context, AWS_CRYPTOSDK_MD_SHA512) ||
        aws_cryptosdk_enc_ctx_size(&context_size, req->enc_ctx) ||
        aws_byte_buf_init(&context_buf, req->alloc, context_size) ||
        aws_cryptosdk_enc_ctx_serialize(req->alloc, &context_buf, req->enc_ctx) ||
        aws_cryptosdk_md_update(md_context, context_buf.buffer, context_buf.len)) {
        goto err;
    }

    if (aws_cryptosdk_md_finish(md_context, context_digest_buf.buffer, &context_digest_buf.len)) {
        md_context = NULL;
        goto err;
    }

    // The decryption request cache IDs are constructed out of a hash of:
    // [partition ID]
    // [algorithm ID]
    // [EDK hashes, in sorted order]
    // [digestLength zero bytes]
    // [encryption context hash]

    // Before we start hashing the top level stuff, let's hash the EDKs and sort them
    // Note that the EDK entries have no length field - if we introduce a larger hash
    // in the future, we just treat the smaller (?) SHA-512 as the top-order bits of
    // a larger field.

    size_t n_edks = aws_array_list_length(&req->encrypted_data_keys);
    for (size_t i = 0; i < n_edks; i++) {
        struct edk_hash_entry entry;
        const struct aws_cryptosdk_edk *edk = NULL;
        void *vp_edk                        = NULL;

        if (aws_array_list_get_at_ptr(&req->encrypted_data_keys, &vp_edk, i)) {
            goto err;
        }

        edk = vp_edk;

        if (hash_edk_for_decrypt(req->alloc, &entry, edk)) {
            goto err;
        }

        if (aws_array_list_push_back(&edk_hash_list, &entry)) {
            goto err;
        }
    }

    aws_array_list_sort(&edk_hash_list, edk_hash_entry_cmp);
    if (aws_cryptosdk_md_init(req->alloc, &md_context, AWS_CRYPTOSDK_MD_SHA512) ||
        aws_cryptosdk_md_update(md_context, aws_string_bytes(partition_id), partition_id->len) ||
        aws_cryptosdk_md_update(md_context, &alg_id_be, sizeof(alg_id_be))) {
        goto err;
    }

    for (size_t i = 0; i < n_edks; i++) {
        void *vp_entry = NULL;

        if (aws_array_list_get_at_ptr(&edk_hash_list, &vp_entry, i) ||
            aws_cryptosdk_md_update(md_context, ((struct edk_hash_entry *)vp_entry)->hash_data, md_length)) {
            goto err;
        }
    }

    if (aws_cryptosdk_md_update(md_context, &zero_entry, sizeof(zero_entry)) ||
        aws_cryptosdk_md_update(md_context, context_digest_buf.buffer, context_digest_buf.len)) {
        goto err;
    }

    rv         = aws_cryptosdk_md_finish(md_context, out->buffer, &out->len);
    md_context = NULL;

err:
    aws_cryptosdk_md_abort(md_context);
    aws_byte_buf_clean_up(&context_buf);
    aws_array_list_clean_up(&edk_hash_list);

    return rv;
}

static void set_ttl_on_miss(struct caching_cmm *cmm, struct aws_cryptosdk_materials_cache_entry *entry) {
    if (entry && cmm->ttl_nanos != UINT64_MAX) {
        uint64_t creation_time = aws_cryptosdk_materials_cache_entry_get_creation_time(cmm->materials_cache, entry);
        uint64_t exp_time      = creation_time + cmm->ttl_nanos;

        if (exp_time > creation_time) {
            aws_cryptosdk_materials_cache_entry_ttl_hint(cmm->materials_cache, entry, exp_time);
        }
    }
}

static int generate_enc_materials(
    struct aws_cryptosdk_cmm *generic_cmm,
    struct aws_cryptosdk_enc_materials **output,
    struct aws_cryptosdk_enc_request *request) {
    struct caching_cmm *cmm = AWS_CONTAINER_OF(generic_cmm, struct caching_cmm, base);

    bool is_encrypt, should_invalidate = false;
    struct aws_cryptosdk_materials_cache_entry *entry = NULL;
    struct aws_cryptosdk_cache_usage_stats delta_usage;

    delta_usage.bytes_encrypted    = request->plaintext_size;
    delta_usage.messages_encrypted = 1;

    /*
     * If the (maximum) size of the plaintext is larger than our limit, there's no point
     * in doing any cache processing.
     *
     * Additionally, if an uncachable (non-KDF) algorithm is requested, we won't be able
     * to safely process the result, and should also bypass the cache.
     */

    if (delta_usage.bytes_encrypted > cmm->limit_bytes ||
        (request->requested_alg && !can_cache_algorithm(request->requested_alg))) {
        return aws_cryptosdk_cmm_generate_enc_materials(cmm->upstream, output, request);
    }

    uint8_t hash_arr[AWS_CRYPTOSDK_MD_MAX_SIZE];
    struct aws_byte_buf hash_buf = aws_byte_buf_from_array(hash_arr, sizeof(hash_arr));
    if (hash_enc_request(cmm->partition_id, &hash_buf, request)) {
        return AWS_OP_ERR;
    }

    if (aws_cryptosdk_materials_cache_find_entry(cmm->materials_cache, &entry, &is_encrypt, &hash_buf) || !entry ||
        !is_encrypt) {
        goto cache_miss;
    }

    if (!check_ttl(cmm, entry)) {
        goto cache_miss;
    }

    struct aws_cryptosdk_cache_usage_stats stats = delta_usage;
    if (aws_cryptosdk_materials_cache_update_usage_stats(cmm->materials_cache, entry, &stats)) {
        goto cache_miss;
    }

    if (stats.bytes_encrypted > cmm->limit_bytes || stats.messages_encrypted > cmm->limit_messages) {
        goto cache_miss;
    }

    /* If the current message exactly hits the message limit, reuse the data key this time but
     * immediately invalidate it from the cache. If the current message exactly hits the byte
     * limit, we do not invalidate the data key, because we are allowed to reuse it for zero
     * byte length messages.
     */
    if (stats.messages_encrypted == cmm->limit_messages) {
        should_invalidate = true;
    }

    if (aws_cryptosdk_materials_cache_get_enc_materials(
            cmm->materials_cache, request->alloc, output, request->enc_ctx, entry)) {
        goto cache_miss;
    }

    aws_cryptosdk_materials_cache_entry_release(cmm->materials_cache, entry, should_invalidate);

    return AWS_OP_SUCCESS;
cache_miss:
    if (entry) {
        /*
         * If we found the entry but then did a cache miss, it must have been unusable for some reason,
         * and we should invalidate.
         */
        aws_cryptosdk_materials_cache_entry_release(cmm->materials_cache, entry, true);
        entry = NULL;
    }

    if (aws_cryptosdk_cmm_generate_enc_materials(cmm->upstream, output, request)) {
        return AWS_OP_ERR;
    }

    if (can_cache_algorithm((*output)->alg)) {
        aws_cryptosdk_materials_cache_put_entry_for_encrypt(
            cmm->materials_cache, &entry, *output, delta_usage, request->enc_ctx, &hash_buf);

        set_ttl_on_miss(cmm, entry);

        if (entry) {
            aws_cryptosdk_materials_cache_entry_release(cmm->materials_cache, entry, false);
        }
    }

    return AWS_OP_SUCCESS;
}

static int decrypt_materials(
    struct aws_cryptosdk_cmm *generic_cmm,
    struct aws_cryptosdk_dec_materials **output,
    struct aws_cryptosdk_dec_request *request) {
    struct caching_cmm *cmm = AWS_CONTAINER_OF(generic_cmm, struct caching_cmm, base);

    bool is_encrypt;
    struct aws_cryptosdk_materials_cache_entry *entry = NULL;

    if (!can_cache_algorithm(request->alg)) {
        /* The algorithm used for the ciphertext is not cachable, so bypass the cache entirely */
        return aws_cryptosdk_cmm_decrypt_materials(cmm->upstream, output, request);
    }

    uint8_t hash_arr[AWS_CRYPTOSDK_MD_MAX_SIZE];
    struct aws_byte_buf hash_buf = aws_byte_buf_from_array(hash_arr, sizeof(hash_arr));

    if (hash_dec_request(cmm->partition_id, &hash_buf, request)) {
        return AWS_OP_ERR;
    }

    if (aws_cryptosdk_materials_cache_find_entry(cmm->materials_cache, &entry, &is_encrypt, &hash_buf) || !entry ||
        is_encrypt) {
        /*
         * If we got an encrypt entry, we'll invalidate it, since we're about to replace it anyway.
         * (This is unlikely to happen anyway, unless our hash function is broken)
         */
        goto cache_miss;
    }

    if (!check_ttl(cmm, entry)) {
        goto cache_miss;
    }

    if (aws_cryptosdk_materials_cache_get_dec_materials(cmm->materials_cache, request->alloc, output, entry)) {
        goto cache_miss;
    }

    aws_cryptosdk_materials_cache_entry_release(cmm->materials_cache, entry, false);

    return AWS_OP_SUCCESS;

cache_miss:
    if (entry) {
        /*
         * If we found the entry but then did a cache miss, it must have been unusable for some reason,
         * and we should invalidate.
         */
        aws_cryptosdk_materials_cache_entry_release(cmm->materials_cache, entry, true);
    }

    if (aws_cryptosdk_cmm_decrypt_materials(cmm->upstream, output, request)) {
        return AWS_OP_ERR;
    }

    aws_cryptosdk_materials_cache_put_entry_for_decrypt(cmm->materials_cache, &entry, *output, &hash_buf);

    set_ttl_on_miss(cmm, entry);

    if (entry) {
        aws_cryptosdk_materials_cache_entry_release(cmm->materials_cache, entry, false);
    }

    return AWS_OP_SUCCESS;
}
