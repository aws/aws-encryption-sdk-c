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

#include <aws/common/linked_list.h> /* AWS_CONTAINER_OF */
#include <aws/common/math.h>
#include <aws/cryptosdk/cache.h>
#include <aws/cryptosdk/enc_context.h>
#include <aws/cryptosdk/private/enc_context.h>
#include <aws/cryptosdk/private/cipher.h>
#include <aws/common/byte_buf.h>

struct caching_cmm {
    struct aws_cryptosdk_cmm base;
    struct aws_allocator *alloc;
    struct aws_cryptosdk_cmm *upstream;
    struct aws_cryptosdk_mat_cache *mat_cache;
    struct aws_string *partition_id;

    int (*clock_get_ticks)(uint64_t *now);

    uint64_t limit_messages, limit_bytes, ttl;
};

#define MAX_LIMIT_MESSAGES ((uint64_t)1 << 32)

static void destroy_caching_cmm(struct aws_cryptosdk_cmm *generic_cmm);
static int generate_enc_materials(struct aws_cryptosdk_cmm * cmm,
                                  struct aws_cryptosdk_encryption_materials ** output,
                                  struct aws_cryptosdk_encryption_request * request);

static const struct aws_cryptosdk_cmm_vt caching_cmm_vt = {
    .vt_size = sizeof(caching_cmm_vt),
    .name = "Caching CMM",
    .destroy = destroy_caching_cmm,
    .generate_encryption_materials = generate_enc_materials,
    .decrypt_materials = NULL
};

static void destroy_caching_cmm(struct aws_cryptosdk_cmm *generic_cmm) {
    struct caching_cmm *cmm = AWS_CONTAINER_OF(generic_cmm, struct caching_cmm, base);

    aws_string_destroy(cmm->partition_id);
    aws_cryptosdk_mat_cache_release(cmm->mat_cache);
    aws_cryptosdk_cmm_release(cmm->upstream);
    aws_mem_release(cmm->alloc, cmm);
}

static bool can_cache_algorithm(enum aws_cryptosdk_alg_id alg_id) {
    const struct aws_cryptosdk_alg_properties *props = aws_cryptosdk_alg_props(alg_id);

    /* TODO: Better name for this property? */
    return props->md_name != NULL;
}

AWS_CRYPTOSDK_TEST_STATIC
struct aws_string *hash_or_generate_partition_id(struct aws_allocator *alloc, const struct aws_byte_buf *partition_name) {
    uint8_t tmparr[AWS_CRYPTOSDK_MD_MAX_SIZE];

    if (partition_name) {
        struct aws_cryptosdk_md_context *md_context = NULL;

        if (aws_cryptosdk_md_init(alloc, &md_context, AWS_CRYPTOSDK_MD_SHA512)
            || aws_cryptosdk_md_update(md_context, partition_name->buffer, partition_name->len))
        {
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

struct aws_cryptosdk_cmm *aws_cryptosdk_caching_cmm_new(
    struct aws_allocator *alloc,
    struct aws_cryptosdk_mat_cache *mat_cache,
    struct aws_cryptosdk_cmm *upstream,
    const struct aws_byte_buf *partition_name
) {
    struct aws_string *partition_id_str = hash_or_generate_partition_id(alloc, partition_name);

    if (!partition_id_str) {
        return NULL;
    }

    struct caching_cmm *cmm = aws_mem_acquire(alloc, sizeof(*cmm));
    if (!cmm) {
        return NULL;
    }

    aws_cryptosdk_cmm_base_init(&cmm->base, &caching_cmm_vt);

    cmm->alloc = alloc;
    cmm->upstream = aws_cryptosdk_cmm_retain(upstream);
    cmm->mat_cache = aws_cryptosdk_mat_cache_retain(mat_cache);
    cmm->partition_id = partition_id_str;

    // We use the test helper here just to ensure we don't get unused static function warnings
    caching_cmm_set_clock(&cmm->base, aws_sys_clock_get_ticks);

    cmm->limit_messages = MAX_LIMIT_MESSAGES;
    cmm->limit_bytes = UINT64_MAX;
    cmm->ttl = UINT64_MAX;

    return &cmm->base;
}

int aws_cryptosdk_caching_cmm_set_limits(
    struct aws_cryptosdk_cmm *generic_cmm,
    enum aws_cryptosdk_caching_cmm_limit_type type,
    uint64_t new_value
) {
    if (generic_cmm->vtable != &caching_cmm_vt) {
        return aws_raise_error(AWS_ERROR_UNSUPPORTED_OPERATION);
    }

    struct caching_cmm *cmm = AWS_CONTAINER_OF(generic_cmm, struct caching_cmm, base);

    if (new_value == 0) {
        return aws_raise_error(AWS_CRYPTOSDK_ERR_LIMIT_EXCEEDED);
    }

    switch (type) {
        case AWS_CRYPTOSDK_CACHE_LIMIT_MESSAGES:
            if (new_value > MAX_LIMIT_MESSAGES) {
                cmm->limit_messages = MAX_LIMIT_MESSAGES;
            } else {
                cmm->limit_messages = new_value;
            }
            break;
        case AWS_CRYPTOSDK_CACHE_LIMIT_BYTES:
            cmm->limit_bytes = new_value;
            break;
        case AWS_CRYPTOSDK_CACHE_LIMIT_TTL:
            cmm->ttl = new_value;
            break;
        default:
            return aws_raise_error(AWS_ERROR_UNSUPPORTED_OPERATION);
    }

    return AWS_OP_SUCCESS;
}

/*
 * Checks the TTL on the entry given. Returns true if the TTL has not yet expired, or false if it has expired.
 * Additionally, sets the TTL hint on the entry if it has not expired.
 */
static bool check_ttl(struct caching_cmm *cmm, struct aws_cryptosdk_mat_cache_entry *entry) {
    if (cmm->ttl == UINT64_MAX) {
        /* Entries never expire, because their expiration time is beyond the maximum time we can represent */
        return true;
    }

    uint64_t creation_time = aws_cryptosdk_mat_cache_entry_get_creation_time(cmm->mat_cache, entry);
    uint64_t expiration = creation_time + cmm->ttl;
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

    aws_cryptosdk_mat_cache_entry_ttl_hint(cmm->mat_cache, entry, expiration);

    return true;
}

AWS_CRYPTOSDK_TEST_STATIC
int hash_encrypt_request(struct aws_string *partition_id, struct aws_byte_buf *out, const struct aws_cryptosdk_encryption_request *req) {
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
    struct aws_byte_buf context_buf = {0};
    uint8_t digestbuf[AWS_CRYPTOSDK_MD_MAX_SIZE] = {0};

    if (out->capacity < AWS_CRYPTOSDK_MD_MAX_SIZE) {
        return aws_raise_error(AWS_ERROR_INVALID_BUFFER_SIZE);
    }

    struct aws_cryptosdk_md_context *md_context, *enc_context_md;
    if (aws_cryptosdk_md_init(req->alloc, &md_context, AWS_CRYPTOSDK_MD_SHA512)) {
        return AWS_OP_ERR;
    }

    if (aws_cryptosdk_md_init(req->alloc, &enc_context_md, AWS_CRYPTOSDK_MD_SHA512)) {
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
    if (aws_cryptosdk_context_size(&context_size, req->enc_context)
        || aws_byte_buf_init(req->alloc, &context_buf, context_size)
        || aws_cryptosdk_context_serialize(req->alloc, &context_buf, req->enc_context)
        || aws_cryptosdk_md_update(enc_context_md, context_buf.buffer, context_buf.len)
    ) {
        goto md_err;
    }

    size_t enc_context_digest_len;
    if (aws_cryptosdk_md_finish(enc_context_md, digestbuf, &enc_context_digest_len)) {
        enc_context_md = NULL;
        goto md_err;
    }
    enc_context_md = NULL;

    if (aws_cryptosdk_md_update(md_context, digestbuf, enc_context_digest_len)) {
        goto md_err;
    }

    aws_byte_buf_clean_up(&context_buf);
    return aws_cryptosdk_md_finish(md_context, out->buffer, &out->len);

md_err:
    aws_byte_buf_clean_up(&context_buf);
    aws_cryptosdk_md_abort(md_context);
    aws_cryptosdk_md_abort(enc_context_md);

    return AWS_OP_ERR;
}

static int generate_enc_materials(struct aws_cryptosdk_cmm *generic_cmm,
               struct aws_cryptosdk_encryption_materials ** output,
               struct aws_cryptosdk_encryption_request * request
) {
    struct caching_cmm *cmm = AWS_CONTAINER_OF(generic_cmm, struct caching_cmm, base);

    bool is_encrypt, should_invalidate = false;
    struct aws_cryptosdk_mat_cache_entry *entry = NULL;
    struct aws_cryptosdk_cache_usage_stats delta_usage;

    delta_usage.bytes_encrypted = request->plaintext_size;
    delta_usage.messages_encrypted = 1;

    /*
     * If the (maximum) size of the plaintext is larger than our limit, there's no point
     * in doing any cache processing.
     *
     * Additionally, if an uncachable (non-KDF) algorithm is requested, we won't be able
     * to safely process the result, and should also bypass the cache.
     */

    if (delta_usage.bytes_encrypted >= cmm->limit_bytes
        || (request->requested_alg && !can_cache_algorithm(request->requested_alg))) {
        return aws_cryptosdk_cmm_generate_encryption_materials(cmm->upstream, output, request);
    }

    uint8_t hash_arr[AWS_CRYPTOSDK_MD_MAX_SIZE];
    struct aws_byte_buf hash_buf = aws_byte_buf_from_array(hash_arr, sizeof(hash_arr));
    if (hash_encrypt_request(cmm->partition_id, &hash_buf, request)) {
        return AWS_OP_ERR;
    }

    if (aws_cryptosdk_mat_cache_find_entry(
        cmm->mat_cache,
        &entry,
        &is_encrypt,
        &hash_buf
    ) || !entry || !is_encrypt) {
        goto cache_miss;
    }

    if (!check_ttl(cmm, entry)) {
        goto cache_miss;
    }

    struct aws_cryptosdk_cache_usage_stats stats = delta_usage;
    if (aws_cryptosdk_mat_cache_update_usage_stats(cmm->mat_cache, entry, &stats)) {
        goto cache_miss;
    }

    if (stats.bytes_encrypted > cmm->limit_bytes || stats.messages_encrypted > cmm->limit_messages) {
        goto cache_miss;
    }

    if (stats.bytes_encrypted == cmm->limit_bytes || stats.messages_encrypted == cmm->limit_messages) {
        should_invalidate = true;
    }

    if (aws_cryptosdk_mat_cache_get_encryption_materials(cmm->mat_cache, request->alloc, output, request->enc_context, entry)) {
        goto cache_miss;
    }

    aws_cryptosdk_mat_cache_entry_release(cmm->mat_cache, entry, should_invalidate);

    return AWS_OP_SUCCESS;
cache_miss:
    if (entry) {
        /*
         * If we found the entry but then did a cache miss, it must have been unusable for some reason,
         * and we should invalidate.
         */
        aws_cryptosdk_mat_cache_entry_release(cmm->mat_cache, entry, true);
    }

    if (aws_cryptosdk_cmm_generate_encryption_materials(cmm->upstream, output, request)) {
        return AWS_OP_ERR;
    }

    if (can_cache_algorithm((*output)->alg)) {
        aws_cryptosdk_mat_cache_put_entry_for_encrypt(
            cmm->mat_cache,
            &entry,
            *output,
            delta_usage,
            request->enc_context,
            &hash_buf
        );
    }

    return AWS_OP_SUCCESS;
}
