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
};

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

        if (aws_cryptosdk_md_init(alloc, &md_context, AWS_CRYPTOSDK_MD_SHA512)) {
            goto md_fault;
        }

        if (aws_cryptosdk_md_update(md_context, partition_name->buffer, partition_name->len)) {
            goto md_fault;
        }

        size_t len;
        if (aws_cryptosdk_md_finish(md_context, tmparr, &len)) {
            return NULL;
        }

        return aws_string_new_from_array(alloc, tmparr, len);

    md_fault:
        aws_cryptosdk_md_abort(md_context);
        return NULL;
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

    return &cmm->base;
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

    uint8_t requested_alg = req->requested_alg != 0;
    if (aws_cryptosdk_md_update(md_context, &requested_alg, 1)) {
        goto md_err;
    }

    if (requested_alg) {
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

    uint8_t hash_arr[AWS_CRYPTOSDK_MD_MAX_SIZE];
    struct aws_byte_buf hash_buf = aws_byte_buf_from_array(hash_arr, sizeof(hash_arr));
    struct aws_cryptosdk_mat_cache_entry *entry = NULL;
    struct aws_cryptosdk_cache_usage_stats delta_usage, stats;
    bool is_encrypt;

    delta_usage.bytes_encrypted = request->plaintext_size;
    delta_usage.messages_encrypted = 1;

    if (delta_usage.bytes_encrypted == UINT64_MAX 
        || (request->requested_alg && !can_cache_algorithm(request->requested_alg))) {
        /* Can't cache the request, so we'll need to just pass it through */
        return aws_cryptosdk_cmm_generate_encryption_materials(cmm->upstream, output, request);
    }

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

    stats = delta_usage;
    if (aws_cryptosdk_mat_cache_update_usage_stats(cmm->mat_cache, entry, &stats)) {
        goto cache_miss;
    }

    /* TODO: check usage, invalidate */

    if (aws_cryptosdk_mat_cache_get_encryption_materials(cmm->mat_cache, request->alloc, output, request->enc_context, entry)) {
        goto cache_miss;
    }

    aws_cryptosdk_mat_cache_entry_release(cmm->mat_cache, entry, false);

    return AWS_OP_SUCCESS;
cache_miss:
    if (entry) {
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
