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

#include <aws/cryptosdk/materials.h>
#include <aws/cryptosdk/cache.h>
#include <aws/cryptosdk/enc_context.h>
#include <aws/cryptosdk/list_utils.h>
#include <aws/cryptosdk/private/cipher.h>
#include <aws/cryptosdk/private/keyring_trace.h>

#include "cache_test_lib.h"
#include "testutil.h"

void gen_enc_materials(struct aws_allocator *alloc, struct aws_cryptosdk_encryption_materials **p_materials, int index, enum aws_cryptosdk_alg_id alg, int n_edks) {
    struct aws_cryptosdk_encryption_materials *materials = *p_materials = aws_cryptosdk_encryption_materials_new(alloc, alg);
    if (!materials) {
        abort();
    }

    byte_buf_printf(&materials->unencrypted_data_key, alloc, "UDK #%d", index);

    const struct aws_cryptosdk_alg_properties *props = aws_cryptosdk_alg_props(alg);
    if (props->signature_len) {
        if (aws_cryptosdk_sig_sign_start_keygen(&materials->signctx, alloc, NULL, props)) {
            abort();
        }
    }

    for (int i = 0; i < n_edks; i++) {
        struct aws_cryptosdk_edk edk;
        byte_buf_printf(&edk.enc_data_key, alloc, "EDK #%d.%d", index, i);
        byte_buf_printf(&edk.provider_id, alloc, "Provider ID #%d.%d", index, i);
        byte_buf_printf(&edk.provider_info, alloc, "Provider info #%d.%d", index, i);

        if (aws_array_list_push_back(&materials->encrypted_data_keys, &edk)) {
            abort();
        }

        if (aws_cryptosdk_keyring_trace_add_record_c_str(alloc,
                                                         &materials->keyring_trace,
                                                         edk.provider_id.buffer,
                                                         edk.provider_info.buffer,
                                                         AWS_CRYPTOSDK_WRAPPING_KEY_GENERATED_DATA_KEY |
                                                         AWS_CRYPTOSDK_WRAPPING_KEY_ENCRYPTED_DATA_KEY |
                                                         AWS_CRYPTOSDK_WRAPPING_KEY_SIGNED_ENC_CTX)) {
            abort();
        }
    }
}

bool materials_eq(const struct aws_cryptosdk_encryption_materials *a, const struct aws_cryptosdk_encryption_materials *b) {
    if (a->alg != b->alg) {
        return false;
    }

    if (!!a->signctx != !!b->signctx) {
        return false;
    }

    if (!aws_byte_buf_eq(&a->unencrypted_data_key, &b->unencrypted_data_key)) {
        return false;
    }

    if (aws_array_list_length(&a->encrypted_data_keys) != aws_array_list_length(&b->encrypted_data_keys)) {
        return false;
    }

    size_t len = aws_array_list_length(&a->encrypted_data_keys);
    for (size_t i = 0; i < len; i++) {
        void *vp_a, *vp_b;

        if (aws_array_list_get_at_ptr(&a->encrypted_data_keys, &vp_a, i) ||
            aws_array_list_get_at_ptr(&b->encrypted_data_keys, &vp_b, i)
        ) {
            abort();
        }

        struct aws_cryptosdk_edk *edk_a = vp_a;
        struct aws_cryptosdk_edk *edk_b = vp_b;

        if (!aws_byte_buf_eq(&edk_a->enc_data_key, &edk_b->enc_data_key)) return false;
        if (!aws_byte_buf_eq(&edk_a->provider_id, &edk_b->provider_id)) return false;
        if (!aws_byte_buf_eq(&edk_a->provider_info, &edk_b->provider_info)) return false;
    }

    return aws_cryptosdk_keyring_trace_eq(&a->keyring_trace, &b->keyring_trace);
}

bool dec_materials_eq(const struct aws_cryptosdk_decryption_materials *a, const struct aws_cryptosdk_decryption_materials *b) {
    return (a->alg == b->alg)
        && (aws_byte_buf_eq(&a->unencrypted_data_key, &b->unencrypted_data_key))
        && (!!a->signctx == !!b->signctx)
        && (!a->signctx || same_signing_key(a->signctx, b->signctx))
        && aws_cryptosdk_keyring_trace_eq(&a->keyring_trace, &b->keyring_trace);
}

bool same_signing_key(struct aws_cryptosdk_signctx *a, struct aws_cryptosdk_signctx *b) {
    struct aws_string *pub_a, *pub_b;

    if (!!a != !!b) {
        return false;
    }

    if (!a) {
        // both are null
        return true;
    }

    if (aws_cryptosdk_sig_get_pubkey(a, aws_default_allocator(), &pub_a)
        || aws_cryptosdk_sig_get_pubkey(b, aws_default_allocator(), &pub_b)
    ) {
        abort();
    }

    bool same = aws_string_eq(pub_a, pub_b);

    aws_string_destroy(pub_a);
    aws_string_destroy(pub_b);

    return same;
}


/*** Mock materials cache ***/

static int mock_find_entry(
    struct aws_cryptosdk_mat_cache *cache,
    struct aws_cryptosdk_mat_cache_entry **entry,
    bool *is_encrypt,
    const struct aws_byte_buf *cache_id
);
static int mock_update_usage_stats(
    struct aws_cryptosdk_mat_cache *cache,
    struct aws_cryptosdk_mat_cache_entry *entry,
    struct aws_cryptosdk_cache_usage_stats *usage_stats
);
static int mock_get_encryption_materials(
    struct aws_cryptosdk_mat_cache *cache,
    struct aws_allocator *allocator,
    struct aws_cryptosdk_encryption_materials **materials,
    struct aws_hash_table *enc_context,
    struct aws_cryptosdk_mat_cache_entry *entry
);
static int mock_get_decryption_materials(
    const struct aws_cryptosdk_mat_cache *cache,
    struct aws_allocator *allocator,
    struct aws_cryptosdk_decryption_materials **materials,
    const struct aws_cryptosdk_mat_cache_entry *entry
);
static void mock_put_entry_for_encrypt(
    struct aws_cryptosdk_mat_cache *cache,
    struct aws_cryptosdk_mat_cache_entry **entry,
    const struct aws_cryptosdk_encryption_materials *encryption_materials,
    struct aws_cryptosdk_cache_usage_stats initial_usage,
    const struct aws_hash_table *enc_context,
    const struct aws_byte_buf *cache_id
);
static void mock_put_entry_for_decrypt(
    struct aws_cryptosdk_mat_cache *cache,
    struct aws_cryptosdk_mat_cache_entry **entry,
    const struct aws_cryptosdk_decryption_materials *decryption_materials,
    const struct aws_byte_buf *cache_id
);

static void mock_mat_cache_destroy(struct aws_cryptosdk_mat_cache *cache);
static void mock_entry_release(
    struct aws_cryptosdk_mat_cache *cache,
    struct aws_cryptosdk_mat_cache_entry *entry,
    bool invalidate
);
static uint64_t mock_entry_ctime(
    const struct aws_cryptosdk_mat_cache *cache,
    const struct aws_cryptosdk_mat_cache_entry *entry
);
static void mock_entry_ttl_hint(
    struct aws_cryptosdk_mat_cache *cache,
    struct aws_cryptosdk_mat_cache_entry *entry,
    uint64_t exp_time
);

const static struct aws_cryptosdk_mat_cache_vt mock_vt = {
    .vt_size = sizeof(mock_vt),
    .name = "Mock materials cache",
    .find_entry = mock_find_entry,
    .update_usage_stats = mock_update_usage_stats,
    .get_encryption_materials = mock_get_encryption_materials,
    .get_decryption_materials = mock_get_decryption_materials,
    .put_entry_for_encrypt = mock_put_entry_for_encrypt,
    .put_entry_for_decrypt = mock_put_entry_for_decrypt,
    .destroy = mock_mat_cache_destroy,
    .entry_release = mock_entry_release,
    .entry_get_creation_time = mock_entry_ctime,
    .entry_ttl_hint = mock_entry_ttl_hint
};

static void check_entry_ptr(const struct mock_mat_cache *cache, const struct aws_cryptosdk_mat_cache_entry *entry) {
    if (!cache->entry_refcount) {
        fprintf(stderr, "\n mock_mat_cache entry refcount underflow\n");
        abort();
    }

    if (entry != (void *)&cache->entry_marker) {
        fprintf(stderr, "\n mock_mat_cache entry ptr mismatch; expected %p got %p\n",
            (void *)&cache->entry_marker, (void *)entry
        );
        abort();
    }
}

static void mock_mat_cache_destroy(struct aws_cryptosdk_mat_cache *generic_cache) {
    struct mock_mat_cache *cache = (struct mock_mat_cache *)generic_cache;

    aws_cryptosdk_encryption_materials_destroy(cache->enc_materials);
    aws_cryptosdk_decryption_materials_destroy(cache->dec_materials);
    aws_cryptosdk_enc_context_clean_up(&cache->encryption_context);
    aws_byte_buf_clean_up(&cache->last_cache_id);

    aws_mem_release(cache->alloc, cache);
}

struct mock_mat_cache *mock_mat_cache_new(struct aws_allocator *alloc) {
    struct mock_mat_cache *cache = aws_mem_acquire(alloc, sizeof(*cache));
    if (!cache) abort();

    memset(cache, 0, sizeof(*cache));
    cache->alloc = alloc;

    aws_cryptosdk_mat_cache_base_init(&cache->base, &mock_vt);
    if (aws_cryptosdk_enc_context_init(alloc, &cache->encryption_context)) abort();

    return cache;
}

static int mock_find_entry(
    struct aws_cryptosdk_mat_cache *generic_cache,
    struct aws_cryptosdk_mat_cache_entry **entry,
    bool *is_encrypt,
    const struct aws_byte_buf *cache_id
) {
    struct mock_mat_cache *cache = (struct mock_mat_cache *)generic_cache;

    aws_byte_buf_clean_up(&cache->last_cache_id);
    if (aws_byte_buf_init_copy(&cache->last_cache_id, cache->alloc, cache_id)) abort();

    *entry = NULL;

    if (cache->should_fail) {
        return aws_raise_error(AWS_CRYPTOSDK_ERR_CRYPTO_UNKNOWN);
    }

    if (!cache->should_hit) {
        return AWS_OP_SUCCESS;
    }

    *is_encrypt = !!cache->enc_materials;
    *entry = (struct aws_cryptosdk_mat_cache_entry *)&cache->entry_marker;
    cache->entry_refcount++;

    return AWS_OP_SUCCESS;
}

static int mock_update_usage_stats(
    struct aws_cryptosdk_mat_cache *generic_cache,
    struct aws_cryptosdk_mat_cache_entry *entry,
    struct aws_cryptosdk_cache_usage_stats *usage_stats
) {
    struct mock_mat_cache *cache = (struct mock_mat_cache *)generic_cache;
    
    check_entry_ptr(cache, entry);

    if (cache->should_fail) return aws_raise_error(AWS_CRYPTOSDK_ERR_CRYPTO_UNKNOWN);

    cache->usage_stats.bytes_encrypted += usage_stats->bytes_encrypted;
    cache->usage_stats.messages_encrypted += usage_stats->messages_encrypted;

    *usage_stats = cache->usage_stats;

    return AWS_OP_SUCCESS;
}

static struct aws_cryptosdk_encryption_materials *clone_enc_materials(
    struct aws_allocator *allocator,
    const struct aws_cryptosdk_encryption_materials *materials
) {
    struct aws_cryptosdk_encryption_materials *new_materials;

    new_materials = aws_cryptosdk_encryption_materials_new(allocator, materials->alg);
    if (!new_materials) abort();

    if (aws_byte_buf_init_copy(&new_materials->unencrypted_data_key, allocator, &materials->unencrypted_data_key)) abort();
    if (aws_cryptosdk_edk_list_copy_all(allocator, &new_materials->encrypted_data_keys, &materials->encrypted_data_keys)) abort();
    if (aws_cryptosdk_keyring_trace_copy_all(allocator, &new_materials->keyring_trace, &materials->keyring_trace)) abort();

    if (materials->signctx) {
        struct aws_string *priv_key_buf;
        if (aws_cryptosdk_sig_get_privkey(materials->signctx, allocator, &priv_key_buf)) abort();
        if (aws_cryptosdk_sig_sign_start(&new_materials->signctx, allocator, NULL, aws_cryptosdk_alg_props(new_materials->alg), priv_key_buf)) abort();
        aws_string_destroy_secure(priv_key_buf);
    }

    return new_materials;
}

static int mock_get_encryption_materials(
    struct aws_cryptosdk_mat_cache *generic_cache,
    struct aws_allocator *allocator,
    struct aws_cryptosdk_encryption_materials **materials,
    struct aws_hash_table *enc_context,
    struct aws_cryptosdk_mat_cache_entry *entry
) {
    struct mock_mat_cache *cache = (struct mock_mat_cache *)generic_cache;
    
    check_entry_ptr(cache, entry);

    *materials = NULL;

    if (cache->should_fail) {
        return aws_raise_error(AWS_CRYPTOSDK_ERR_CRYPTO_UNKNOWN);
    }

    if (!cache->enc_materials) {
        return aws_raise_error(AWS_CRYPTOSDK_ERR_BAD_STATE);
    }

    *materials = clone_enc_materials(allocator, cache->enc_materials);

    if (aws_cryptosdk_enc_context_clone(allocator, enc_context, &cache->encryption_context)) abort();

    return AWS_OP_SUCCESS;
}

static struct aws_cryptosdk_decryption_materials *clone_dec_materials(struct aws_allocator *allocator, const struct aws_cryptosdk_decryption_materials *input) {
    struct aws_cryptosdk_decryption_materials *materials = aws_cryptosdk_decryption_materials_new(allocator, input->alg);

    if (!materials) {
        abort();
    }

    if (aws_byte_buf_init_copy(&materials->unencrypted_data_key, allocator, &input->unencrypted_data_key)) {
        abort();
    }

    if (aws_cryptosdk_keyring_trace_copy_all(allocator, &materials->keyring_trace, &input->keyring_trace)) {
        abort();
    }

    materials->signctx = NULL;
    if (input->signctx) {
        struct aws_string *pubkey;
        const struct aws_cryptosdk_alg_properties *props = aws_cryptosdk_alg_props(materials->alg);

        if (aws_cryptosdk_sig_get_pubkey(input->signctx, allocator, &pubkey)
            || aws_cryptosdk_sig_verify_start(&materials->signctx, allocator, pubkey, props)) {
            abort();
        }

        aws_string_destroy(pubkey);
    }

    return materials;
}

static int mock_get_decryption_materials(
    const struct aws_cryptosdk_mat_cache *generic_cache,
    struct aws_allocator *allocator,
    struct aws_cryptosdk_decryption_materials **materials,
    const struct aws_cryptosdk_mat_cache_entry *entry
) {
    const struct mock_mat_cache *cache = (const struct mock_mat_cache *)generic_cache;

    check_entry_ptr(cache, entry);

    *materials = NULL;

    if (cache->should_fail) {
        return aws_raise_error(AWS_CRYPTOSDK_ERR_CRYPTO_UNKNOWN);
    }

    if (!cache->dec_materials) {
        return aws_raise_error(AWS_CRYPTOSDK_ERR_BAD_STATE);
    }

    *materials = clone_dec_materials(allocator, cache->dec_materials);

    return 0;
}

static void mock_put_entry_for_encrypt(
    struct aws_cryptosdk_mat_cache *generic_cache,
    struct aws_cryptosdk_mat_cache_entry **entry,
    const struct aws_cryptosdk_encryption_materials *encryption_materials,
    struct aws_cryptosdk_cache_usage_stats initial_usage,
    const struct aws_hash_table *enc_context,
    const struct aws_byte_buf *cache_id
) {
    struct mock_mat_cache *cache = (struct mock_mat_cache *)generic_cache;

    aws_byte_buf_clean_up(&cache->last_cache_id);
    if (aws_byte_buf_init_copy(&cache->last_cache_id, cache->alloc, cache_id)) abort();

    if (cache->should_fail) {
        *entry = NULL;
        return;
    }

    aws_cryptosdk_encryption_materials_destroy(cache->enc_materials);
    aws_cryptosdk_decryption_materials_destroy(cache->dec_materials);

    cache->enc_materials = NULL;
    cache->dec_materials = NULL;

    if (aws_cryptosdk_enc_context_clone(cache->alloc, &cache->encryption_context, enc_context)) abort();
    cache->enc_materials = clone_enc_materials(cache->alloc, encryption_materials);
    if (!cache->enc_materials) abort();

    cache->usage_stats = initial_usage;
    *entry = (struct aws_cryptosdk_mat_cache_entry *)&cache->entry_marker;
    cache->entry_refcount++;
}

static void mock_put_entry_for_decrypt(
    struct aws_cryptosdk_mat_cache *generic_cache,
    struct aws_cryptosdk_mat_cache_entry **entry,
    const struct aws_cryptosdk_decryption_materials *decryption_materials,
    const struct aws_byte_buf *cache_id)
{
    struct mock_mat_cache *cache = (struct mock_mat_cache *)generic_cache;

    aws_byte_buf_clean_up(&cache->last_cache_id);
    if (aws_byte_buf_init_copy(&cache->last_cache_id, cache->alloc, cache_id)) abort();

    if (cache->should_fail) {
        *entry = NULL;
        return;
    }

    aws_cryptosdk_encryption_materials_destroy(cache->enc_materials);
    aws_cryptosdk_decryption_materials_destroy(cache->dec_materials);

    cache->enc_materials = NULL;
    cache->dec_materials = NULL;

    cache->dec_materials = clone_dec_materials(cache->alloc, decryption_materials);
    if (!cache->dec_materials) abort();

    *entry = (struct aws_cryptosdk_mat_cache_entry *)&cache->entry_marker;
    cache->entry_refcount++;
}

static void mock_entry_release(
    struct aws_cryptosdk_mat_cache *generic_cache,
    struct aws_cryptosdk_mat_cache_entry *entry,
    bool invalidate
) {
    struct mock_mat_cache *cache = (struct mock_mat_cache *)generic_cache;
    
    check_entry_ptr(cache, entry);

    cache->invalidated = cache->invalidated || invalidate;
    cache->entry_refcount--;
}

static uint64_t mock_entry_ctime(
    const struct aws_cryptosdk_mat_cache *generic_cache,
    const struct aws_cryptosdk_mat_cache_entry *entry
) {
    struct mock_mat_cache *cache = (struct mock_mat_cache *)generic_cache;
    
    check_entry_ptr(cache, entry);

    return cache->entry_creation_time;
}

static void mock_entry_ttl_hint(
    struct aws_cryptosdk_mat_cache *generic_cache,
    struct aws_cryptosdk_mat_cache_entry *entry,
    uint64_t exp_time
) {
    struct mock_mat_cache *cache = (struct mock_mat_cache *)generic_cache;
    
    check_entry_ptr(cache, entry);
 
    cache->entry_ttl_hint = exp_time;
}

/*** Mock upstream CMM ***/

static void mock_upstream_cmm_destroy(struct aws_cryptosdk_cmm *cmm) {
    struct mock_upstream_cmm *mock = (struct mock_upstream_cmm *)cmm;

    aws_string_destroy(mock->last_pubkey);

    aws_mem_release(mock->alloc, mock);
}

static int mock_gen_enc_materials(struct aws_cryptosdk_cmm *generic_cmm,
                           struct aws_cryptosdk_encryption_materials **output,
                           struct aws_cryptosdk_encryption_request *request
) {
    struct mock_upstream_cmm *cmm = (struct mock_upstream_cmm *)generic_cmm;

    char tmpbuf[256];
    AWS_STATIC_STRING_FROM_LITERAL(context_key, "Context key");
    struct aws_string *v;

    sprintf(tmpbuf, "Encryption materials #%d", cmm->materials_index);
    v = aws_string_new_from_c_str(request->alloc, tmpbuf);
    if (!v) return AWS_OP_ERR;

    if (aws_hash_table_put(request->enc_context, context_key, v, NULL)) {
        aws_string_destroy(v);
        return AWS_OP_ERR;
    }

    gen_enc_materials(request->alloc, output, cmm->materials_index, cmm->returned_alg, cmm->n_edks);
    cmm->last_enc_request = request;

    aws_string_destroy(cmm->last_pubkey);
    cmm->last_pubkey = NULL;

    if ((*output)->signctx && aws_cryptosdk_sig_get_pubkey((*output)->signctx, cmm->alloc, &cmm->last_pubkey)) {
        abort();
    }

    return AWS_OP_SUCCESS;
}

/* From caching_cmm.c as a test static */
int hash_decrypt_request(const struct aws_string *partition_id, struct aws_byte_buf *out, const struct aws_cryptosdk_decryption_request *req);

static int mock_decrypt_materials(
    struct aws_cryptosdk_cmm *generic_cmm,
    struct aws_cryptosdk_decryption_materials **output,
    struct aws_cryptosdk_decryption_request *request
) {
    struct mock_upstream_cmm *cmm = (struct mock_upstream_cmm *)generic_cmm;
    AWS_STATIC_STRING_FROM_LITERAL(PARTITION_ID, "mock_decrypt_materials");

    cmm->last_dec_request = request;

    if (!(*output = aws_cryptosdk_decryption_materials_new(request->alloc, request->alg))) {
        abort();
    }

    struct aws_cryptosdk_decryption_materials *materials = *output;

    const struct aws_cryptosdk_alg_properties *props = aws_cryptosdk_alg_props(request->alg);

    size_t alloc_size = props->data_key_len > AWS_CRYPTOSDK_MD_MAX_SIZE ? props->data_key_len : AWS_CRYPTOSDK_MD_MAX_SIZE;
    if (aws_byte_buf_init(&materials->unencrypted_data_key, request->alloc, alloc_size)) {
        abort();
    }

    /*
     * Generate a test pattern which depends on the input.
     * We reuse hash_decrypt_request for convenience (we have tests that verify that it's input-dependent)
     */
    memset(materials->unencrypted_data_key.buffer, 0xAA, materials->unencrypted_data_key.capacity);
    if (hash_decrypt_request(PARTITION_ID, &materials->unencrypted_data_key, request)) {
        abort();
    }
    materials->unencrypted_data_key.len = props->data_key_len;

    if (aws_cryptosdk_keyring_trace_add_record_c_str(request->alloc,
                                                     &materials->keyring_trace,
                                                     "namespace",
                                                     "name",
                                                     AWS_CRYPTOSDK_WRAPPING_KEY_DECRYPTED_DATA_KEY |
                                                     AWS_CRYPTOSDK_WRAPPING_KEY_VERIFIED_ENC_CTX)) {
        abort();
    }

    aws_string_destroy(cmm->last_pubkey);
    cmm->last_pubkey = NULL;

    if (props->signature_len) {
        struct aws_cryptosdk_signctx *priv_ctx;

        if (aws_cryptosdk_sig_sign_start_keygen(&priv_ctx, request->alloc, &cmm->last_pubkey, props)) {
            abort();
        }

        /* We only needed this context to generate a key */
        aws_cryptosdk_sig_abort(priv_ctx);

        if (aws_cryptosdk_sig_verify_start(&materials->signctx, request->alloc, cmm->last_pubkey, props)) {
            abort();
        }
    }

    return AWS_OP_SUCCESS;
}

static const struct aws_cryptosdk_cmm_vt mock_upstream_cmm_vt = {
    .vt_size = sizeof(mock_upstream_cmm_vt),
    .name = "Mock upstream CMM",
    .destroy = mock_upstream_cmm_destroy,
    .generate_encryption_materials = mock_gen_enc_materials,
    .decrypt_materials = mock_decrypt_materials
};

struct mock_upstream_cmm *mock_upstream_cmm_new(struct aws_allocator *alloc) {
    struct mock_upstream_cmm *cmm = aws_mem_acquire(alloc, sizeof(*cmm));
    if (!cmm) abort();

    memset(cmm, 0, sizeof(*cmm));
    cmm->alloc = alloc;

    aws_cryptosdk_cmm_base_init(&cmm->base, &mock_upstream_cmm_vt);

    return cmm;
}
