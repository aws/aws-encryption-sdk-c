/*
 * Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
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

#include <openssl/ec.h>
#include <openssl/evp.h>

#include <aws/cryptosdk/cipher.h>
#include <aws/cryptosdk/private/hkdf.h>
#include <cipher_openssl.h>
#include <ec_utils.h>
#include <evp_utils.h>
#include <make_common_data_structures.h>

#include <aws/cryptosdk/keyring_trace.h>
#include <aws/cryptosdk/private/keyring_trace.h>
#include <proof_helpers/cryptosdk/make_common_data_structures.h>
#include <proof_helpers/make_common_data_structures.h>
#include <proof_helpers/proof_allocators.h>

void ensure_alg_properties_attempt_allocation(struct aws_cryptosdk_alg_properties *const alg_props) {
    size_t md_name_size;
    alg_props->md_name = can_fail_malloc(md_name_size);
    size_t cipher_name_size;
    alg_props->cipher_name = can_fail_malloc(cipher_name_size);
    size_t alg_name_size;
    alg_props->alg_name = can_fail_malloc(alg_name_size);
}

void ensure_record_has_allocated_members(struct aws_cryptosdk_keyring_trace_record *record, size_t max_len) {
    record->wrapping_key_namespace = ensure_string_is_allocated_bounded_length(max_len);
    record->wrapping_key_name      = ensure_string_is_allocated_bounded_length(max_len);
    record->flags                  = malloc(sizeof(uint32_t));
}

void ensure_trace_has_allocated_records(struct aws_array_list *trace, size_t max_len) {
    /* iterate over each record in the keyring trace */
    size_t num_records = aws_array_list_length(trace);
    for (size_t idx = 0; idx < num_records; ++idx) {
        struct aws_cryptosdk_keyring_trace_record *record;
        if (!aws_array_list_get_at_ptr(trace, (void **)&record, idx)) {
            /* make sure each record is valid */
            ensure_record_has_allocated_members(record, max_len);
        }
    }
}

void ensure_md_context_has_allocated_members(struct aws_cryptosdk_md_context *ctx) {
    ctx->alloc      = nondet_bool() ? NULL : can_fail_allocator();
    ctx->evp_md_ctx = evp_md_ctx_nondet_alloc();
}

void ensure_sig_ctx_has_allocated_members(struct aws_cryptosdk_sig_ctx *ctx) {
    ctx->alloc = nondet_bool() ? NULL : can_fail_allocator();
    enum aws_cryptosdk_alg_id alg_id;
    ctx->props   = aws_cryptosdk_alg_props(alg_id);
    ctx->keypair = ec_key_nondet_alloc();
    ctx->pkey    = evp_pkey_nondet_alloc();
    ctx->ctx     = evp_md_ctx_nondet_alloc();

    // Need to ensure consistency of reference count later by assuming ctx is valid
    evp_pkey_set0_ec_key(ctx->pkey, ctx->keypair);

    if (ctx->is_sign) {
        evp_md_ctx_set0_evp_pkey(ctx->ctx, NULL);
    } else {
        // Need to ensure consistency of reference count later by assuming ctx is valid
        evp_md_ctx_set0_evp_pkey(ctx->ctx, ctx->pkey);
    }
}

bool aws_cryptosdk_edk_is_bounded(const struct aws_cryptosdk_edk *edk, const size_t max_size) {
    return aws_byte_buf_is_bounded(&edk->provider_id, max_size) &&
           aws_byte_buf_is_bounded(&edk->provider_info, max_size) &&
           aws_byte_buf_is_bounded(&edk->ciphertext, max_size);
}

void ensure_cryptosdk_edk_has_allocated_members(struct aws_cryptosdk_edk *edk) {
    ensure_byte_buf_has_allocated_buffer_member(&edk->provider_id);
    ensure_byte_buf_has_allocated_buffer_member(&edk->provider_info);
    ensure_byte_buf_has_allocated_buffer_member(&edk->ciphertext);
}

bool aws_cryptosdk_edk_list_is_bounded(
    const struct aws_array_list *const list, const size_t max_initial_item_allocation) {
    if (list->item_size != sizeof(struct aws_cryptosdk_edk)) {
        return false;
    }
    if (list->length > max_initial_item_allocation) {
        return false;
    }

    return true;
}

bool aws_cryptosdk_edk_list_elements_are_bounded(const struct aws_array_list *const list, const size_t max_item_size) {
    for (size_t i = 0; i < list->length; ++i) {
        struct aws_cryptosdk_edk *data = (struct aws_cryptosdk_edk *)list->data;
        if (!aws_cryptosdk_edk_is_bounded(&(data[i]), max_item_size)) {
            return false;
        }
    }
    return true;
}

void ensure_cryptosdk_edk_list_has_allocated_list(struct aws_array_list *list) {
    if (list->current_size == 0) {
        __CPROVER_assume(list->data == NULL);
        list->alloc = can_fail_allocator();
    } else {
        size_t max_length = list->current_size / sizeof(struct aws_cryptosdk_edk);
        list->data        = bounded_malloc(sizeof(struct aws_cryptosdk_edk) * max_length);
        list->alloc       = nondet_bool() ? NULL : can_fail_allocator();
    }
}

void ensure_cryptosdk_edk_list_has_allocated_list_elements(struct aws_array_list *list) {
    for (size_t i = 0; i < list->length; ++i) {
        struct aws_cryptosdk_edk *data = (struct aws_cryptosdk_edk *)list->data;
        ensure_cryptosdk_edk_has_allocated_members(&(data[i]));
    }
}

enum aws_cryptosdk_sha_version aws_cryptosdk_which_sha(enum aws_cryptosdk_alg_id alg_id) {
    switch (alg_id) {
        case ALG_AES256_GCM_IV12_TAG16_HKDF_SHA384_ECDSA_P384:
        case ALG_AES192_GCM_IV12_TAG16_HKDF_SHA384_ECDSA_P384: return AWS_CRYPTOSDK_SHA384;
        case ALG_AES128_GCM_IV12_TAG16_HKDF_SHA256_ECDSA_P256:
        case ALG_AES256_GCM_IV12_TAG16_HKDF_SHA256:
        case ALG_AES192_GCM_IV12_TAG16_HKDF_SHA256:
        case ALG_AES128_GCM_IV12_TAG16_HKDF_SHA256: return AWS_CRYPTOSDK_SHA256;
        case ALG_AES256_GCM_IV12_TAG16_NO_KDF:
        case ALG_AES192_GCM_IV12_TAG16_NO_KDF:
        case ALG_AES128_GCM_IV12_TAG16_NO_KDF:
        default: return AWS_CRYPTOSDK_NOSHA;
    }
}

void ensure_cryptosdk_keyring_has_allocated_members(struct aws_cryptosdk_keyring *keyring
                                                    struct aws_cryptosdk_keyring_vt ) {
    keyring->refcount.value = can_fail_malloc(sizeof(size_t));
    keyring->vtable         = can_fail_malloc(sizeof(struct aws_cryptosdk_keyring_vt *));
}
