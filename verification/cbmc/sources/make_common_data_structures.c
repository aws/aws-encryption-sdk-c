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

#include <aws/cryptosdk/cipher.h>
#include <aws/cryptosdk/keyring_trace.h>
#include <aws/cryptosdk/materials.h>
#include <aws/cryptosdk/private/header.h>
#include <aws/cryptosdk/private/hkdf.h>
#include <aws/cryptosdk/private/keyring_trace.h>
#include <aws/cryptosdk/private/multi_keyring.h>
#include <aws/cryptosdk/private/session.h>
#include <cipher_openssl.h>
#include <ec_utils.h>
#include <evp_utils.h>

#include <openssl/ec.h>
#include <openssl/evp.h>

#include <proof_helpers/make_common_data_structures.h>
#include <proof_helpers/proof_allocators.h>

const EVP_MD *nondet_EVP_MD_ptr(void);
const EVP_CIPHER *nondet_EVP_CIPHER_ptr(void);

struct aws_cryptosdk_alg_impl *ensure_impl_attempt_allocation(const size_t max_len) {
    struct aws_cryptosdk_alg_impl *impl = malloc(sizeof(struct aws_cryptosdk_alg_impl));
    if (impl) {
        *(const EVP_MD **)(&impl->md_ctor)         = (nondet_bool()) ? NULL : &nondet_EVP_MD_ptr;
        *(const EVP_MD **)(&impl->sig_md_ctor)     = (nondet_bool()) ? NULL : &nondet_EVP_MD_ptr;
        *(const EVP_CIPHER **)(&impl->cipher_ctor) = (nondet_bool()) ? NULL : &nondet_EVP_CIPHER_ptr;
        *(const char **)(&impl->curve_name)        = ensure_c_str_is_allocated(max_len);
    }
    return impl;
}
struct aws_cryptosdk_alg_properties *ensure_alg_properties_attempt_allocation(const size_t max_len) {
    struct aws_cryptosdk_alg_properties *alg_props = malloc(sizeof(struct aws_cryptosdk_alg_properties));
    if (alg_props) {
        alg_props->md_name     = ensure_c_str_is_allocated(max_len);
        alg_props->cipher_name = ensure_c_str_is_allocated(max_len);
        alg_props->alg_name    = ensure_c_str_is_allocated(max_len);
        alg_props->sig_md_name = ensure_c_str_is_allocated(max_len);
        alg_props->impl        = malloc(sizeof(struct aws_cryptosdk_alg_impl));
    }
    return alg_props;
}

struct content_key *ensure_content_key_attempt_allocation() {
    struct content_key *key = malloc(sizeof(uint8_t) * MAX_DATA_KEY_SIZE);
    return key;
}

struct data_key *ensure_data_key_attempt_allocation() {
    struct data_key *key = malloc(sizeof(uint8_t) * MAX_DATA_KEY_SIZE);
    return key;
}

struct aws_cryptosdk_session *ensure_session_attempt_allocation(size_t max_len) {
    struct aws_cryptosdk_session *session = malloc(sizeof(struct aws_cryptosdk_session));
    if (session) {
        session->alloc       = nondet_bool() ? NULL : can_fail_allocator();
        session->cmm         = malloc(sizeof(struct aws_cryptosdk_cmm));
        session->header_copy = malloc(sizeof(uint8_t));
        session->alg_props   = ensure_alg_properties_attempt_allocation(max_len);
        // session->signctx     = ensure_nondet_sig_ctx_has_allocated_members();
    }
    return session;
}

struct aws_cryptosdk_dec_materials *ensure_dec_materials_attempt_allocation() {
    struct aws_cryptosdk_dec_materials *materials = malloc(sizeof(struct aws_cryptosdk_dec_materials));
    if (materials) {
        materials->alloc = nondet_bool() ? NULL : can_fail_allocator();
        // materials->signctx = ensure_nondet_sig_ctx_has_allocated_members();
    }
    return materials;
}

void ensure_record_has_allocated_members(struct aws_cryptosdk_keyring_trace_record *record, size_t max_len) {
    record->wrapping_key_namespace = ensure_string_is_allocated_nondet_length();
    if (record->wrapping_key_namespace) {
        __CPROVER_assume(record->wrapping_key_namespace->len <= max_len);
    }
    record->wrapping_key_name = ensure_string_is_allocated_nondet_length();
    if (record->wrapping_key_name) {
        __CPROVER_assume(record->wrapping_key_name->len <= max_len);
    }
    record->flags = malloc(sizeof(uint32_t));
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

struct aws_cryptosdk_sig_ctx *ensure_nondet_sig_ctx_has_allocated_members() {
    struct aws_cryptosdk_sig_ctx *ctx = malloc(sizeof(*ctx));
    if (ctx == NULL) {
        return NULL;
    }
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
    return ctx;
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
    if (list != NULL) {
        if (list->current_size == 0) {
            __CPROVER_assume(list->data == NULL);
            list->alloc = can_fail_allocator();
        } else {
            size_t max_length = list->current_size / sizeof(struct aws_cryptosdk_edk);
            list->data        = bounded_malloc(sizeof(struct aws_cryptosdk_edk) * max_length);
            list->alloc       = nondet_bool() ? NULL : can_fail_allocator();
        }
    }
}

void ensure_cryptosdk_edk_list_has_allocated_list_elements(struct aws_array_list *list) {
    if (aws_cryptosdk_edk_list_is_valid(list)) {
        for (size_t i = 0; i < list->length; ++i) {
            struct aws_cryptosdk_edk *data = (struct aws_cryptosdk_edk *)list->data;
            ensure_cryptosdk_edk_has_allocated_members(&(data[i]));
        }
    }
}

struct aws_cryptosdk_hdr *ensure_nondet_hdr_has_allocated_members(const size_t max_table_size) {
    struct aws_cryptosdk_hdr *hdr = malloc(sizeof(*hdr));
    if (hdr != NULL) {
        hdr->alloc = nondet_bool() ? NULL : can_fail_allocator();
        ensure_byte_buf_has_allocated_buffer_member(&hdr->iv);
        ensure_byte_buf_has_allocated_buffer_member(&hdr->auth_tag);
        ensure_byte_buf_has_allocated_buffer_member(&hdr->message_id);
        ensure_byte_buf_has_allocated_buffer_member(&hdr->alg_suite_data);
        ensure_allocated_hash_table(&hdr->enc_ctx, max_table_size);
        ensure_cryptosdk_edk_list_has_allocated_list(&hdr->edk_list);
    }
    return hdr;
}

bool aws_cryptosdk_hdr_members_are_bounded(
    const struct aws_cryptosdk_hdr *hdr, const size_t max_edk_item_size, const size_t max_item_size) {
    if (hdr != NULL) {
        /*IV buffer length might need further constraints, this is done in the harness when necessary */
        return aws_cryptosdk_edk_list_is_bounded(&hdr->edk_list, max_edk_item_size) &&
               (!aws_cryptosdk_edk_list_is_valid(&hdr->edk_list) ||
                aws_cryptosdk_edk_list_elements_are_bounded(&hdr->edk_list, max_item_size)) &&
               aws_byte_buf_is_bounded(&hdr->iv, max_item_size) &&
               aws_byte_buf_is_bounded(&hdr->auth_tag, max_item_size) &&
               aws_byte_buf_is_bounded(&hdr->message_id, max_item_size) &&
               aws_byte_buf_is_bounded(&hdr->alg_suite_data, max_item_size);
    }
    return true; /* If hdr is NULL, true by default */
}

struct aws_cryptosdk_hdr *hdr_setup(
    const size_t max_table_size, const size_t max_edk_item_size, const size_t max_item_size) {
    struct aws_cryptosdk_hdr *hdr = ensure_nondet_hdr_has_allocated_members(max_table_size);
    __CPROVER_assume(aws_cryptosdk_hdr_members_are_bounded(hdr, max_edk_item_size, max_item_size));

    /* Precondition: The edk list has allocated list elements */
    ensure_cryptosdk_edk_list_has_allocated_list_elements(&hdr->edk_list);
    __CPROVER_assume(aws_cryptosdk_hdr_is_valid(hdr));

    __CPROVER_assume(hdr->enc_ctx.p_impl != NULL);
    ensure_hash_table_has_valid_destroy_functions(&hdr->enc_ctx);
    return hdr;
}

enum aws_cryptosdk_sha_version aws_cryptosdk_which_sha(enum aws_cryptosdk_alg_id alg_id) {
    switch (alg_id) {
        case ALG_AES256_GCM_HKDF_SHA512_COMMIT_KEY_ECDSA_P384:
        case ALG_AES256_GCM_HKDF_SHA512_COMMIT_KEY: return AWS_CRYPTOSDK_SHA512;
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

void ensure_cryptosdk_keyring_has_allocated_members(
    struct aws_cryptosdk_keyring *keyring, const struct aws_cryptosdk_keyring_vt *vtable) {
    if (keyring) {
        keyring->refcount.value = malloc(sizeof(size_t));
        keyring->vtable         = nondet_bool() ? NULL : vtable;
    }
}

void ensure_nondet_allocate_keyring_vtable_members(struct aws_cryptosdk_keyring_vt *vtable, size_t max_len) {
    if (vtable) {
        vtable->name = ensure_c_str_is_allocated(max_len);
    }
}

void ensure_nondet_allocate_cmm_vtable_members(struct aws_cryptosdk_cmm_vt *vtable, size_t max_len) {
    if (vtable) {
        vtable->name = ensure_c_str_is_allocated(max_len);
    }
}
