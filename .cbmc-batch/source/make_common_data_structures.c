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

#include <cipher_openssl.h>
#include <ec_utils.h>
#include <evp_utils.h>

#include <proof_helpers/make_common_data_structures.h>
#include <proof_helpers/cryptosdk/make_common_data_structures.h>
#include <proof_helpers/proof_allocators.h>

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


bool aws_cryptosdk_edk_is_bounded(const struct aws_cryptosdk_edk* edk, const size_t max_size){
  return aws_byte_buf_is_bounded(&edk->provider_id, max_size) &&
    aws_byte_buf_is_bounded(&edk->provider_info, max_size) &&
    aws_byte_buf_is_bounded(&edk->ciphertext, max_size);
}

void ensure_cryptosdk_edk_has_allocated_members(struct aws_cryptosdk_edk* edk){
  ensure_byte_buf_has_allocated_buffer_member(&edk->provider_id);
  ensure_byte_buf_has_allocated_buffer_member(&edk->provider_info);
  ensure_byte_buf_has_allocated_buffer_member(&edk->ciphertext);
}
