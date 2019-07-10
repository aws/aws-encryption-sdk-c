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
#include <make_common_data_structures.h>

void ensure_alg_properties_has_allocated_names(struct aws_cryptosdk_alg_properties *const alg_props) {
    size_t md_name_size;
    alg_props->md_name = can_fail_malloc(md_name_size);
    size_t cipher_name_size;
    alg_props->cipher_name = can_fail_malloc(cipher_name_size);
    size_t alg_name_size;
    alg_props->alg_name = can_fail_malloc(alg_name_size);
}

void ensure_sig_ctx_has_allocated_members(struct aws_cryptosdk_sig_ctx *ctx) {
    ctx->keypair = EC_KEY_new();
    ctx->pkey    = EVP_PKEY_new();
    ctx->ctx     = EVP_MD_CTX_new();

    // initialize members nondeterministically
    if (ctx->keypair) ec_key_nondet_init(ctx->keypair);
    if (ctx->pkey) evp_pkey_nondet_init(ctx->pkey);
    if (ctx->ctx) evp_md_ctx_nondet_init(ctx->ctx);
}
