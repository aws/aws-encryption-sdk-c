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

#include <cbmc_invariants.h>

#include <ec_utils.h>
#include <evp_utils.h>

#include <cipher_openssl.h>

bool aws_cryptosdk_md_context_is_valid_cbmc(struct aws_cryptosdk_md_context *md_context) {
    return aws_cryptosdk_md_context_is_valid(md_context) && evp_md_ctx_is_valid(md_context->evp_md_ctx);
}

bool aws_cryptosdk_sig_ctx_is_valid_cbmc(struct aws_cryptosdk_sig_ctx *sig_ctx) {
    return aws_cryptosdk_sig_ctx_is_valid(sig_ctx) && ec_key_is_valid(sig_ctx->keypair) &&
           evp_pkey_is_valid(sig_ctx->pkey) && evp_md_ctx_is_valid(sig_ctx->ctx) &&
           // The EVP_PKEY has a reference to the EC_KEY
           (ec_key_get_reference_count(sig_ctx->keypair) >= 2) &&
           // If the context is in verify mode, the EVP_MD_CTX holds an extra reference to the EVP_PKEY
           (evp_pkey_get_reference_count(sig_ctx->pkey) >= (sig_ctx->is_sign ? 1 : 2)) &&
           (evp_md_ctx_get0_evp_pkey(sig_ctx->ctx) == (sig_ctx->is_sign ? NULL : sig_ctx->pkey));
}
