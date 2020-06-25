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
#include <cbmc_invariants.h>
#include <ec_utils.h>
#include <evp_utils.h>
#include <make_common_data_structures.h>
#include <proof_allocators.h>
#include <proof_helpers/proof_allocators.h>

#include <cipher_openssl.h>

void aws_cryptosdk_sig_sign_finish_harness() {
    /* arguments */
    struct aws_cryptosdk_sig_ctx *ctx = can_fail_malloc(sizeof(struct aws_cryptosdk_sig_ctx));
    struct aws_allocator *alloc       = can_fail_allocator();
    struct aws_string *signature;
    /* Max signature size is queried inside the function. This call initializes the value nondeterministically. */
    initialize_max_signature_size();

    /* assumptions */
    __CPROVER_assume(ctx);
    ensure_sig_ctx_has_allocated_members(ctx);
    __CPROVER_assume(ctx->alloc);
    __CPROVER_assume(aws_cryptosdk_sig_ctx_is_valid_cbmc(ctx));
    __CPROVER_assume(ctx->is_sign);
    /* Reference count of pkey is incremented and decremented inside the function. This is an overestimation; reference
     * count is never expected to go above the single digits. */
    __CPROVER_assume(evp_pkey_get_reference_count(ctx->pkey) < INT_MAX);

    /* saving previous state */
    EC_KEY *keypair                 = ctx->keypair;
    int old_keypair_reference_count = ec_key_get_reference_count(keypair);
    bool keypair_needs_clean_up     = old_keypair_reference_count > 2;
    EVP_PKEY *pkey                  = ctx->pkey;
    int old_pkey_reference_count    = evp_pkey_get_reference_count(pkey);
    bool pkey_needs_clean_up        = old_pkey_reference_count > 1;

    /* operation under verification */
    if (aws_cryptosdk_sig_sign_finish(ctx, alloc, &signature) == AWS_OP_SUCCESS) {
        /* assertions */
        assert(aws_string_is_valid(signature));
    } else {
        assert(!signature);
    }
}
