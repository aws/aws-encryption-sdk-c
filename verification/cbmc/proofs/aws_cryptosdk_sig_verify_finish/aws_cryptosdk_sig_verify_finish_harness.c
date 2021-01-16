/*
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
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
#include <cipher_openssl.h>
#include <ec_utils.h>
#include <evp_utils.h>
#include <make_common_data_structures.h>
#include <proof_allocators.h>
#include <proof_helpers/proof_allocators.h>

void aws_cryptosdk_sig_verify_finish_harness() {
    /* Nondet Input */
    struct aws_cryptosdk_sig_ctx *ctx = ensure_nondet_sig_ctx_has_allocated_members();
    struct aws_string *signature      = ensure_string_is_allocated_nondet_length();

    __CPROVER_assume(aws_cryptosdk_sig_ctx_is_valid_cbmc(ctx));
    __CPROVER_assume(aws_string_is_valid(signature));

    /* Saving state */
    EC_KEY *keypair        = ctx->keypair;
    int keypair_references = ec_key_get_reference_count(keypair);
    EVP_PKEY *pkey         = ctx->pkey;
    int pkey_references    = evp_pkey_get_reference_count(pkey);

    /* Operation under verification */
    aws_cryptosdk_sig_verify_finish(ctx, signature);
}
