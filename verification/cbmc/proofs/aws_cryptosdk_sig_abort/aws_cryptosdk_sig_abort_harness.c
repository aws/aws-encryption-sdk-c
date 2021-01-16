/*
 * Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License").
 * You may not use this file except in compliance with the License.
 * A copy of the License is located at
 *
 *  http://aws.amazon.com/apache2.0
 *
 * or in the "license" file accompanying this file. This file is distributed
 * on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
 * express or implied. See the License for the specific language governing
 * permissions and limitations under the License.
 */

#include <aws/cryptosdk/cipher.h>
#include <cbmc_invariants.h>
#include <ec_utils.h>
#include <evp_utils.h>
#include <make_common_data_structures.h>
#include <proof_allocators.h>
#include <proof_helpers/proof_allocators.h>

#include <cipher_openssl.h>

void aws_cryptosdk_sig_abort_harness() {
    /* arguments */
    struct aws_cryptosdk_sig_ctx *ctx = ensure_nondet_sig_ctx_has_allocated_members();
    __CPROVER_assume(aws_cryptosdk_sig_ctx_is_valid_cbmc(ctx));

    /* saving previous state */
    EC_KEY *keypair                 = ctx ? ctx->keypair : NULL;
    int old_keypair_reference_count = ec_key_get_reference_count(keypair);
    bool keypair_needs_clean_up     = old_keypair_reference_count > 2;
    EVP_PKEY *pkey                  = ctx ? ctx->pkey : NULL;
    int old_pkey_reference_count    = evp_pkey_get_reference_count(pkey);
    int min_pkey_reference_count    = !ctx ? 0 : (ctx->is_sign ? 1 : 2);
    bool pkey_needs_clean_up        = old_pkey_reference_count > min_pkey_reference_count;

    /* operation under verification */
    aws_cryptosdk_sig_abort(ctx);

    if (pkey_needs_clean_up) {
        // assertions
        assert(evp_pkey_get_reference_count(pkey) == old_pkey_reference_count - min_pkey_reference_count);
        assert(ec_key_get_reference_count(keypair) == old_keypair_reference_count - 1);
        // clean up (necessary because we are checking for memory leaks)
        evp_pkey_unconditional_free(pkey);
        // pkey holds a reference to keypair, have to free that too
        ec_key_unconditional_free(keypair);
    } else if (keypair_needs_clean_up) {
        // pkey was freed, but keypair was not

        // assertions
        assert(ec_key_get_reference_count(keypair) == old_keypair_reference_count - 2);
        // clean up (necessary because we are checking for memory leaks)
        ec_key_unconditional_free(keypair);
    }
}
