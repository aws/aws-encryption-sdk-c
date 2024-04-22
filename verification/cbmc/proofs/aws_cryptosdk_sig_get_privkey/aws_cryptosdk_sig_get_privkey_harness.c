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

#include <cipher_openssl.h>

void aws_cryptosdk_sig_get_privkey_harness() {
    /* Nondet Input */
    struct aws_cryptosdk_sig_ctx *ctx = ensure_nondet_sig_ctx_has_allocated_members();
    struct aws_allocator *alloc       = aws_default_allocator();
    struct aws_string *priv_key       = ensure_string_is_allocated_nondet_length();

    /* Assumptions */
    __CPROVER_assume(aws_cryptosdk_sig_ctx_is_valid_cbmc(ctx));
    __CPROVER_assume(ctx->is_sign);  // context has to be in signing mode, otherwise private key is NULL
    __CPROVER_assume(AWS_OBJECT_PTR_IS_READABLE(priv_key));

    /* Operation under verification */
    if (aws_cryptosdk_sig_get_privkey(ctx, alloc, &priv_key) == AWS_OP_SUCCESS) {
        assert(aws_string_is_valid(priv_key));
    } else {
        assert(!priv_key);
    }

    /* Post-conditions */
    assert(aws_cryptosdk_sig_ctx_is_valid_cbmc(ctx));
}
