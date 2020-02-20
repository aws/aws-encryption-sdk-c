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

void aws_cryptosdk_sig_update_harness() {
    /* arguments */
    struct aws_cryptosdk_sig_ctx *ctx = can_fail_malloc(sizeof(struct aws_cryptosdk_sig_ctx));
    struct aws_byte_cursor buf;

    /* assumptions */
    __CPROVER_assume(ctx);
    ensure_sig_ctx_has_allocated_members(ctx);
    __CPROVER_assume(aws_cryptosdk_sig_ctx_is_valid_cbmc(ctx));
    ensure_byte_cursor_has_allocated_buffer_member(&buf);
    __CPROVER_assume(aws_byte_cursor_is_valid(&buf));

    /* operation under verification */
    if (aws_cryptosdk_sig_update(ctx, buf) == AWS_OP_SUCCESS) {
        /* assertions */
        assert(aws_cryptosdk_sig_ctx_is_valid_cbmc(ctx));
    }

    /* assertions */
    assert(aws_byte_cursor_is_valid(&buf));

    /* clean up (necessary because we are checking for memory leaks) */
    free(buf.ptr);
    ec_key_unconditional_free(ctx->keypair);
    evp_pkey_unconditional_free(ctx->pkey);
    evp_md_ctx_shallow_free(ctx->ctx);
    free(ctx);
}
