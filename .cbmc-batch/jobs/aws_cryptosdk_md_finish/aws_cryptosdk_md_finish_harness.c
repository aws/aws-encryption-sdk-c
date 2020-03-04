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

#include <aws/cryptosdk/private/cipher.h>
#include <cbmc_invariants.h>
#include <evp_utils.h>
#include <make_common_data_structures.h>
#include <proof_helpers/proof_allocators.h>

#include <cipher_openssl.h>

/* Expected runtime 1m20s */
void aws_cryptosdk_md_finish_harness() {
    /* arguments */
    struct aws_cryptosdk_md_context *md_context = can_fail_malloc(sizeof(struct aws_cryptosdk_md_context));
    size_t length;
    size_t buf_size;
    void *buf = can_fail_malloc(buf_size);

    /* assumptions */
    __CPROVER_assume(md_context);
    ensure_md_context_has_allocated_members(md_context);
    __CPROVER_assume(evp_md_ctx_get0_evp_pkey(md_context->evp_md_ctx) == NULL);
    __CPROVER_assume(aws_cryptosdk_md_context_is_valid_cbmc(md_context));
    __CPROVER_assume(buf);
    size_t digest_size = evp_md_ctx_get_digest_size(md_context->evp_md_ctx);
    __CPROVER_assume(length >= digest_size);
    __CPROVER_assume(buf_size >= length);

    /* operation under verification */
    if (aws_cryptosdk_md_finish(md_context, buf, &length) == AWS_OP_SUCCESS) {
        assert(length == digest_size);
    } else {
        assert(length == 0);
    }

    /* clean up (necessary because we are checking for memory leaks) */
    free(buf);
}
