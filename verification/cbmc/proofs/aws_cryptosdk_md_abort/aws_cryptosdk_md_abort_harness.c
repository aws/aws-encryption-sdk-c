/*
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
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
#include <cipher_openssl.h>
#include <evp_utils.h>
#include <make_common_data_structures.h>
#include <proof_helpers/proof_allocators.h>

/* Expected runtime: 40 seconds */
void aws_cryptosdk_md_abort_harness() {
    /* arguments */
    struct aws_cryptosdk_md_context *md_context = can_fail_malloc(sizeof(struct aws_cryptosdk_md_context));

    /* assumptions */
    if (md_context) {
        ensure_md_context_has_allocated_members(md_context);
        __CPROVER_assume(evp_md_ctx_get0_evp_pkey(md_context->evp_md_ctx) == NULL);
        __CPROVER_assume(aws_cryptosdk_md_context_is_valid_cbmc(md_context));
    }

    /* operation under verification */
    aws_cryptosdk_md_abort(md_context);
    /* After the abort, the md_context is now invalid. Nothing to assert here */
}
