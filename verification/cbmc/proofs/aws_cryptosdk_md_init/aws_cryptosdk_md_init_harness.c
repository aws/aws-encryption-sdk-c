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
#include <evp_utils.h>
#include <proof_helpers/make_common_data_structures.h>

#include <cipher_openssl.h>

/* Expected runtime 45s */
void aws_cryptosdk_md_init_harness() {
    /* arguments */
    struct aws_allocator *alloc;
    struct aws_cryptosdk_md_context *md_context;
    enum aws_cryptosdk_md_alg md_alg;

    /* assumptions */
    alloc = aws_default_allocator();

    /* operation under verification */
    if (aws_cryptosdk_md_init(alloc, &md_context, md_alg) == AWS_OP_SUCCESS) {
        /* assertions */
        assert(aws_cryptosdk_md_context_is_valid_cbmc(md_context));
    }

    /* clean up (necessary because we are checking for memory leaks) */
    if (md_context) {
        EVP_MD_CTX_free(md_context->evp_md_ctx);
        aws_mem_release(alloc, md_context);
    }
    assert(aws_allocator_is_valid(alloc));
}
