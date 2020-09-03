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

#include <ec_utils.h>
#include <make_common_data_structures.h>

/*
 * Checks whether EVP_MD_CTX is a valid object.
 * Use this stub when we are certain there is no pkey
 * associated with the digest context.
 */
bool evp_md_ctx_is_valid(EVP_MD_CTX *ctx) {
	assert(ctx->pkey == NULL);
    return ctx && ctx->is_initialized && ctx->digest_size <= EVP_MAX_MD_SIZE;
}
