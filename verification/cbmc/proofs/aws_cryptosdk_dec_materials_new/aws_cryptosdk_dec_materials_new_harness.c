/*
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"). You may not
 * use
 * this file except in compliance with the License. A copy of the License is
 * located at
 *
 *     http://aws.amazon.com/apache2.0/
 *
 * or in the "license" file accompanying this file. This file is distributed on
 * an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express
 * or
 * implied. See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <aws/cryptosdk/materials.h>
#include <cipher_openssl.h>
#include <proof_helpers/cryptosdk/make_common_data_structures.h>
#include <proof_helpers/make_common_data_structures.h>
#include <proof_helpers/proof_allocators.h>
#include <proof_helpers/utils.h>

void aws_cryptosdk_dec_materials_new_harness() {
    struct aws_allocator *alloc = can_fail_allocator();
    enum aws_cryptosdk_alg_id alg;

    struct aws_cryptosdk_dec_materials *rval = aws_cryptosdk_dec_materials_new(alloc, alg);
    if (rval) {
        assert(aws_cryptosdk_dec_materials_is_valid(rval));
    }
}
