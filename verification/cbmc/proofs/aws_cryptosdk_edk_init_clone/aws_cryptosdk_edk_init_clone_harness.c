/*
 * Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
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

#include <aws/cryptosdk/edk.h>
#include <proof_helpers/cryptosdk/make_common_data_structures.h>
#include <proof_helpers/make_common_data_structures.h>
#include <proof_helpers/utils.h>

void aws_cryptosdk_edk_init_clone_harness() {
    struct aws_array_list edk_list;

    struct aws_allocator *alloc = aws_default_allocator();  // Precondition: valid allocator
    __CPROVER_assume(aws_allocator_is_valid(alloc));

    struct aws_cryptosdk_edk dest;  // Precondition: non-null

    const struct aws_cryptosdk_edk src;  // Precondition: non-null
    ensure_cryptosdk_edk_has_allocated_members(&src);
    __CPROVER_assume(aws_cryptosdk_edk_is_valid(&src));  // Precondition: is_valid()

    int rval = aws_cryptosdk_edk_init_clone(alloc, &dest, &src);
    assert(aws_cryptosdk_edk_is_valid(&src));
    assert(aws_allocator_is_valid(alloc));
    if (rval == AWS_OP_SUCCESS) {
        assert(aws_cryptosdk_edk_is_valid(&dest));
    }
}
