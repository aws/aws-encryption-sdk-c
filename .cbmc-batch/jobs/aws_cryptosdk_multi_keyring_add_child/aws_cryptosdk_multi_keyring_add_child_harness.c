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

#include <aws/cryptosdk/materials.h>
#include <aws/cryptosdk/multi_keyring.h>
#include "proof_helpers/proof_allocators.h"

void aws_cryptosdk_multi_keyring_add_child_harness() {
    /* Non-deterministic inputs. */
    struct aws_allocator *alloc = can_fail_allocator();
    struct aws_cryptosdk_keyring generator;
    aws_cryptosdk_keyring_base_init(&generator, NULL);
    struct multi_keyring *multi = aws_cryptosdk_multi_keyring_new(alloc, &generator);

    struct aws_cryptosdk_keyring child;
    aws_cryptosdk_keyring_base_init(&child, NULL);

    /* Assumptions. */
    __CPROVER_assume(aws_cryptosdk_keyring_is_valid(multi));
    __CPROVER_assume(aws_cryptosdk_keyring_is_valid(&child));

    /* Operation under verification. */
    if (aws_cryptosdk_multi_keyring_add_child(multi, &child) == AWS_OP_SUCCESS) {
        assert(aws_array_list_length(&multi->children) > 0);
    }

    /* Post-conditions. */
    assert(aws_cryptosdk_keyring_is_valid(multi));
    assert(aws_cryptosdk_keyring_is_valid(&child));
}
