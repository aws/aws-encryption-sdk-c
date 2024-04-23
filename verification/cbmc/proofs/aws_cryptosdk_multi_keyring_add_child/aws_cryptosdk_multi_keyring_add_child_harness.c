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
#include <aws/cryptosdk/private/multi_keyring.h>

#include <make_common_data_structures.h>
#include <proof_helpers/make_common_data_structures.h>
#include <proof_helpers/proof_allocators.h>

void aws_cryptosdk_multi_keyring_add_child_harness() {
    /* Non-deterministic inputs to initialize a multi_keyring object. */
    const struct aws_cryptosdk_keyring_vt vtable_generator = { .vt_size    = sizeof(struct aws_cryptosdk_keyring_vt),
                                                               .name       = ensure_c_str_is_allocated(SIZE_MAX),
                                                               .destroy    = nondet_voidp(),
                                                               .on_encrypt = nondet_voidp(),
                                                               .on_decrypt = nondet_voidp() };
    struct aws_cryptosdk_keyring generator;
    ensure_cryptosdk_keyring_has_allocated_members(&generator, &vtable_generator);
    __CPROVER_assume(aws_cryptosdk_keyring_is_valid(&generator));

    struct aws_allocator *alloc = can_fail_allocator();

    /*
     * We inject non-deterministic parameters in aws_cryptosdk_multi_keyring_new to ensure
     * that multi_keyring is allocated. We use the initializer because a multi_keyring
     * structure must have as base member the static aws_cryptosdk_keyring_vt (vt) defined
     * in the multi_keyring.c file.
     */
    struct aws_cryptosdk_keyring *multi = aws_cryptosdk_multi_keyring_new(alloc, &generator);
    __CPROVER_assume(aws_cryptosdk_multi_keyring_is_valid(multi));

    const struct aws_cryptosdk_keyring_vt vtable_child = { .vt_size    = sizeof(struct aws_cryptosdk_keyring_vt),
                                                           .name       = ensure_c_str_is_allocated(SIZE_MAX),
                                                           .destroy    = nondet_voidp(),
                                                           .on_encrypt = nondet_voidp(),
                                                           .on_decrypt = nondet_voidp() };
    struct aws_cryptosdk_keyring child;
    ensure_cryptosdk_keyring_has_allocated_members(&child, &vtable_child);
    __CPROVER_assume(aws_cryptosdk_keyring_is_valid(&child));

    /* save current state of the data structure */
    struct aws_array_list old = ((struct multi_keyring *)multi)->children;

    /* Operation under verification. */
    if (aws_cryptosdk_multi_keyring_add_child(multi, &child) == AWS_OP_SUCCESS) {
        assert(((struct multi_keyring *)multi)->children.length == (old.length + 1));
    } else {
        assert(((struct multi_keyring *)multi)->children.length == old.length);
    }

    /* Post-conditions. */
    assert(aws_cryptosdk_multi_keyring_is_valid(multi));
    assert(aws_cryptosdk_keyring_is_valid(&child));
}
