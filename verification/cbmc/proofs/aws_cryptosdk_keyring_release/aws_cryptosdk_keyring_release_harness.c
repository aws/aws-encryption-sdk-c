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

#include <aws/cryptosdk/materials.h>
#include <make_common_data_structures.h>

void destroy(struct aws_cryptosdk_keyring *keyring) {
    assert(keyring != NULL);
    free(keyring);
}

void aws_cryptosdk_keyring_release_harness() {
    /* Non-deterministic inputs. */
    const struct aws_cryptosdk_keyring_vt vtable = { .vt_size    = sizeof(struct aws_cryptosdk_keyring_vt),
                                                     .name       = ensure_c_str_is_allocated(SIZE_MAX),
                                                     .destroy    = nondet_bool() ? destroy : NULL,
                                                     .on_encrypt = nondet_voidp(),
                                                     .on_decrypt = nondet_voidp() };
    struct aws_cryptosdk_keyring *keyring        = malloc(sizeof(*keyring));

    /* Pre-conditions. */
    if (keyring != NULL) {
        ensure_cryptosdk_keyring_has_allocated_members(keyring, &vtable);
        __CPROVER_assume(aws_cryptosdk_keyring_is_valid(keyring));
        __CPROVER_assume(keyring->vtable != NULL);
    }

    /* Operation under verification. */
    aws_cryptosdk_keyring_release(keyring);
}
