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

void aws_cryptosdk_edk_eq_harness() {
    const struct aws_cryptosdk_edk a;  // Precondition: non-null
    ensure_cryptosdk_edk_has_allocated_members(&a);
    __CPROVER_assume(aws_cryptosdk_edk_is_valid(&a));  // Precondition: is_valid()

    const struct aws_cryptosdk_edk b;  // Precondition: non-null
    ensure_cryptosdk_edk_has_allocated_members(&b);
    __CPROVER_assume(aws_cryptosdk_edk_is_valid(&b));  // Precondition: is_valid()

    bool rval = aws_cryptosdk_edk_eq(&a, &b);
    assert(aws_cryptosdk_edk_is_valid(&a));
    assert(aws_cryptosdk_edk_is_valid(&b));
}
