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

#include <aws/cryptosdk/materials.h>
#include <proof_helpers/cryptosdk/make_common_data_structures.h>
#include <proof_helpers/make_common_data_structures.h>
#include <proof_helpers/proof_allocators.h>
#include <proof_helpers/utils.h>

void aws_cryptosdk_cmm_base_init_harness() {
    /* Nondet input */
    struct aws_cryptosdk_cmm cmm;
    const struct aws_cryptosdk_cmm_vt vtable;

    /* Assumptions */
    *(char **)(&vtable.name) = ensure_c_str_is_allocated(SIZE_MAX);
    __CPROVER_assume(aws_cryptosdk_cmm_vtable_is_valid(&vtable));

    /* Operation under verification */
    aws_cryptosdk_cmm_base_init(&cmm, &vtable);

    /* Post-conditions */
    assert(aws_cryptosdk_cmm_base_is_valid(&cmm));
}
