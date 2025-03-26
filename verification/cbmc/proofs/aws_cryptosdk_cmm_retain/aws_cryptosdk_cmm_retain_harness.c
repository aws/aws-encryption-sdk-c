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
#include <proof_helpers/utils.h>

void aws_cryptosdk_cmm_retain_harness() {
    const struct aws_cryptosdk_cmm_vt vtable = { .vt_size                = sizeof(struct aws_cryptosdk_cmm_vt),
                                                 .name                   = ensure_c_str_is_allocated(SIZE_MAX),
                                                 .destroy                = nondet_voidp(),
                                                 .generate_enc_materials = nondet_voidp(),
                                                 .decrypt_materials      = nondet_voidp() };
    __CPROVER_assume(aws_cryptosdk_cmm_vtable_is_valid(&vtable));

    struct aws_cryptosdk_cmm cmm;  // Precondition: non-null
    cmm.vtable = &vtable;
    __CPROVER_assume(aws_cryptosdk_cmm_base_is_valid(&cmm));
    __CPROVER_assume(AWS_ATOMIC_VAR_INTVAL(&cmm.refcount) < SIZE_MAX);
    aws_cryptosdk_cmm_retain(&cmm);
}
