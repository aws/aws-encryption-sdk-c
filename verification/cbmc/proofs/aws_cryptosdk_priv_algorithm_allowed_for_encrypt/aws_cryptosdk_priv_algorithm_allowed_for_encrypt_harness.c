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

#include <aws/cryptosdk/private/session.h>
#include <aws/cryptosdk/session.h>
#include <make_common_data_structures.h>

void aws_cryptosdk_priv_algorithm_allowed_for_encrypt_harness() {
    /* Nondet Input */
    enum aws_cryptosdk_alg_id alg_id;
    enum aws_cryptosdk_commitment_policy policy;

    /* Assumptions */
    __CPROVER_assume(aws_cryptosdk_commitment_policy_is_valid(policy));

    /* Function under test */
    aws_cryptosdk_priv_algorithm_allowed_for_encrypt(alg_id, policy);

    /* Assertions */
    assert(aws_cryptosdk_commitment_policy_is_valid(policy));
}
