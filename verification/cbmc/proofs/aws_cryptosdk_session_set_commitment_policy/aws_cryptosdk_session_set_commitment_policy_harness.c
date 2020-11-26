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

void aws_cryptosdk_session_set_commitment_policy_harness() {
    /* Nondet Input */
    struct aws_cryptosdk_session *session = malloc(sizeof(*session));
    enum aws_cryptosdk_commitment_policy policy;

    /* Assumptions */
    __CPROVER_assume(session != NULL);

    /* Function under test */
    if (aws_cryptosdk_session_set_commitment_policy(session, policy) == AWS_OP_SUCCESS) {
        /* Assertions */
        assert(aws_cryptosdk_commitment_policy_is_valid(session->commitment_policy));
        assert(session->state == ST_CONFIG);
    } else {
        /* Assertions */
        assert(session->state == ST_ERROR || !aws_cryptosdk_commitment_policy_is_valid(session->commitment_policy));
    }

    /* Assertions */
    assert(session->commitment_policy == policy);
}
