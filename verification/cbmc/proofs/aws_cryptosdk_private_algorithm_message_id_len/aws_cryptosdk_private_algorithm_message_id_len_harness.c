/*
 * Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
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

#include <aws/cryptosdk/private/cipher.h>
#include <make_common_data_structures.h>

void aws_cryptosdk_private_algorithm_message_id_len_harness() {
    /* Nondet Input */
    struct aws_cryptosdk_alg_properties *props = ensure_alg_properties_attempt_allocation(MAX_STRING_LEN);;

    /* Assumptions */
    __CPROVER_assume(aws_cryptosdk_alg_properties_is_valid(props));

    /* Operation under verification */
    size_t message_id_len = aws_cryptosdk_private_algorithm_message_id_len(props);

    /* Postconditions */
    assert(aws_cryptosdk_alg_properties_is_valid(props));
    assert(IMPLIES(props->msg_format_version == AWS_CRYPTOSDK_HEADER_VERSION_1_0, message_id_len == MSG_ID_LEN));
    assert(IMPLIES(props->msg_format_version == AWS_CRYPTOSDK_HEADER_VERSION_2_0, message_id_len == MSG_ID_LEN_V2));
}
