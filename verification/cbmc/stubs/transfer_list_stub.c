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

#include <aws/cryptosdk/list_utils.h>

#include <proof_helpers/make_common_data_structures.h>

/* Stub this because of the override of aws_array_list_get_at_ptr and for performance.
 The contents of session->keyring_trace are nondet in the construction of the harness.
 Also neither keyring trace is later used.
 Original function is here:
 https://github.com/aws/aws-encryption-sdk-c/blob/master/source/list_utils.c#L17 */
int aws_cryptosdk_transfer_list(struct aws_array_list *dest, struct aws_array_list *src) {
    assert(src != dest);
    assert(aws_array_list_is_valid(dest));
    assert(aws_array_list_is_valid(src));
    assert(dest->item_size == src->item_size);

    if (nondet_bool()) {
        return AWS_OP_ERR;
    }
    return AWS_OP_SUCCESS;
}
