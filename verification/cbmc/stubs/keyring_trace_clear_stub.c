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

#include <aws/cryptosdk/keyring_trace.h>

#include <proof_helpers/make_common_data_structures.h>

/* Stub this because of the override of aws_array_list_get_at_ptr
 Original function is here:
 https://github.com/aws/aws-encryption-sdk-c/blob/master/source/keyring_trace.c#L235 */
void aws_cryptosdk_keyring_trace_clear(struct aws_array_list *trace) {
    AWS_FATAL_PRECONDITION(aws_cryptosdk_keyring_trace_is_valid(trace));
    AWS_FATAL_PRECONDITION(trace->item_size == sizeof(struct aws_cryptosdk_keyring_trace_record));
    aws_array_list_clear(trace);
}
