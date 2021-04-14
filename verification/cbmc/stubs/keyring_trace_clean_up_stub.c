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

#include <aws/cryptosdk/edk.h>

#include <proof_helpers/make_common_data_structures.h>

/* Stub this until https://github.com/diffblue/cbmc/issues/5344 is fixed
 Original function is here:
 https://github.com/aws/aws-encryption-sdk-c/blob/master/source/edk.c#L44 */
void aws_cryptosdk_edk_list_clean_up(struct aws_array_list *encrypted_data_keys) {
    assert(aws_cryptosdk_edk_list_is_valid(encrypted_data_keys));
    aws_array_list_clean_up(encrypted_data_keys);
}
