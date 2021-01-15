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

#include <aws/cryptosdk/private/hkdf.h>

#include <proof_helpers/make_common_data_structures.h>

/* Stub this for performance but check the preconditions.
 No modified data structure is used again.
 Original function is here:
 https://github.com/aws/aws-encryption-sdk-c/blob/master/source/hkdf.c#148 */
int aws_cryptosdk_hkdf(
    struct aws_byte_buf *okm,
    enum aws_cryptosdk_sha_version which_sha,
    const struct aws_byte_buf *salt,
    const struct aws_byte_buf *ikm,
    const struct aws_byte_buf *info) {
    assert(aws_byte_buf_is_valid(okm));
    assert(aws_byte_buf_is_valid(salt));
    assert(aws_byte_buf_is_valid(ikm));
    assert(aws_byte_buf_is_valid(info));
    if (nondet_bool()) {
        return AWS_OP_ERR;
    }
    return AWS_OP_SUCCESS;
}
