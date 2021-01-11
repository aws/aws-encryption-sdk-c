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

#include <aws/cryptosdk/private/header.h>

#include <proof_helpers/make_common_data_structures.h>

/**
 * The original aws_cryptosdk_hdr_write function declares an aws_byte_buf
 * output variable where different components of the header get written,
 * however, the actual output of the function is bytes_written. Therefore,
 * we assign a nondeterministic value to bytes_written in case of success
 * or zero both outbuf and outlen in case of failure.
 */
int aws_cryptosdk_hdr_write(
    const struct aws_cryptosdk_hdr *hdr, size_t *bytes_written, uint8_t *outbuf, size_t outlen) {
    assert(aws_cryptosdk_hdr_is_valid(hdr));
    assert(hdr->iv.len <= UINT8_MAX);  // uint8_t max value
    assert(outlen == 0 || AWS_MEM_IS_READABLE(outbuf, outlen));
    assert(bytes_written != NULL);

    if (nondet_bool()) {
        size_t nondet_size;
        __CPROVER_assume(nondet_size < MAX_BUFFER_SIZE);
        *bytes_written = nondet_size;
        return AWS_OP_SUCCESS;
    } else {
        int error = nondet_bool() ? AWS_CRYPTOSDK_ERR_BAD_STATE : AWS_ERROR_SHORT_BUFFER;
        aws_secure_zero(outbuf, outlen);
        *bytes_written = 0;
        return aws_raise_error(error);
    }
}
