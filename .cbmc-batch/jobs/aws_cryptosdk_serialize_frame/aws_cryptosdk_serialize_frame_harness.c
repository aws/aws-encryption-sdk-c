/*
 * Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
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

#include <aws/common/byte_buf.h>
#include <aws/cryptosdk/private/framefmt.h>
#include <make_common_data_structures.h>
#include <proof_helpers/make_common_data_structures.h>

void harness() {
    /* data structure */
    struct aws_cryptosdk_frame frame;
    size_t ciphertext_size;
    size_t plaintext_size;
    struct aws_byte_buf ciphertext_buf;
    struct aws_cryptosdk_alg_properties alg_props;

    /* Assumptions about the function input */
    ensure_byte_buf_has_allocated_buffer_member(&ciphertext_buf);
    __CPROVER_assume(aws_byte_buf_is_valid(&ciphertext_buf));

    ensure_alg_properties_has_allocated_names(&alg_props);
    __CPROVER_assume(aws_cryptosdk_alg_properties_is_valid(&alg_props));

    /* Save the old state of the ciphertext buffer */
    uint8_t *old_ciphertext_buffer   = ciphertext_buf.buffer;
    size_t old_ciphertext_buffer_len = ciphertext_buf.len;

    int rval = aws_cryptosdk_serialize_frame(&frame, &ciphertext_size, plaintext_size, &ciphertext_buf, &alg_props);
    if (rval == AWS_OP_SUCCESS) {
        assert(aws_cryptosdk_frame_is_valid(&frame));
        assert(ciphertext_buf.buffer == old_ciphertext_buffer);
        assert(ciphertext_buf.len == old_ciphertext_buffer_len + ciphertext_size);
    } else {
        // Assert that the ciphertext buffer is zeroed in case of failure
        assert_all_zeroes(ciphertext_buf.buffer, ciphertext_buf.capacity);
        assert(ciphertext_buf.len == 0);
    }   
}
