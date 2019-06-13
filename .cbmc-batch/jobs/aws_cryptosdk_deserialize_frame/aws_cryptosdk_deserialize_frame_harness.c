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

void aws_cryptosdk_deserialize_frame_harness() {
    /* Data structures */
    struct aws_cryptosdk_frame frame;
    size_t ciphertext_size;
    size_t plaintext_size;
    struct aws_byte_cursor ciphertext_buf;
    enum aws_cryptosdk_alg_id id;
    struct aws_cryptosdk_alg_properties *alg_props = aws_cryptosdk_alg_props(id);
    uint32_t max_frame_size;

    /* Assumptions about the function inputs */
    ensure_byte_cursor_has_allocated_buffer_member(&ciphertext_buf);
    __CPROVER_assume(aws_byte_cursor_is_valid(&ciphertext_buf));
    __CPROVER_assume(aws_cryptosdk_alg_properties_is_valid(alg_props));

    /* Save the old state of the ciphertext cursor */
    uint8_t *old_ciphertext_buffer      = ciphertext_buf.ptr;
    size_t old_ciphertext_buffer_length = ciphertext_buf.len;

    size_t number_of_bytes_read;

    /* Operation being verified */
    if (aws_cryptosdk_deserialize_frame(
            &frame, &ciphertext_size, &plaintext_size, &ciphertext_buf, alg_props, max_frame_size) == AWS_OP_SUCCESS) {
        assert(aws_cryptosdk_frame_is_valid(&frame));
        if (max_frame_size == 0) {
            // non-framed case
            assert(frame.sequence_number == 1);
            assert(frame.type == FRAME_TYPE_SINGLE);
            // Reads: IV, encrypted content length (8 bytes), encrypted content, authentication tag
            number_of_bytes_read = alg_props->iv_len + 8 + plaintext_size + alg_props->tag_len;
        } else {
            // framed case
            if (frame.type == FRAME_TYPE_FRAME) {
                assert(plaintext_size == max_frame_size);
                // Reads: sequence number (4 bytes), IV, encrypted content, authentication tag
                number_of_bytes_read = 4 + alg_props->iv_len + plaintext_size + alg_props->tag_len;
            } else {
                assert(frame.type == FRAME_TYPE_FINAL);
                // Reads: sequence number end indicator (4 bytes), sequence number (4 bytes), IV, encrypted content
                // length (4 bytes), encrypted content, authentication tag
                number_of_bytes_read = 4 + 4 + alg_props->iv_len + 4 + plaintext_size + alg_props->tag_len;
            }
        }
        assert(ciphertext_buf.ptr == old_ciphertext_buffer + number_of_bytes_read);
        assert(ciphertext_buf.len == old_ciphertext_buffer_length - number_of_bytes_read);
    }
    assert(aws_byte_cursor_is_valid(&ciphertext_buf));
    assert(aws_cryptosdk_alg_properties_is_valid(alg_props));
}
