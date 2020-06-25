/*
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"). You may not use
 * this file except in compliance with the License. A copy of the License is
 * located at
 *
 *     http://aws.amazon.com/apache2.0/
 *
 * or in the "license" file accompanying this file. This file is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
 * implied. See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <aws/common/encoding.h>
#include <proof_helpers/nondet.h>

/**
 * Stub for base64 encode.  Doesn't actually write the values, hence a lot faster.  Safe as long as output buffer was
 * already unconstrained.
 */
int aws_base64_encode(const struct aws_byte_cursor *AWS_RESTRICT to_encode, struct aws_byte_buf *AWS_RESTRICT output) {
    AWS_ASSERT(to_encode->ptr);
    AWS_ASSERT(output->buffer);

    size_t terminated_length = 0;
    size_t encoded_length    = 0;
    if (AWS_UNLIKELY(aws_base64_compute_encoded_len(to_encode->len, &terminated_length))) {
        return AWS_OP_ERR;
    }

    size_t needed_capacity = 0;
    if (AWS_UNLIKELY(aws_add_size_checked(output->len, terminated_length, &needed_capacity))) {
        return AWS_OP_ERR;
    }

    if (AWS_UNLIKELY(output->capacity < needed_capacity)) {
        return aws_raise_error(AWS_ERROR_SHORT_BUFFER);
    }

    /*
     * For convenience to standard C functions expecting a null-terminated
     * string, the output is terminated. As the encoding itself can be used in
     * various ways, however, its length should never account for that byte.
     */
    encoded_length = (terminated_length - 1);

    /* it's a string add the null terminator. */
    output->buffer[output->len + encoded_length] = 0;

    output->len += encoded_length;

    return AWS_OP_SUCCESS;
}
