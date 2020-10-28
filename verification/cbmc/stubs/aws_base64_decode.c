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
 * Stub for base64 decode.  Doesn't actually write the values, hence a lot faster.  Safe as long as output buffer was
 * already unconstrained.
 */
int aws_base64_decode(const struct aws_byte_cursor *AWS_RESTRICT to_decode, struct aws_byte_buf *AWS_RESTRICT output) {
    size_t decoded_length = 0;

    if (AWS_UNLIKELY(aws_base64_compute_decoded_len(to_decode, &decoded_length))) {
        return AWS_OP_ERR;
    }

    if (output->capacity < decoded_length) {
        return aws_raise_error(AWS_ERROR_SHORT_BUFFER);
    }

    if (nondet_bool()) {
        return aws_raise_error(AWS_ERROR_INVALID_BASE64_STR);
    }

    output->len = decoded_length;
    return AWS_OP_SUCCESS;
}
