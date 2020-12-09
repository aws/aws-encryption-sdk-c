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
#include <utils.h>

void aws_cryptosdk_private_commitment_eq_harness() {
    /* Nondet Input */
    struct aws_byte_buf *buf1 = malloc(sizeof(*buf1));
    struct aws_byte_buf *buf2 = malloc(sizeof(*buf2));

    /* Assumptions */
    __CPROVER_assume(IMPLIES(buf1 != NULL, aws_byte_buf_is_bounded(buf1, MAX_BUFFER_SIZE)));
    ensure_byte_buf_has_allocated_buffer_member(buf1);
    __CPROVER_assume(aws_byte_buf_is_valid(buf1));

    __CPROVER_assume(IMPLIES(buf2 != NULL, aws_byte_buf_is_bounded(buf2, MAX_BUFFER_SIZE)));
    ensure_byte_buf_has_allocated_buffer_member(buf2);
    __CPROVER_assume(aws_byte_buf_is_valid(buf2));

    /* Save current state of the data structures */
    struct aws_byte_buf *old_buf1 = buf1;
    struct store_byte_from_buffer old_byte_from_buf1;
    save_byte_from_array(buf1->buffer, buf1->len, &old_byte_from_buf1);

    struct aws_byte_buf *old_buf2 = buf2;
    struct store_byte_from_buffer old_byte_from_buf2;
    save_byte_from_array(buf2->buffer, buf2->len, &old_byte_from_buf2);

    /* Operation under verification */
    if (aws_cryptosdk_private_commitment_eq(buf1, buf2)) {
        assert(aws_byte_buf_contents_match(buf1, buf2));
    } else {
        assert(buf1->len != 32 || !aws_byte_buf_contents_match(buf1, buf2));
    }

    /* Postconditions */
    assert(aws_byte_buf_is_valid(buf1));
    assert_byte_buf_equivalence(buf1, old_buf1, &old_byte_from_buf1);
    assert(aws_byte_buf_is_valid(buf2));
    assert_byte_buf_equivalence(buf2, old_buf2, &old_byte_from_buf2);
}
