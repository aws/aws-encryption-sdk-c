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

#include <aws/cryptosdk/cipher.h>
#include <aws/cryptosdk/private/cipher.h>
#include <make_common_data_structures.h>

#define KEY_LEN 256

void aws_cryptosdk_rsa_encrypt_harness() {
    struct aws_byte_buf cipher;
    struct aws_allocator *alloc = can_fail_allocator();
    struct aws_byte_cursor plain;
    struct aws_string *key = ensure_string_is_allocated_bounded_length(KEY_LEN);
    enum aws_cryptosdk_rsa_padding_mode rsa_padding_mode;

    __CPROVER_assume(aws_byte_buf_is_bounded(&cipher, MAX_BUFFER_SIZE));
    // ensure_byte_buf_has_allocated_buffer_member(&cipher);
    __CPROVER_assume(aws_byte_buf_is_valid(&cipher));

    __CPROVER_assume(aws_byte_cursor_is_bounded(&plain, MAX_BUFFER_SIZE));
    ensure_byte_cursor_has_allocated_buffer_member(&plain);
    __CPROVER_assume(aws_byte_cursor_is_valid(&plain));

    /* save current state of the data structure */
    struct aws_byte_cursor old_plain = plain;
    struct store_byte_from_buffer old_byte_from_plain;
    save_byte_from_array(plain.ptr, plain.len, &old_byte_from_plain);

    /*initialize a nondeterministic but fixed max encryption size between 0 and INT_MAX */
    initialize_max_encryption_size();

    if (aws_cryptosdk_rsa_encrypt(&cipher, alloc, plain, key, rsa_padding_mode) == AWS_OP_SUCCESS) {
        assert(aws_byte_buf_is_valid(&cipher));
    }
    if (plain.len != 0) {
        assert_byte_from_buffer_matches(plain.ptr, &old_byte_from_plain);
    }
}
