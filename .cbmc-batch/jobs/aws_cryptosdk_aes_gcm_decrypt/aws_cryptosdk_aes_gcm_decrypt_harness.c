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

void aws_cryptosdk_aes_gcm_decrypt_harness() {
    /* Nondet inputs */
    struct aws_byte_buf plain;
    struct aws_byte_cursor cipher;
    struct aws_byte_cursor tag;
    struct aws_byte_cursor iv;
    struct aws_byte_cursor aad;
    struct aws_string *key;

    /* Assumptions */
    __CPROVER_assume(aws_byte_buf_is_bounded(&plain, MAX_BUFFER_SIZE));
    ensure_byte_buf_has_allocated_buffer_member(&plain);
    __CPROVER_assume(plain.buffer != NULL);
    __CPROVER_assume(aws_byte_buf_is_valid(&plain));

    __CPROVER_assume(aws_byte_cursor_is_bounded(&cipher, MAX_BUFFER_SIZE));
    ensure_byte_cursor_has_allocated_buffer_member(&cipher);
    __CPROVER_assume(aws_byte_cursor_is_valid(&cipher));

    __CPROVER_assume(aws_byte_cursor_is_bounded(&tag, MAX_BUFFER_SIZE));
    ensure_byte_cursor_has_allocated_buffer_member(&tag);
    __CPROVER_assume(aws_byte_cursor_is_valid(&tag));

    __CPROVER_assume(aws_byte_cursor_is_bounded(&iv, MAX_BUFFER_SIZE));
    ensure_byte_cursor_has_allocated_buffer_member(&iv);
    __CPROVER_assume(aws_byte_cursor_is_valid(&iv));

    __CPROVER_assume(aws_byte_cursor_is_bounded(&aad, MAX_BUFFER_SIZE));
    ensure_byte_cursor_has_allocated_buffer_member(&aad);
    __CPROVER_assume(aws_byte_cursor_is_valid(&aad));

    key = ensure_string_is_allocated_nondet_length();
    __CPROVER_assume(key != NULL);
    __CPROVER_assume(aws_string_is_valid(key));

    /* Save current state of the data structure */
    struct aws_byte_cursor old_cipher = cipher;
    struct store_byte_from_buffer old_byte_from_cipher;
    save_byte_from_array(cipher.ptr, cipher.len, &old_byte_from_cipher);

    struct aws_byte_cursor old_tag = tag;
    struct store_byte_from_buffer old_byte_from_tag;
    save_byte_from_array(tag.ptr, tag.len, &old_byte_from_tag);

    struct aws_byte_cursor old_iv = iv;
    struct store_byte_from_buffer old_byte_from_iv;
    save_byte_from_array(iv.ptr, iv.len, &old_byte_from_iv);

    struct aws_byte_cursor old_aad = aad;
    struct store_byte_from_buffer old_byte_from_aad;
    save_byte_from_array(aad.ptr, aad.len, &old_byte_from_aad);

    /* Operation under verification */
    if (aws_cryptosdk_aes_gcm_decrypt(&plain, cipher, tag, iv, aad, key) == AWS_OP_SUCCESS) {
        /* Postconditions */
        assert(plain.len == cipher.len);
    }
    /* Postconditions */
    assert(aws_byte_buf_is_valid(&plain));
    if (cipher.len != 0) {
        assert_byte_from_buffer_matches(cipher.ptr, &old_byte_from_cipher);
    }
    if (tag.len != 0) {
        assert_byte_from_buffer_matches(tag.ptr, &old_byte_from_tag);
    }
    if (iv.len != 0) {
        assert_byte_from_buffer_matches(iv.ptr, &old_byte_from_iv);
    }
    if (aad.len != 0) {
        assert_byte_from_buffer_matches(aad.ptr, &old_byte_from_aad);
    }
}
