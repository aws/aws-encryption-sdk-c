/*
 * Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
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

#include <aws/cryptosdk/default_cmm.h>
#include <aws/cryptosdk/private/cipher.h>
#include <aws/cryptosdk/private/framefmt.h>
#include <aws/cryptosdk/session.h>
#include <stdlib.h>
#include "counting_keyring.h"
#include "testing.h"
#include "testutil.h"
#include "zero_keyring.h"

int test_serialize_return_ciphertext_size() {
    // Arguments to the function
    size_t ciphertext_buf_capacity = 10000;
    size_t plaintext_size          = 100;
    enum aws_cryptosdk_alg_id id   = ALG_AES128_GCM_IV12_TAG16_HKDF_SHA256_ECDSA_P256;

    struct aws_allocator *alloc = aws_default_allocator();

    // Alocate the frame
    struct aws_cryptosdk_frame out_frame;
    out_frame.type            = FRAME_TYPE_SINGLE;
    out_frame.sequence_number = 1;

    // Allocate the byte buffer
    struct aws_byte_buf ciphertext_buf;
    TEST_ASSERT_SUCCESS(aws_byte_buf_init(&ciphertext_buf, alloc, ciphertext_buf_capacity));

    // Allocate and initialize the alg_properties
    const struct aws_cryptosdk_alg_properties *alg_props = aws_cryptosdk_alg_props(id);
    size_t ciphertext_size;

    size_t old_ciphertext_buf_len = ciphertext_buf.len;

    TEST_ASSERT_SUCCESS(
        aws_cryptosdk_serialize_frame(&out_frame, &ciphertext_size, plaintext_size, &ciphertext_buf, alg_props));
    // Assert that the returned size is correct
    TEST_ASSERT(old_ciphertext_buf_len + ciphertext_size == ciphertext_buf.len);

    aws_byte_buf_clean_up(&ciphertext_buf);

    return 0;
}

struct test_case framefmt_test_cases[] = {
    { "framefmt", "test_serialize_return_ciphertext_size", test_serialize_return_ciphertext_size }, { NULL }
};
