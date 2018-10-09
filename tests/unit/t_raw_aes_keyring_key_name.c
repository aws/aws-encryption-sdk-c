/*
 * Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
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
#include <aws/cryptosdk/private/raw_aes_keyring.h>
#include "testing.h"

/**
 * Key name serialization/deserialization tests.
 */

AWS_STATIC_STRING_FROM_LITERAL(ser_key_name, "Key name");
static const uint8_t iv[RAW_AES_KR_IV_LEN] =
{0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb};

static const uint8_t serialized_key_name[] = {
    'K', 'e', 'y', ' ', 'n', 'a', 'm', 'e',
    0x00, 0x00, 0x00, RAW_AES_KR_TAG_LEN << 3,
    0x00, 0x00, 0x00, RAW_AES_KR_IV_LEN,
    0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb};

AWS_STATIC_STRING_FROM_LITERAL(ser_name_space, "Name space");

static const uint8_t raw_key_bytes[32];

int serialize_valid_key_name() {

    struct aws_allocator * alloc = aws_default_allocator();
    struct aws_byte_buf key_name;

    TEST_ASSERT_INT_EQ(AWS_OP_SUCCESS, aws_cryptosdk_serialize_key_name_init(alloc,
                                                                                  &key_name,
                                                                                  ser_key_name,
                                                                                  iv));

    TEST_ASSERT_BUF_EQ(key_name,
                       'K', 'e', 'y', ' ', 'n', 'a', 'm', 'e',
                       0x00, 0x00, 0x00, RAW_AES_KR_TAG_LEN << 3,
                       0x00, 0x00, 0x00, RAW_AES_KR_IV_LEN,
                       0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb);

    aws_byte_buf_clean_up(&key_name);
    return 0;
}

int parse_valid_key_name() {
    struct aws_cryptosdk_keyring * kr = aws_cryptosdk_raw_aes_keyring_new(aws_default_allocator(),
                                                                aws_string_bytes(ser_key_name),
                                                                ser_key_name->len,
                                                                aws_string_bytes(ser_name_space),
                                                                ser_name_space->len,
                                                                raw_key_bytes,
                                                                AWS_CRYPTOSDK_AES_256);
    TEST_ASSERT_ADDR_NOT_NULL(kr);

    struct aws_byte_buf iv_output;
    struct aws_byte_buf ser_key_name = aws_byte_buf_from_array(serialized_key_name,
                                                                sizeof(serialized_key_name));
    TEST_ASSERT(aws_cryptosdk_parse_key_name(kr, &iv_output, &ser_key_name));

    TEST_ASSERT_BUF_EQ(iv_output, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb);

    aws_cryptosdk_keyring_release(kr);
    return 0;
}

struct test_case raw_aes_keyring_key_name_test_cases[] = {
    { "raw_aes_keyring", "serialize_valid_key_name", serialize_valid_key_name },
    { "raw_aes_keyring", "parse_valid_key_name", parse_valid_key_name },
    { NULL }
};
