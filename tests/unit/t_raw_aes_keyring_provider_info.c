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
 * Provider info serialization/deserialization tests.
 */

AWS_STATIC_STRING_FROM_LITERAL(ser_key_name, "Key name");
static const uint8_t iv[RAW_AES_KR_IV_LEN] =
{0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb};

static const uint8_t serialized_provider_info[] = {
    'K', 'e', 'y', ' ', 'n', 'a', 'm', 'e',
    0x00, 0x00, 0x00, RAW_AES_KR_TAG_LEN << 3,
    0x00, 0x00, 0x00, RAW_AES_KR_IV_LEN,
    0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb};

AWS_STATIC_STRING_FROM_LITERAL(ser_provider_id, "Provider id");

static const uint8_t raw_key_bytes[32];

int serialize_valid_provider_info() {

    struct aws_allocator * alloc = aws_default_allocator();
    struct aws_byte_buf provider_info;

    TEST_ASSERT_INT_EQ(AWS_OP_SUCCESS, aws_cryptosdk_serialize_provider_info_init(alloc,
                                                                                  &provider_info,
                                                                                  ser_key_name,
                                                                                  iv));

    TEST_ASSERT_BUF_EQ(provider_info,
                       'K', 'e', 'y', ' ', 'n', 'a', 'm', 'e',
                       0x00, 0x00, 0x00, RAW_AES_KR_TAG_LEN << 3,
                       0x00, 0x00, 0x00, RAW_AES_KR_IV_LEN,
                       0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb);

    aws_byte_buf_clean_up(&provider_info);
    return 0;
}

int parse_valid_provider_info() {
    struct aws_cryptosdk_keyring * kr = aws_cryptosdk_raw_aes_keyring_new(aws_default_allocator(),
                                                                aws_string_bytes(ser_key_name),
                                                                ser_key_name->len,
                                                                aws_string_bytes(ser_provider_id),
                                                                ser_provider_id->len,
                                                                raw_key_bytes,
                                                                AWS_CRYPTOSDK_AES_256);
    TEST_ASSERT_ADDR_NOT_NULL(kr);

    struct aws_byte_buf iv_output;
    struct aws_byte_buf ser_prov_info = aws_byte_buf_from_array(serialized_provider_info,
                                                                sizeof(serialized_provider_info));
    TEST_ASSERT(aws_cryptosdk_parse_provider_info(kr, &iv_output, &ser_prov_info));

    TEST_ASSERT_BUF_EQ(iv_output, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb);

    aws_cryptosdk_keyring_release(kr);
    return 0;
}

struct test_case raw_aes_keyring_provider_info_test_cases[] = {
    { "raw_aes_keyring", "serialize_valid_provider_info", serialize_valid_provider_info },
    { "raw_aes_keyring", "parse_valid_provider_info", parse_valid_provider_info },
    { NULL }
};
