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
#include <aws/cryptosdk/private/raw_aes_mk.h>
#include "testing.h"

AWS_STATIC_STRING_FROM_LITERAL(master_key_id, "Master key id");
static const uint8_t iv[RAW_AES_MK_IV_LEN] =
{0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb};

static const uint8_t serialized_provider_info[] = {
    'M', 'a', 's', 't', 'e', 'r', ' ', 'k', 'e', 'y', ' ', 'i', 'd',
    0x00, 0x00, 0x00, RAW_AES_MK_TAG_LEN,
    0x00, 0x00, 0x00, RAW_AES_MK_IV_LEN,
    0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb};

AWS_STATIC_STRING_FROM_LITERAL(provider_id, "Provider id");

static const uint8_t raw_key_bytes[32];

int serialize_valid_provider_info() {

    struct aws_allocator * alloc = aws_default_allocator();
    struct aws_byte_buf provider_info;

    TEST_ASSERT_INT_EQ(AWS_OP_SUCCESS, serialize_provider_info_init(alloc,
                                                                    &provider_info,
                                                                    master_key_id,
                                                                    iv));

    TEST_ASSERT_BUF_EQ(provider_info,
                       'M', 'a', 's', 't', 'e', 'r', ' ', 'k', 'e', 'y', ' ', 'i', 'd',
                       0x00, 0x00, 0x00, RAW_AES_MK_TAG_LEN,
                       0x00, 0x00, 0x00, RAW_AES_MK_IV_LEN,
                       0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb);

    aws_byte_buf_clean_up(&provider_info);
    return 0;
}

int parse_valid_provider_info() {
    struct aws_cryptosdk_mk * mk = aws_cryptosdk_raw_aes_mk_new(aws_default_allocator(),
                                                                aws_string_bytes(master_key_id),
                                                                master_key_id->len,
                                                                aws_string_bytes(provider_id),
                                                                provider_id->len,
                                                                raw_key_bytes);
    TEST_ASSERT_ADDR_NOT_NULL(mk);

    struct aws_byte_buf iv_output;
    struct aws_byte_buf ser_prov_info = aws_byte_buf_from_array(serialized_provider_info,
                                                                sizeof(serialized_provider_info));
    TEST_ASSERT(parse_provider_info(mk, &iv_output, &ser_prov_info));

    TEST_ASSERT_BUF_EQ(iv_output, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb);

    aws_cryptosdk_mk_destroy(mk);
    return 0;
}

int decrypt_data_key() {
    struct aws_allocator * alloc = aws_default_allocator();
    const uint8_t my_master_key_id[] = "asdfhasiufhiasuhviawurhgiuawrhefiuawhf";
    const uint8_t my_provider_id[] = "static-random";
    const uint8_t my_wrapping_key[] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
                                       0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f};
    struct aws_cryptosdk_mk * mk = aws_cryptosdk_raw_aes_mk_new(alloc,
                                                                my_master_key_id,
                                                                sizeof(my_master_key_id) - 1,
                                                                my_provider_id,
                                                                sizeof(my_provider_id) - 1,
                                                                my_wrapping_key);
    TEST_ASSERT_ADDR_NOT_NULL(mk);

    struct aws_cryptosdk_decryption_request req;
    req.alloc = alloc;
    req.alg = AES_256_GCM_IV12_AUTH16_KDNONE_SIGNONE;
    aws_array_list_init_dynamic(&req.encrypted_data_keys, alloc, 1, sizeof(struct aws_cryptosdk_edk));

    const uint8_t edk_bytes[] = {0xff, 0xaf, 0xb4, 0x82, 0xf0, 0x0f, 0x9b, 0x4e, 0x5e, 0x0e, 0x75, 0xea, 0x67, 0xbb, 0x80, 0xc6, 0x5a, 0x37, 0x18, 0x35, 0x55, 0x62, 0xfb, 0x9c, 0x9e, 0x90, 0xd8, 0xae, 0xdd, 0x39, 0xd0, 0x67, 0x85, 0x0e, 0x18, 0x5b, 0xcb, 0x92, 0xc7, 0xbb, 0xff, 0x88, 0xfd, 0xe8, 0xf9, 0x33, 0x6c, 0x74};
    const uint8_t edk_provider_info[] = "asdfhasiufhiasuhviawurhgiuawrhefiuawhf\x00\x00\x00\x80\x00\x00\x00\x0c\x1bHv\xb4z\x10\x16\x19\xeb?\x93\x1d";

    struct aws_cryptosdk_edk edk;
    edk.enc_data_key = aws_byte_buf_from_array(edk_bytes, sizeof(edk_bytes));
    edk.provider_id = aws_byte_buf_from_array(my_provider_id, sizeof(my_provider_id) - 1);
    edk.provider_info = aws_byte_buf_from_array(edk_provider_info, sizeof(edk_provider_info) - 1);

    aws_array_list_push_back(&req.encrypted_data_keys, (void *) &edk);
    
    struct aws_cryptosdk_decryption_materials * dec_mat = aws_cryptosdk_decryption_materials_new(alloc, req.alg);
    TEST_ASSERT_ADDR_NOT_NULL(dec_mat);

    TEST_ASSERT_INT_EQ(AWS_OP_SUCCESS, aws_cryptosdk_mk_decrypt_data_key(mk, dec_mat, &req));
    TEST_ASSERT_ADDR_NOT_NULL(dec_mat->unencrypted_data_key.buffer);
    TEST_ASSERT_BUF_EQ(dec_mat->unencrypted_data_key, 0x9b, 0x01, 0xc1, 0xaa, 0x62, 0x25, 0x1d, 0x0f, 0x16, 0xa0, 0xa2, 0x15, 0xea, 0xe4, 0xc2, 0x37, 0x4a, 0x8c, 0xc7, 0x9f, 0xfa, 0x3a, 0xe7, 0xa2, 0xa4, 0xa8, 0x1e, 0x83, 0xba, 0x38, 0x23, 0x16);

    aws_cryptosdk_decryption_materials_destroy(dec_mat);
    aws_array_list_clean_up(&req.encrypted_data_keys);
    aws_cryptosdk_mk_destroy(mk);
    return 0;
}

struct test_case raw_aes_mk_test_cases[] = {
    { "raw_aes_mk", "serialize_valid_provider_info", serialize_valid_provider_info },
    { "raw_aes_mk", "parse_valid_provider_info", parse_valid_provider_info },
    { "raw_aes_mk", "decrypt_data_key", decrypt_data_key },
    { NULL }
};
