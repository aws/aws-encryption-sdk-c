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

#include <aws/common/array_list.h>
#include <aws/cryptosdk/default_cmm.h>
#include "testing.h"
#include "zero_mkp.h"
#include "bad_cmm.h"

int default_cmm_zero_mkp_enc_mat() {
    struct aws_allocator * alloc = aws_default_allocator();
    struct aws_cryptosdk_mkp * mkp = aws_cryptosdk_zero_mkp_new();
    struct aws_cryptosdk_cmm * cmm = aws_cryptosdk_default_cmm_new(alloc, mkp);

    struct aws_cryptosdk_encryption_request req;
    req.enc_context = (void *)0xdeadbeef; // bogus address just to see if it gets passed along
    req.requested_alg = AES_256_GCM_IV12_AUTH16_KDNONE_SIGNONE;

    struct aws_cryptosdk_encryption_materials * enc_mat;
    int ret = aws_cryptosdk_cmm_generate_encryption_materials(cmm, &enc_mat, &req);
    TEST_ASSERT_INT_EQ(ret, AWS_OP_SUCCESS);

    TEST_ASSERT_ADDR_EQ(enc_mat->enc_context, (void *)0xdeadbeef);
    TEST_ASSERT_INT_EQ(enc_mat->alg, AES_256_GCM_IV12_AUTH16_KDNONE_SIGNONE);

    TEST_ASSERT_BUF_EQ(enc_mat->unencrypted_data_key,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00);

    TEST_ASSERT_INT_EQ(enc_mat->encrypted_data_keys.length, 1);
    struct aws_cryptosdk_edk * edk;
    ret = aws_array_list_get_at_ptr(&enc_mat->encrypted_data_keys, (void **)&edk, 0);
    TEST_ASSERT_INT_EQ(ret, AWS_OP_SUCCESS);
    TEST_ASSERT_INT_EQ(edk->enc_data_key.len, 0);

    aws_cryptosdk_encryption_materials_destroy(enc_mat);
    aws_cryptosdk_cmm_destroy(cmm);
    aws_cryptosdk_mkp_destroy(mkp);
    
    return 0;
}

int default_cmm_zero_mkp_dec_mat() {
    struct aws_allocator * alloc = aws_default_allocator();
    struct aws_cryptosdk_mkp * mkp = aws_cryptosdk_zero_mkp_new(alloc);
    struct aws_cryptosdk_cmm * cmm = aws_cryptosdk_default_cmm_new(alloc, mkp);

    struct aws_cryptosdk_decryption_request req;
    req.alg = AES_192_GCM_IV12_AUTH16_KDNONE_SIGNONE;
    aws_array_list_init_dynamic(&req.encrypted_data_keys, alloc, 1, sizeof(struct aws_cryptosdk_edk));
    struct aws_cryptosdk_edk edk = {{0}};
    aws_array_list_push_back(&req.encrypted_data_keys, (void *) &edk);

    struct aws_cryptosdk_decryption_materials * dec_mat;
    int ret = aws_cryptosdk_cmm_decrypt_materials(cmm, &dec_mat, &req);
    TEST_ASSERT_INT_EQ(ret, AWS_OP_SUCCESS);

    TEST_ASSERT_BUF_EQ(dec_mat->unencrypted_data_key,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00);

    aws_cryptosdk_decryption_materials_destroy(dec_mat);
    aws_cryptosdk_cmm_destroy(cmm);
    aws_cryptosdk_mkp_destroy(mkp);
    aws_array_list_clean_up(&req.encrypted_data_keys);
    return 0;
}

#define ASSERT_UNIMPLEMENTED_ERR_SET \
    do { \
        int err = aws_last_error(); \
        TEST_ASSERT_INT_EQ(err, AWS_ERROR_UNIMPLEMENTED); \
        aws_reset_error(); \
    } while (0)

int zero_size_cmm_does_not_run_vfs() {
    struct aws_cryptosdk_cmm * cmm = aws_cryptosdk_zero_size_cmm_new();
    int ret = aws_cryptosdk_cmm_generate_encryption_materials(cmm, NULL, NULL);
    TEST_ASSERT_INT_EQ(ret, AWS_OP_ERR);
    ASSERT_UNIMPLEMENTED_ERR_SET;

    ret = aws_cryptosdk_cmm_decrypt_materials(cmm, NULL, NULL);
    TEST_ASSERT_INT_EQ(ret, AWS_OP_ERR);
    ASSERT_UNIMPLEMENTED_ERR_SET;

    aws_cryptosdk_cmm_destroy(cmm);
    bool b = zero_size_cmm_did_destroy_vf_run();
    TEST_ASSERT_INT_EQ(b, false);
    ASSERT_UNIMPLEMENTED_ERR_SET;

    return 0;
}

int null_cmm_fails_vf_calls_cleanly() {
    struct aws_cryptosdk_cmm * cmm = aws_cryptosdk_null_cmm_new();
    int ret = aws_cryptosdk_cmm_generate_encryption_materials(cmm, NULL, NULL);
    TEST_ASSERT_INT_EQ(ret, AWS_OP_ERR);
    ASSERT_UNIMPLEMENTED_ERR_SET;

    ret = aws_cryptosdk_cmm_decrypt_materials(cmm, NULL, NULL);
    TEST_ASSERT_INT_EQ(ret, AWS_OP_ERR);
    ASSERT_UNIMPLEMENTED_ERR_SET;

    aws_cryptosdk_cmm_destroy(cmm);
    ASSERT_UNIMPLEMENTED_ERR_SET;
    return 0;
}

struct test_case materials_test_cases[] = {
    { "materials", "default_cmm_zero_mkp_enc_mat", default_cmm_zero_mkp_enc_mat },
    { "materials", "default_cmm_zero_mkp_dec_mat", default_cmm_zero_mkp_dec_mat },
    { "materials", "zero_size_cmm_does_not_run_vfs", zero_size_cmm_does_not_run_vfs },
    { "materials", "null_cmm_fails_vf_calls_cleanly", null_cmm_fails_vf_calls_cleanly },
    { NULL }
};
