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

#include <aws/cryptosdk/materials.h>
#include <aws/cryptosdk/zero_mkp.h>
#include <aws/cryptosdk/standard_cmm.h>
#include "testing.h"

int standard_cmm_zero_mkp_enc_mat() {
    struct aws_allocator * alloc = aws_default_allocator();
    struct aws_cryptosdk_mkp * mkp = aws_cryptosdk_zero_mkp_new(alloc);
    struct aws_cryptosdk_cmm * cmm = aws_cryptosdk_standard_cmm_new(alloc, mkp);

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

    aws_cryptosdk_encryption_materials_destroy(enc_mat);
    aws_cryptosdk_cmm_destroy(cmm);
    aws_cryptosdk_mkp_destroy(mkp);
    
    return 0;
}

int standard_cmm_zero_mkp_dec_mat() {
    struct aws_allocator * alloc = aws_default_allocator();
    struct aws_cryptosdk_mkp * mkp = aws_cryptosdk_zero_mkp_new(alloc);
    struct aws_cryptosdk_cmm * cmm = aws_cryptosdk_standard_cmm_new(alloc, mkp);

    struct aws_cryptosdk_decryption_request req;
    // normally set req.encrypted_data_keys, but they are ignored by this MKP/MK
    req.alg = AES_192_GCM_IV12_AUTH16_KDNONE_SIGNONE;

    struct aws_cryptosdk_decryption_materials * dec_mat;
    int ret = aws_cryptosdk_cmm_decrypt_materials(cmm, &dec_mat, &req);
    TEST_ASSERT_INT_EQ(ret, AWS_OP_SUCCESS);

    TEST_ASSERT_BUF_EQ(dec_mat->unencrypted_data_key,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00);

    aws_cryptosdk_decryption_materials_destroy(dec_mat);
    aws_cryptosdk_cmm_destroy(cmm);
    aws_cryptosdk_mkp_destroy(mkp);

    return 0;
}

struct test_case materials_test_cases[] = {
    { "materials", "standard_cmm_zero_mkp_enc_mat", standard_cmm_zero_mkp_enc_mat },
    { "materials", "standard_cmm_zero_mkp_dec_mat", standard_cmm_zero_mkp_dec_mat },
    { NULL }
};
