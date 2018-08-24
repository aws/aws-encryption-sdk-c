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

#include <string.h>
#include <stdlib.h>
#include <stdio.h>

#include <aws/common/common.h>
#include <aws/core/Aws.h>
#include <aws/core/utils/logging/DefaultLogSystem.h>
#include <aws/core/utils/logging/AWSLogging.h>
#include <aws/core/utils/memory/MemorySystemInterface.h>
#include <aws/core/utils/memory/stl/AWSString.h>
#include <aws/core/utils/Outcome.h>
#include <aws/kms/model/EncryptResult.h>
#include <aws/cryptosdk/session.h>
#include <aws/cryptosdk/default_cmm.h>
#include <aws/cryptosdk/kms_c_master_key.h>
#include <aws/cryptosdk/private/cpputils.h>

#include "testing.h"
#include "test_crypto.h"
#include "testutil.h"

using namespace Aws::Cryptosdk;
using Aws::SDKOptions;

const char *CLASS_CTAG = "Test KMS";

/* This special test key has been configured to allow Encrypt, Decrypt, and GenerateDataKey operations from any
 * AWS principal and should be used when adding new KMS tests.
 * You should never use it in production!
 */
const char *KEY_ARN_STR1 = "arn:aws:kms:us-west-2:658956600833:key/b3537ef1-d8dc-4780-9f5a-55776cbb2f7f";
const char *KEY_ARN_STR2 = "arn:aws:kms:eu-central-1:658956600833:key/75414c93-5285-4b57-99c9-30c1cf0a22c2";

struct TestData {
    struct aws_allocator *alloc;
    const uint8_t *pt_str = (uint8_t *) "Hello, world!";
    struct aws_byte_buf pt_in;
    Aws::Client::ClientConfiguration client_configuration;
    std::shared_ptr<Aws::KMS::KMSClient> kms_client;

    TestData() : alloc(aws_default_allocator()),
                 pt_in(aws_byte_buf_from_array(pt_str, sizeof(pt_str))) {
        client_configuration.region = Aws::Region::US_WEST_2;
        kms_client = Aws::MakeShared<Aws::KMS::KMSClient>(CLASS_CTAG, client_configuration);
    }
};

struct TestDataOut {
    uint8_t pt_out_buf[1024] = {0};
    uint8_t ct_out_buf[1024] = {0};
    struct aws_byte_buf ct_out;
    struct aws_byte_buf pt_out;
    TestDataOut() :
        ct_out(aws_byte_buf_from_array(ct_out_buf, sizeof(ct_out_buf))),
        pt_out(aws_byte_buf_from_array(pt_out_buf, sizeof(pt_out_buf))) {

    };
};

int t_decrypt_encrypt_same_mk() {
    TestData td;
    TestDataOut td_out;

    auto kms_c_master_key = Aws::New<KmsCMasterKey>(CLASS_CTAG, td.alloc, td.kms_client, KEY_ARN_STR1);

    // encrypt
    TEST_ASSERT_SUCCESS(aws_cryptosdk_process(kms_c_master_key, AWS_CRYPTOSDK_ENCRYPT, &td.pt_in, &td_out.ct_out));

    // decrypt
    TEST_ASSERT_SUCCESS(aws_cryptosdk_process(kms_c_master_key, AWS_CRYPTOSDK_DECRYPT, &td_out.ct_out, &td_out.pt_out));

    TEST_ASSERT(aws_byte_buf_eq(&td.pt_in, &td_out.pt_out) == true);

    Aws::Delete(kms_c_master_key);

    return 0;
}

int t_decrypt_encrypt_same_mk_autodetect_region() {
    TestData td;
    TestDataOut td_out;

    auto kms_c_master_key = Aws::New<KmsCMasterKey>(CLASS_CTAG, td.alloc, KEY_ARN_STR1);

    // encrypt
    TEST_ASSERT_SUCCESS(aws_cryptosdk_process(kms_c_master_key, AWS_CRYPTOSDK_ENCRYPT, &td.pt_in, &td_out.ct_out));

    // decrypt
    TEST_ASSERT_SUCCESS(aws_cryptosdk_process(kms_c_master_key, AWS_CRYPTOSDK_DECRYPT, &td_out.ct_out, &td_out.pt_out));

    TEST_ASSERT(aws_byte_buf_eq(&td.pt_in, &td_out.pt_out) == true);

    Aws::Delete(kms_c_master_key);

    return 0;
}

int test_kms_master_key_encrypt(TestDataOut &td_out, TestData &td, const Aws::String &key_arn) {
    auto kms_c_master_key_encrypt = Aws::New<KmsCMasterKey>(CLASS_CTAG, td.alloc, key_arn);
    TEST_ASSERT_SUCCESS(aws_cryptosdk_process(kms_c_master_key_encrypt,
                                              AWS_CRYPTOSDK_ENCRYPT,
                                              &td.pt_in,
                                              &td_out.ct_out));
    Aws::Delete(kms_c_master_key_encrypt);
    return 0;
}

int test_kms_master_key_decrypt(TestDataOut &td_out, TestData &td, const Aws::String &key_arn) {
    auto kms_c_master_key_decrypt = Aws::New<KmsCMasterKey>(CLASS_CTAG, td.alloc, key_arn);
    TEST_ASSERT_SUCCESS(aws_cryptosdk_process(kms_c_master_key_decrypt,
                                              AWS_CRYPTOSDK_DECRYPT,
                                              &td_out.ct_out,
                                              &td_out.pt_out));
    Aws::Delete(kms_c_master_key_decrypt);
    return 0;
}


int t_decrypt_encrypt_two_mk() {
    TestData td;
    TestDataOut td_out;

    // encrypt
    TEST_ASSERT_SUCCESS(test_kms_master_key_encrypt(td_out, td, KEY_ARN_STR1));

    // decrypt
    TEST_ASSERT_SUCCESS(test_kms_master_key_decrypt(td_out, td, KEY_ARN_STR1));


    TEST_ASSERT(aws_byte_buf_eq(&td.pt_in, &td_out.pt_out) == true);

    return 0;
}


int t_decrypt_encrypt_two_keys_for_decryption() {
    TestData td;
    TestDataOut td_out;

    Aws::List <Aws::String> keys = { KEY_ARN_STR1, KEY_ARN_STR2 };

    // encrypt
    TEST_ASSERT_SUCCESS(test_kms_master_key_encrypt(td_out, td, KEY_ARN_STR2));

    // decrypt
    auto kms_c_master_key_decrypt = Aws::New<KmsCMasterKey>(CLASS_CTAG, td.alloc, keys);
    TEST_ASSERT_SUCCESS(aws_cryptosdk_process(kms_c_master_key_decrypt,
                                              AWS_CRYPTOSDK_DECRYPT,
                                              &td_out.ct_out,
                                              &td_out.pt_out));
    Aws::Delete(kms_c_master_key_decrypt);

    TEST_ASSERT(aws_byte_buf_eq(&td.pt_in, &td_out.pt_out) == true);

    return 0;
}

int t_integration_two_encryptions_two_decryptions() {
    TestData td1, td2;
    TestDataOut td_out1, td_out2;

    td2.pt_in = aws_byte_buf_from_c_str("Testing");

    Aws::List <Aws::String> keys = { KEY_ARN_STR1, KEY_ARN_STR2 };

    // encrypt
    TEST_ASSERT_SUCCESS(test_kms_master_key_encrypt(td_out1, td1, KEY_ARN_STR1));
    TEST_ASSERT_SUCCESS(test_kms_master_key_encrypt(td_out2, td2, KEY_ARN_STR2));

    // decrypt
    auto kms_c_master_key_decrypt = Aws::New<KmsCMasterKey>(CLASS_CTAG, td1.alloc, keys);
    TEST_ASSERT_SUCCESS(aws_cryptosdk_process(kms_c_master_key_decrypt,
                                              AWS_CRYPTOSDK_DECRYPT,
                                              &td_out1.ct_out,
                                              &td_out1.pt_out));
    TEST_ASSERT_SUCCESS(aws_cryptosdk_process(kms_c_master_key_decrypt,
                                              AWS_CRYPTOSDK_DECRYPT,
                                              &td_out2.ct_out,
                                              &td_out2.pt_out));
    Aws::Delete(kms_c_master_key_decrypt);

    TEST_ASSERT(aws_byte_buf_eq(&td1.pt_in, &td_out1.pt_out) == true);
    TEST_ASSERT(aws_byte_buf_eq(&td2.pt_in, &td_out2.pt_out) == true);

    return 0;
}

int t_decrypt_encrypt_not_matching_key() {
    TestData td;
    TestDataOut td_out;

    Aws::List <Aws::String> keys = { KEY_ARN_STR1, KEY_ARN_STR2 };

    // encrypt
    TEST_ASSERT_SUCCESS(test_kms_master_key_encrypt(td_out, td, KEY_ARN_STR2));

    // decrypt should fail
    auto kms_c_master_key_decrypt = Aws::New<KmsCMasterKey>(CLASS_CTAG, td.alloc, KEY_ARN_STR1);
    TEST_ASSERT_SUCCESS(aws_cryptosdk_process(kms_c_master_key_decrypt,
                                              AWS_CRYPTOSDK_DECRYPT,
                                              &td_out.ct_out,
                                              &td_out.pt_out, AWS_OP_ERR));
    Aws::Delete(kms_c_master_key_decrypt);

    return 0;
}

int main() {
    SDKOptions *options = Aws::New<SDKOptions>(CLASS_CTAG);
    Aws::InitAPI(*options);

    /* TODO Valgrind complains about an uninitialized value inside BuildAWSError when we enable logging.
     * We should check where is that coming from
     * Aws::Utils::Logging::InitializeAWSLogging(
        Aws::MakeShared<Aws::Utils::Logging::DefaultLogSystem>(
            "RunUnitTests", Aws::Utils::Logging::LogLevel::Trace, "aws_encryption_sdk_"));*/

    RUN_TEST(t_decrypt_encrypt_same_mk());
    RUN_TEST(t_decrypt_encrypt_two_mk());
    RUN_TEST(t_decrypt_encrypt_same_mk_autodetect_region());
    RUN_TEST(t_decrypt_encrypt_two_keys_for_decryption());
    RUN_TEST(t_decrypt_encrypt_not_matching_key());
    RUN_TEST(t_integration_two_encryptions_two_decryptions());

    //Aws::Utils::Logging::ShutdownAWSLogging();

    Aws::ShutdownAPI(*options);
    Aws::Delete(options);
}

