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
#include <aws/common/array_list.h>
#include <aws/core/Aws.h>
#include <aws/core/utils/logging/DefaultLogSystem.h>
#include <aws/core/utils/logging/AWSLogging.h>
#include <aws/core/utils/memory/MemorySystemInterface.h>
#include <aws/core/utils/memory/stl/AWSString.h>
#include <aws/core/utils/Outcome.h>
#include <aws/kms/model/EncryptResult.h>
#include <aws/cryptosdk/session.h>
#include <aws/cryptosdk/default_cmm.h>
#include <aws/cryptosdk/private/cpputils.h>
#include <aws/cryptosdk/kms_keyring.h>
#include <test_keyring.h>
#include <edks_utils.h>

#include "testing.h"
#include "test_crypto.h"
#include "testutil.h"

using namespace Aws::Cryptosdk;
using Aws::Cryptosdk::Private::aws_string_from_c_aws_byte_buf;
using Aws::SDKOptions;

const char *CLASS_CTAG = "Test KMS";

/* This special test key has been configured to allow Encrypt, Decrypt, and GenerateDataKey operations from any
 * AWS principal and should be used when adding new KMS tests.
 * You should never use it in production!
 */
const char *KEY_ARN_STR1 = "arn:aws:kms:us-west-2:658956600833:key/b3537ef1-d8dc-4780-9f5a-55776cbb2f7f";
const char *KEY_ARN_STR1_REGION = Aws::Region::US_WEST_2;
const char *KEY_ARN_STR2 = "arn:aws:kms:eu-central-1:658956600833:key/75414c93-5285-4b57-99c9-30c1cf0a22c2";
const char *KEY_ARN_STR2_REGION = Aws::Region::EU_CENTRAL_1;

struct TestData {
    struct aws_allocator *alloc;
    const uint8_t *pt_str = (uint8_t *) "Hello, world!";
    struct aws_byte_buf pt_in;
    Aws::Client::ClientConfiguration client_configuration;
    std::shared_ptr<Aws::KMS::KMSClient> kms_client;

    TestData(Aws::String region = Aws::Region::US_WEST_2) : alloc(aws_default_allocator()),
                 pt_in(aws_byte_buf_from_array(pt_str, sizeof(pt_str))) {
        client_configuration.region = region;
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

int generatedkAndDecrypt_sameKeyring_returnSuccess(const char *key, const char *region) {
    TestData td(region);
    TestDataOut td_out;

    auto kms_keyring = KmsKeyring::Builder().SetAllocator(td.alloc).SetKmsClient(td.kms_client).SetKeyId(key).Build();

    // generate dk
    TEST_ASSERT_SUCCESS(t_aws_cryptosdk_process(kms_keyring, AWS_CRYPTOSDK_ENCRYPT, &td.pt_in, &td_out.ct_out));

    // decrypt
    TEST_ASSERT_SUCCESS(t_aws_cryptosdk_process(kms_keyring,
                                                AWS_CRYPTOSDK_DECRYPT,
                                                &td_out.ct_out,
                                                &td_out.pt_out));

    TEST_ASSERT(aws_byte_buf_eq(&td.pt_in, &td_out.pt_out) == true);

    aws_cryptosdk_keyring_release(kms_keyring);

    return 0;
}


int generatedkAndDecrypt_sameKeyringKey1_returnSuccess() {
    return generatedkAndDecrypt_sameKeyring_returnSuccess(KEY_ARN_STR1, KEY_ARN_STR1_REGION);
}

int generatedkAndDecrypt_sameKeyringKey2_returnSuccess() {
    return generatedkAndDecrypt_sameKeyring_returnSuccess(KEY_ARN_STR2, KEY_ARN_STR2_REGION);
}

/**
 * Generates a new key that it saves to td_out using a temporary KmsKeyring object
 */
int t_kms_keyring_generate_dk(TestDataOut &td_out, TestData &td, const Aws::String &key_arn) {
    auto kms_keyring_generate_dk = KmsKeyring::Builder().SetAllocator(td.alloc).SetKeyId(key_arn).Build();
    TEST_ASSERT_SUCCESS(t_aws_cryptosdk_process(kms_keyring_generate_dk,
                                                AWS_CRYPTOSDK_ENCRYPT,
                                                &td.pt_in,
                                                &td_out.ct_out));
    aws_cryptosdk_keyring_release(kms_keyring_generate_dk);
    return 0;
}

/**
 * Decrypts a key and saves result to td_out using a temporary KmsKeyring object
 */
int t_kms_keyring_decrypt(TestDataOut &td_out, TestData &td, const Aws::String &key_arn) {
    auto kms_keyring_decrypt = KmsKeyring::Builder().SetAllocator(td.alloc).SetKeyId(key_arn).Build();
    TEST_ASSERT_SUCCESS(t_aws_cryptosdk_process(kms_keyring_decrypt,
                                                AWS_CRYPTOSDK_DECRYPT,
                                                &td_out.ct_out,
                                                &td_out.pt_out));
    aws_cryptosdk_keyring_release(kms_keyring_decrypt);
    return 0;
}

int generatedkAndDecrypt_twoDistinctKeyrings_returnSuccess() {
    TestData td;
    TestDataOut td_out;

    // generate dk
    TEST_ASSERT_SUCCESS(t_kms_keyring_generate_dk(td_out, td, KEY_ARN_STR1));

    // decrypt
    TEST_ASSERT_SUCCESS(t_kms_keyring_decrypt(td_out, td, KEY_ARN_STR1));

    TEST_ASSERT(aws_byte_buf_eq(&td.pt_in, &td_out.pt_out) == true);

    return 0;
}

int generatedkAndDecrypt_oneKeyEncryptsTwoKeysForDecryptionConfigured_returnSuccess() {
    TestData td;
    TestDataOut td_out;

    Aws::List<Aws::String> keys = {KEY_ARN_STR1, KEY_ARN_STR2};

    // generate dk
    TEST_ASSERT_SUCCESS(t_kms_keyring_generate_dk(td_out, td, KEY_ARN_STR2));

    // decrypt
    auto kms_keyring_decrypt = KmsKeyring::Builder().SetAllocator(td.alloc)
                                                    .SetKeyIds(keys).SetDefaultRegion(Aws::Region::CN_NORTH_1).Build();
    TEST_ASSERT_SUCCESS(t_aws_cryptosdk_process(kms_keyring_decrypt,
                                                AWS_CRYPTOSDK_DECRYPT,
                                                &td_out.ct_out,
                                                &td_out.pt_out));
    aws_cryptosdk_keyring_release(kms_keyring_decrypt);

    TEST_ASSERT(aws_byte_buf_eq(&td.pt_in, &td_out.pt_out) == true);

    return 0;
}

int generatedkAndDecrypt_twoKeysEncryptsTwoKeyDecrypts_returnSuccess() {
    TestData td1, td2;
    TestDataOut td_out1, td_out2;

    td2.pt_in = aws_byte_buf_from_c_str("Testing");

    Aws::List<Aws::String> keys = {KEY_ARN_STR1, KEY_ARN_STR2};

    // generate dk
    TEST_ASSERT_SUCCESS(t_kms_keyring_generate_dk(td_out1, td1, KEY_ARN_STR1));
    TEST_ASSERT_SUCCESS(t_kms_keyring_generate_dk(td_out2, td2, KEY_ARN_STR2));

    // decrypt
    auto kms_keyring_decrypt = KmsKeyring::Builder().SetAllocator(td1.alloc)
                                                    .SetKeyIds(keys).SetDefaultRegion(Aws::Region::CN_NORTH_1).Build();
    TEST_ASSERT_SUCCESS(t_aws_cryptosdk_process(kms_keyring_decrypt,
                                                AWS_CRYPTOSDK_DECRYPT,
                                                &td_out1.ct_out,
                                                &td_out1.pt_out));
    TEST_ASSERT_SUCCESS(t_aws_cryptosdk_process(kms_keyring_decrypt,
                                                AWS_CRYPTOSDK_DECRYPT,
                                                &td_out2.ct_out,
                                                &td_out2.pt_out));
    aws_cryptosdk_keyring_release(kms_keyring_decrypt);

    TEST_ASSERT(aws_byte_buf_eq(&td1.pt_in, &td_out1.pt_out) == true);
    TEST_ASSERT(aws_byte_buf_eq(&td2.pt_in, &td_out2.pt_out) == true);

    return 0;
}

int generatedkAndDecrypt_keyForDecryptionMismatch_returnErr() {
    TestData td;
    TestDataOut td_out;

    // generate dk
    TEST_ASSERT_SUCCESS(t_kms_keyring_generate_dk(td_out, td, KEY_ARN_STR2));

    // decrypt should fail
    auto kms_keyring_decrypt = KmsKeyring::Builder().SetAllocator(td.alloc).SetKeyId(KEY_ARN_STR1).Build();
    TEST_ASSERT_SUCCESS(t_aws_cryptosdk_process(kms_keyring_decrypt,
                                                AWS_CRYPTOSDK_DECRYPT,
                                                &td_out.ct_out,
                                                &td_out.pt_out, AWS_OP_ERR));
    aws_cryptosdk_keyring_release(kms_keyring_decrypt);

    return 0;
}


static int test_assert_edk_name_space_and_info(const char *expected_name_space,
                                                const char *expected_provider_info,
                                                struct aws_cryptosdk_edk *edk) {
    struct aws_byte_buf name_space_bb = aws_byte_buf_from_c_str(expected_name_space);
    struct aws_byte_buf provider_info_bb = aws_byte_buf_from_c_str(expected_provider_info);
    TEST_ASSERT(aws_byte_buf_eq(&edk->name_space, &name_space_bb));
    TEST_ASSERT(aws_byte_buf_eq(&edk->provider_info, &provider_info_bb));

    return 0;
}

/**
 * Decrypts content of edk and then compares with expected_plain_text
 * @return 0 on success when content of decryption is equal with expected_plain_text
 */
int test_keyring_datakey_decrypt_and_compare_with_pt(struct aws_allocator *alloc,
                                                     const struct aws_byte_buf *expected_plain_text,
                                                     struct aws_cryptosdk_keyring *keyring,
                                                     struct aws_array_list *edks,
                                                     struct aws_hash_table *enc_context,
                                                     enum aws_cryptosdk_alg_id alg) {
    struct aws_byte_buf result_output = {0};
    TEST_ASSERT_SUCCESS(aws_cryptosdk_keyring_on_decrypt(keyring,
                                                         alloc,
                                                         &result_output,
                                                         edks,
                                                         enc_context,
                                                         alg));
    TEST_ASSERT(aws_byte_buf_eq(&result_output, expected_plain_text));
    aws_byte_buf_clean_up(&result_output);
    return 0;
}

int encryptdkAndDecrypt_singleKey_returnSuccess() {
    auto alg = AES_128_GCM_IV12_AUTH16_KDNONE_SIGNONE;
    auto plain_text = aws_byte_buf_from_c_str("encrypt_me___16b");
    auto alloc = aws_default_allocator();
    Testing::Edks edks(alloc);

    struct aws_hash_table enc_context;
    test_enc_context_init_and_fill(&enc_context);
    auto kms_keyring = KmsKeyring::Builder().SetAllocator(alloc).SetKeyId(KEY_ARN_STR2).Build();

    TEST_ASSERT_SUCCESS(aws_cryptosdk_keyring_on_encrypt(kms_keyring,
                                                         alloc,
                                                         &plain_text,
                                                         &edks.encrypted_data_keys,
                                                         &enc_context,
                                                         alg));
    TEST_ASSERT(edks.encrypted_data_keys.length > 0);

    struct aws_cryptosdk_edk *edk;
    TEST_ASSERT_SUCCESS(aws_array_list_get_at_ptr(&edks.encrypted_data_keys, (void **) &edk, 0));
    TEST_ASSERT_SUCCESS(test_assert_edk_name_space_and_info("aws-kms", KEY_ARN_STR2, edk));

    TEST_ASSERT_SUCCESS(test_keyring_datakey_decrypt_and_compare_with_pt(alloc,
                                                                         &plain_text,
                                                                         kms_keyring,
                                                                         &edks.encrypted_data_keys,
                                                                         &enc_context,
                                                                         alg));

    aws_cryptosdk_keyring_release(kms_keyring);
    aws_hash_table_clean_up(&enc_context);
    return 0;
}

int encryptdkAndDecrypt_twoKeys_returnSuccess() {
    auto alg = AES_128_GCM_IV12_AUTH16_KDNONE_SIGNONE;
    auto plain_text = aws_byte_buf_from_c_str("encrypt_me___16b");
    auto alloc = aws_default_allocator();
    Testing::Edks edks(alloc);

    struct aws_hash_table enc_context;
    test_enc_context_init_and_fill(&enc_context);
    auto encrypting_keyring_with_two_keys = KmsKeyring::Builder().AppendKeyId(KEY_ARN_STR2)
        .AppendKeyId(KEY_ARN_STR1)
        .SetDefaultRegion(KEY_ARN_STR2_REGION).Build();
    TEST_ASSERT_ADDR_NOT_NULL(encrypting_keyring_with_two_keys);

    TEST_ASSERT_SUCCESS(aws_cryptosdk_keyring_on_encrypt(encrypting_keyring_with_two_keys,
                                                         alloc,
                                                         &plain_text,
                                                         &edks.encrypted_data_keys,
                                                         &enc_context,
                                                         alg));
    aws_cryptosdk_keyring_release(encrypting_keyring_with_two_keys);

    // make sure it encrypted with both keys
    std::vector<const char *> keys = {KEY_ARN_STR2, KEY_ARN_STR1};
    for (unsigned int i = 0; i < keys.size(); i++) {
        struct aws_cryptosdk_edk *edk;
        TEST_ASSERT_SUCCESS(aws_array_list_get_at_ptr(&edks.encrypted_data_keys, (void **) &edk, i));
        TEST_ASSERT_SUCCESS(test_assert_edk_name_space_and_info("aws-kms", keys[i], edk));

        auto decrypting_keyring = KmsKeyring::Builder().AppendKeyId(keys[i]).Build();
        TEST_ASSERT_ADDR_NOT_NULL(decrypting_keyring);
        TEST_ASSERT_SUCCESS(test_keyring_datakey_decrypt_and_compare_with_pt(alloc,
                                                                             &plain_text,
                                                                             decrypting_keyring,
                                                                             &edks.encrypted_data_keys,
                                                                             &enc_context,
                                                                             alg));
        aws_cryptosdk_keyring_release(decrypting_keyring);
    }

    aws_hash_table_clean_up(&enc_context);
    return 0;
}

//todo add more tests for each type of KmsKeyring constructor
//todo add more tests for grantTokens
//todo We'll need tests for the default region that encrypt with key IDs of the form [uuid] or alias/whatever.

namespace {
    class LoggingRAII {
        public:
        LoggingRAII() {
            Aws::Utils::Logging::InitializeAWSLogging(
                Aws::MakeShared<Aws::Utils::Logging::DefaultLogSystem>(
                    "RunUnitTests", Aws::Utils::Logging::LogLevel::Trace, "aws_encryption_sdk_"));
        }
        ~LoggingRAII() {
            Aws::Utils::Logging::ShutdownAWSLogging();
        }
    };
}

int main() {
    aws_load_error_strings();
    aws_cryptosdk_err_init_strings();

    SDKOptions options;
    Aws::InitAPI(options);

    // Enabling AWS C++ SDK logging generates valgrind warnings from deep in the SDK client code
    //LoggingRAII loggingInit;

    RUN_TEST(generatedkAndDecrypt_sameKeyringKey1_returnSuccess());
    RUN_TEST(generatedkAndDecrypt_sameKeyringKey2_returnSuccess());
    RUN_TEST(generatedkAndDecrypt_twoDistinctKeyrings_returnSuccess());
    RUN_TEST(generatedkAndDecrypt_oneKeyEncryptsTwoKeysForDecryptionConfigured_returnSuccess());
    RUN_TEST(generatedkAndDecrypt_twoKeysEncryptsTwoKeyDecrypts_returnSuccess());
    RUN_TEST(generatedkAndDecrypt_keyForDecryptionMismatch_returnErr());
    RUN_TEST(encryptdkAndDecrypt_singleKey_returnSuccess());
    RUN_TEST(encryptdkAndDecrypt_twoKeys_returnSuccess());

    Aws::ShutdownAPI(options);
}
