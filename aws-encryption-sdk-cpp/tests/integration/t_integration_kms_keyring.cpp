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

#include <aws/common/encoding.h>
#include <aws/core/utils/logging/ConsoleLogSystem.h>
#include <aws/core/utils/logging/AWSLogging.h>
#include <aws/cryptosdk/enc_context.h>
#include <aws/cryptosdk/kms_keyring.h>

#include "edks_utils.h"
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
const char *KEY_ARN_STR1_REGION = Aws::Region::US_WEST_2;
const char *KEY_ARN_STR2 = "arn:aws:kms:eu-central-1:658956600833:key/75414c93-5285-4b57-99c9-30c1cf0a22c2";
const char *KEY_ARN_STR2_REGION = Aws::Region::EU_CENTRAL_1;
/* For testing that discovery keyring fails cleanly when it gets a key it cannot decrypt with */
const char *KEY_ARN_STR_FAKE = "arn:aws:kms:us-west-2:658956600833:key/01234567-89ab-cdef-fedc-ba9876543210";
const char *KEY_ARN_STR_FAKE_REGION = Aws::Region::US_WEST_2;

struct TestData {
    struct aws_allocator *alloc;
    struct aws_byte_buf pt_in;
    Aws::Client::ClientConfiguration client_configuration;
    std::shared_ptr<Aws::KMS::KMSClient> kms_client;

    TestData(Aws::String region = Aws::Region::US_WEST_2) :
        alloc(aws_default_allocator()),
        pt_in(aws_byte_buf_from_c_str("Hello, world!")) {
        client_configuration.region = region;

        // When running under valgrind, we can run slowly enough that requests timeout.
        // We'll bump these up to try to mitigate this.
        client_configuration.requestTimeoutMs = 10000;
        client_configuration.connectTimeoutMs = 10000;

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

int encryptAndDecrypt_sameKeyring_returnSuccess(const char *key, const char *region) {
    TestData td(region);
    TestDataOut td_out;

    auto kms_keyring = KmsKeyring::Builder().WithKmsClient(td.kms_client).Build({key});

    TEST_ASSERT_SUCCESS(t_aws_cryptosdk_process(kms_keyring, AWS_CRYPTOSDK_ENCRYPT, &td.pt_in, &td_out.ct_out));

    TEST_ASSERT_SUCCESS(t_aws_cryptosdk_process(kms_keyring,
                                                AWS_CRYPTOSDK_DECRYPT,
                                                &td_out.ct_out,
                                                &td_out.pt_out));

    TEST_ASSERT(aws_byte_buf_eq(&td.pt_in, &td_out.pt_out) == true);

    aws_cryptosdk_keyring_release(kms_keyring);
    return 0;
}


int encryptAndDecrypt_sameKeyringKey1_returnSuccess() {
    return encryptAndDecrypt_sameKeyring_returnSuccess(KEY_ARN_STR1, KEY_ARN_STR1_REGION);
}

int encryptAndDecrypt_sameKeyringKey2_returnSuccess() {
    return encryptAndDecrypt_sameKeyring_returnSuccess(KEY_ARN_STR2, KEY_ARN_STR2_REGION);
}

/**
 * Encrypts plaintext at td.pt_in and stores it in td_out.ct_out with a temporary KmsKeyring
 */
int t_kms_keyring_encrypt(TestDataOut &td_out, TestData &td, const Aws::String &key_arn) {
    auto kms_keyring_encrypt = KmsKeyring::Builder().Build({key_arn});
    TEST_ASSERT_SUCCESS(t_aws_cryptosdk_process(kms_keyring_encrypt,
                                                AWS_CRYPTOSDK_ENCRYPT,
                                                &td.pt_in,
                                                &td_out.ct_out));
    aws_cryptosdk_keyring_release(kms_keyring_encrypt);
    return 0;
}

/**
 * Decrypts plaintext at td.pt_in and stores it in td_out.pt_out using a temporary KmsKeyring
 */
int t_kms_keyring_decrypt(TestDataOut &td_out, const Aws::String &key_arn) {
    auto kms_keyring_decrypt = KmsKeyring::Builder().Build({key_arn});
    TEST_ASSERT_SUCCESS(t_aws_cryptosdk_process(kms_keyring_decrypt,
                                                AWS_CRYPTOSDK_DECRYPT,
                                                &td_out.ct_out,
                                                &td_out.pt_out));
    aws_cryptosdk_keyring_release(kms_keyring_decrypt);
    return 0;
}

/**
 * Decrypts plaintext at td.pt_in and stores it in td_out.pt_out using a discovery KmsKeyring
 */
int t_kms_keyring_discovery_decrypt(TestDataOut &td_out) {
    auto kms_keyring_discovery = KmsKeyring::Builder().BuildDiscovery();
    TEST_ASSERT_SUCCESS(t_aws_cryptosdk_process(kms_keyring_discovery,
                                                AWS_CRYPTOSDK_DECRYPT,
                                                &td_out.ct_out,
                                                &td_out.pt_out));
    aws_cryptosdk_keyring_release(kms_keyring_discovery);
    return 0;
}

struct aws_cryptosdk_keyring *kms_keyring_with_two_keys() {
    auto keyring = KmsKeyring::Builder().Build({KEY_ARN_STR2, KEY_ARN_STR1});
    if (!keyring) abort();
    return keyring;
}

int encryptAndDecrypt_twoDistinctKeyrings_returnSuccess() {
    TestData td;
    TestDataOut td_out;

    TEST_ASSERT_SUCCESS(t_kms_keyring_encrypt(td_out, td, KEY_ARN_STR1));

    TEST_ASSERT_SUCCESS(t_kms_keyring_decrypt(td_out, KEY_ARN_STR1));

    TEST_ASSERT(aws_byte_buf_eq(&td.pt_in, &td_out.pt_out));

    return 0;
}

int encryptAndDecrypt_discoveryKeyringDecrypts_returnSuccess() {
    TestData td;
    TestDataOut td_out;

    TEST_ASSERT_SUCCESS(t_kms_keyring_encrypt(td_out, td, KEY_ARN_STR1));

    TEST_ASSERT_SUCCESS(t_kms_keyring_discovery_decrypt(td_out));

    TEST_ASSERT(aws_byte_buf_eq(&td.pt_in, &td_out.pt_out));

    return 0;
}

int encryptAndDecrypt_oneKeyEncryptsTwoKeysForDecryptionConfigured_returnSuccess() {
    TestData td;
    TestDataOut td_out;

    TEST_ASSERT_SUCCESS(t_kms_keyring_encrypt(td_out, td, KEY_ARN_STR2));

    auto kms_keyring_decrypt = kms_keyring_with_two_keys();

    TEST_ASSERT_SUCCESS(t_aws_cryptosdk_process(kms_keyring_decrypt,
                                                AWS_CRYPTOSDK_DECRYPT,
                                                &td_out.ct_out,
                                                &td_out.pt_out));
    aws_cryptosdk_keyring_release(kms_keyring_decrypt);

    TEST_ASSERT(aws_byte_buf_eq(&td.pt_in, &td_out.pt_out) == true);

    return 0;
}

int encryptAndDecrypt_twoKeysEncryptsTwoKeyDecrypts_returnSuccess() {
    TestData td1, td2;
    TestDataOut td_out1, td_out2;

    td2.pt_in = aws_byte_buf_from_c_str("Testing");

    TEST_ASSERT_SUCCESS(t_kms_keyring_encrypt(td_out1, td1, KEY_ARN_STR1));
    TEST_ASSERT_SUCCESS(t_kms_keyring_encrypt(td_out2, td2, KEY_ARN_STR2));

    auto kms_keyring_decrypt = kms_keyring_with_two_keys();

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

int encryptAndDecrypt_keyForDecryptionMismatch_returnErr() {
    TestData td;
    TestDataOut td_out;

    TEST_ASSERT_SUCCESS(t_kms_keyring_encrypt(td_out, td, KEY_ARN_STR2));

    // decrypt should fail
    auto kms_keyring_decrypt = KmsKeyring::Builder().Build({KEY_ARN_STR1});
    TEST_ASSERT_SUCCESS(t_aws_cryptosdk_process(kms_keyring_decrypt,
                                                AWS_CRYPTOSDK_DECRYPT,
                                                &td_out.ct_out,
                                                &td_out.pt_out, AWS_OP_ERR));
    aws_cryptosdk_keyring_release(kms_keyring_decrypt);

    return 0;
}


static int test_assert_edk_provider_id_and_info(const char *expected_provider_id,
                                                const char *expected_provider_info,
                                                struct aws_cryptosdk_edk *edk) {
    struct aws_byte_buf provider_id_bb = aws_byte_buf_from_c_str(expected_provider_id);
    struct aws_byte_buf provider_info_bb = aws_byte_buf_from_c_str(expected_provider_info);
    TEST_ASSERT(aws_byte_buf_eq(&edk->provider_id, &provider_id_bb));
    TEST_ASSERT(aws_byte_buf_eq(&edk->provider_info, &provider_info_bb));

    return 0;
}

static const auto alg = AES_128_GCM_IV12_AUTH16_KDNONE_SIGNONE;
static aws_allocator * alloc;
static struct aws_hash_table enc_context;
static struct aws_array_list keyring_trace;

static int verify_decrypt_trace(const char *key_arn = nullptr) {
    return assert_keyring_trace_item(&keyring_trace,
                                     aws_array_list_length(&keyring_trace) - 1,
                                     AWS_CRYPTOSDK_WRAPPING_KEY_DECRYPTED_DATA_KEY |
                                     AWS_CRYPTOSDK_WRAPPING_KEY_VERIFIED_ENC_CTX,
                                     "aws-kms",
                                     key_arn);
}

/**
 * Decrypts content of edk and then compares with expected_plain_text
 * @return 0 on success when content of decryption is equal with expected_plain_text
 */
static int test_keyring_datakey_decrypt_and_compare_with_pt_datakey(struct aws_allocator *alloc,
                                                                    const struct aws_byte_buf *expected_pt_datakey,
                                                                    struct aws_cryptosdk_keyring *keyring,
                                                                    struct aws_array_list *edks,
                                                                    struct aws_hash_table *enc_context,
                                                                    enum aws_cryptosdk_alg_id alg,
                                                                    const char *decrypting_kms_arn = NULL) {
    size_t old_trace_size = aws_array_list_length(&keyring_trace);
    struct aws_byte_buf result_output = {0};
    TEST_ASSERT_SUCCESS(aws_cryptosdk_keyring_on_decrypt(keyring,
                                                         alloc,
                                                         &result_output,
                                                         &keyring_trace,
                                                         edks,
                                                         enc_context,
                                                         alg));
    TEST_ASSERT(aws_byte_buf_eq(&result_output, expected_pt_datakey));

    TEST_ASSERT_INT_EQ(aws_array_list_length(&keyring_trace), old_trace_size + 1);
    verify_decrypt_trace(decrypting_kms_arn);

    aws_byte_buf_clean_up(&result_output);
    return 0;
}

static int setup_dataKeyEncryptAndDecrypt_tests(bool fill_enc_context) {
    alloc = aws_default_allocator();
    TEST_ASSERT_SUCCESS((fill_enc_context ? test_enc_context_init_and_fill :
                         aws_cryptosdk_enc_context_init)
                        (alloc, &enc_context));
    TEST_ASSERT_SUCCESS(aws_cryptosdk_keyring_trace_init(alloc, &keyring_trace));
}

static void teardown_dataKeyEncryptAndDecrypt_tests() {
    aws_cryptosdk_enc_context_clean_up(&enc_context);
    aws_cryptosdk_keyring_trace_clean_up(&keyring_trace);
}

int dataKeyEncrypt_discoveryKeyringEncryptIsNoOp_returnSuccess() {
    TEST_ASSERT_SUCCESS(setup_dataKeyEncryptAndDecrypt_tests(true));

    aws_byte_buf pt_datakey = {0};
    Testing::Edks edks(alloc);
    auto kms_keyring = KmsKeyring::Builder().BuildDiscovery();
    TEST_ASSERT_SUCCESS(aws_cryptosdk_keyring_on_encrypt(kms_keyring,
                                                         alloc,
                                                         &pt_datakey,
                                                         &keyring_trace,
                                                         &edks.encrypted_data_keys,
                                                         &enc_context,
                                                         alg));
    TEST_ASSERT_ADDR_NULL(pt_datakey.buffer);
    TEST_ASSERT(!aws_array_list_length(&edks.encrypted_data_keys));
    TEST_ASSERT(!aws_array_list_length(&keyring_trace));
    aws_cryptosdk_keyring_release(kms_keyring);
    teardown_dataKeyEncryptAndDecrypt_tests();
    return 0;
}

static aws_cryptosdk_edk create_kms_edk(struct aws_allocator *alloc, const char *key_arn, const char *b64) {
    aws_cryptosdk_edk edk;
    edk.provider_id = aws_byte_buf_from_c_str("aws-kms");
    edk.provider_info = aws_byte_buf_from_c_str(key_arn);
    edk.enc_data_key = easy_b64_decode(b64);
    return edk;
}

static const char *key_arns[2] = {KEY_ARN_STR_FAKE, KEY_ARN_STR1};
static const char *edk_bytes[2] = {
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
    "AQEDAHhA84wnXjEJdBbBBylRUFcZZK2j7xwh6UyLoL28nQ+0FAAAAH4wfAYJKoZIhvcNAQcGoG8"
    "wbQIBADBoBgkqhkiG9w0BBwEwHgYJYIZIAWUDBAEuMBEEDPVbPiDgp7xqrnyFzwIBEIA7oESPqm"
    "r8JCHVnMaySHGncvyb73O1deYukuy/iPRJ2Ts8Q486xow2LOhl/6QMsMGY+NHoqC61cNJfr6w="
};


int dataKeyDecrypt_discoveryKeyringHandlesKeyItCannotAccess_returnSuccess() {
    TEST_ASSERT_SUCCESS(setup_dataKeyEncryptAndDecrypt_tests(false));
    const auto my_alg = AES_256_GCM_IV12_AUTH16_KDNONE_SIGNONE;
    Testing::Edks edks(alloc);

    for (int i = 0; i < 2; ++i) {
        aws_cryptosdk_edk edk = create_kms_edk(alloc, key_arns[i], edk_bytes[i]);
        TEST_ASSERT_SUCCESS(aws_array_list_push_back(&edks.encrypted_data_keys, &edk));
    }
    auto kms_keyring = KmsKeyring::Builder().BuildDiscovery();
    struct aws_byte_buf pt_datakey = easy_b64_decode(
        "sVCsYPf6v/zGp0clol/ffyVrdkqXrw4LwTxB0pRGvok=");
    TEST_ASSERT_SUCCESS(test_keyring_datakey_decrypt_and_compare_with_pt_datakey(alloc,
                                                                                 &pt_datakey,
                                                                                 kms_keyring,
                                                                                 &edks.encrypted_data_keys,
                                                                                 &enc_context,
                                                                                 my_alg,
                                                                                 KEY_ARN_STR1));

    aws_byte_buf_clean_up(&pt_datakey);
    teardown_dataKeyEncryptAndDecrypt_tests();
    aws_cryptosdk_keyring_release(kms_keyring);
    return 0;
}

int dataKeyDecrypt_doNotReturnDataKeyWhenKeyIdMismatchFromKms_returnSuccess() {
    TEST_ASSERT_SUCCESS(setup_dataKeyEncryptAndDecrypt_tests(false));
    const auto my_alg = AES_256_GCM_IV12_AUTH16_KDNONE_SIGNONE;
    Testing::Edks edks(alloc);

    // Use real key bytes that will decrypt, but for a different ARN
    aws_cryptosdk_edk edk = create_kms_edk(alloc, key_arns[0], edk_bytes[1]);
    TEST_ASSERT_SUCCESS(aws_array_list_push_back(&edks.encrypted_data_keys, &edk));
    auto kms_keyring = KmsKeyring::Builder().Build({key_arns[0]});
    struct aws_byte_buf output = {0};
    TEST_ASSERT_SUCCESS(aws_cryptosdk_keyring_on_decrypt(kms_keyring,
                                                         alloc,
                                                         &output,
                                                         &keyring_trace,
                                                         &edks.encrypted_data_keys,
                                                         &enc_context,
                                                         my_alg));
    TEST_ASSERT_ADDR_NULL(output.buffer);
    TEST_ASSERT(!aws_array_list_length(&keyring_trace));
    teardown_dataKeyEncryptAndDecrypt_tests();
    aws_cryptosdk_keyring_release(kms_keyring);
    return 0;
}

static int verify_encrypt_trace(size_t idx, bool generated = false, const char *key_arn = nullptr) {
    uint32_t flags = AWS_CRYPTOSDK_WRAPPING_KEY_ENCRYPTED_DATA_KEY |
        AWS_CRYPTOSDK_WRAPPING_KEY_SIGNED_ENC_CTX;
    if (generated) flags |= AWS_CRYPTOSDK_WRAPPING_KEY_GENERATED_DATA_KEY;
    return assert_keyring_trace_item(&keyring_trace, idx, flags, "aws-kms", key_arn);
}

int dataKeyEncryptAndDecrypt_singleKey_returnSuccess() {
    TEST_ASSERT_SUCCESS(setup_dataKeyEncryptAndDecrypt_tests(true));

    auto kms_keyring = KmsKeyring::Builder().Build({KEY_ARN_STR2});

    /* First iteration of loop, generate a data key. Second iteration, use the provided one. */
    struct aws_byte_buf pt_datakeys[2] = {{0}, aws_byte_buf_from_c_str("encrypt_me___16b")};
    for (struct aws_byte_buf &pt_datakey : pt_datakeys) {
        bool generated = !pt_datakey.buffer;
        Testing::Edks edks(alloc);
        TEST_ASSERT_SUCCESS(aws_cryptosdk_keyring_on_encrypt(kms_keyring,
                                                             alloc,
                                                             &pt_datakey,
                                                             &keyring_trace,
                                                             &edks.encrypted_data_keys,
                                                             &enc_context,
                                                             alg));

        TEST_ASSERT_INT_EQ(aws_array_list_length(&keyring_trace), 1);
        TEST_ASSERT_SUCCESS(verify_encrypt_trace(0, generated, KEY_ARN_STR2));

        TEST_ASSERT_INT_EQ(aws_array_list_length(&edks.encrypted_data_keys), 1);
        struct aws_cryptosdk_edk *edk;
        TEST_ASSERT_SUCCESS(aws_array_list_get_at_ptr(&edks.encrypted_data_keys, (void **) &edk, 0));
        TEST_ASSERT_SUCCESS(test_assert_edk_provider_id_and_info("aws-kms", KEY_ARN_STR2, edk));

        TEST_ASSERT_SUCCESS(test_keyring_datakey_decrypt_and_compare_with_pt_datakey(alloc,
                                                                                     &pt_datakey,
                                                                                     kms_keyring,
                                                                                     &edks.encrypted_data_keys,
                                                                                     &enc_context,
                                                                                     alg,
                                                                                     KEY_ARN_STR2));

        aws_byte_buf_clean_up(&pt_datakey);
        aws_cryptosdk_keyring_trace_clear(&keyring_trace);
    }
    aws_cryptosdk_keyring_release(kms_keyring);
    teardown_dataKeyEncryptAndDecrypt_tests();
    return 0;
}

int dataKeyEncryptAndDecrypt_twoKeys_returnSuccess() {
    TEST_ASSERT_SUCCESS(setup_dataKeyEncryptAndDecrypt_tests(true));

    auto encrypting_keyring_with_two_keys = kms_keyring_with_two_keys();


    /* First iteration of loop, generate a data key. Second iteration, use the provided one. */
    struct aws_byte_buf pt_datakeys[2] = {{0}, aws_byte_buf_from_c_str("encrypt_me___16b")};
    for (struct aws_byte_buf &pt_datakey : pt_datakeys) {
        bool generated = !pt_datakey.buffer;
        Testing::Edks edks(alloc);

        TEST_ASSERT_SUCCESS(aws_cryptosdk_keyring_on_encrypt(encrypting_keyring_with_two_keys,
                                                             alloc,
                                                             &pt_datakey,
                                                             &keyring_trace,
                                                             &edks.encrypted_data_keys,
                                                             &enc_context,
                                                             alg));
        TEST_ASSERT_INT_EQ(aws_array_list_length(&keyring_trace), 2);
        TEST_ASSERT_INT_EQ(aws_array_list_length(&edks.encrypted_data_keys), 2);

        std::vector<const char *> keys = {KEY_ARN_STR2, KEY_ARN_STR1};
        TEST_ASSERT_SUCCESS(verify_encrypt_trace(0, generated, keys[0]));
        TEST_ASSERT_SUCCESS(verify_encrypt_trace(1, false, keys[1]));

        // make sure it can be decrypted with either CMK
        for (unsigned int i = 0; i < keys.size(); i++) {
            struct aws_cryptosdk_edk *edk;
            TEST_ASSERT_SUCCESS(aws_array_list_get_at_ptr(&edks.encrypted_data_keys, (void **) &edk, i));
            TEST_ASSERT_SUCCESS(test_assert_edk_provider_id_and_info("aws-kms", keys[i], edk));

            auto decrypting_keyring = KmsKeyring::Builder().Build({keys[i]});
            TEST_ASSERT_ADDR_NOT_NULL(decrypting_keyring);
            TEST_ASSERT_SUCCESS(test_keyring_datakey_decrypt_and_compare_with_pt_datakey(alloc,
                                                                                         &pt_datakey,
                                                                                         decrypting_keyring,
                                                                                         &edks.encrypted_data_keys,
                                                                                         &enc_context,
                                                                                         alg,
                                                                                         keys[i]));
            aws_cryptosdk_keyring_release(decrypting_keyring);
            aws_cryptosdk_keyring_trace_clear(&keyring_trace);
        }
        aws_byte_buf_clean_up(&pt_datakey);
    }
    aws_cryptosdk_keyring_release(encrypting_keyring_with_two_keys);
    teardown_dataKeyEncryptAndDecrypt_tests();
    return 0;
}

int dataKeyEncryptAndDecrypt_twoKeysSharedBuilderAndCache_returnSuccess() {
    TEST_ASSERT_SUCCESS(setup_dataKeyEncryptAndDecrypt_tests(true));
    std::vector<const char *> keys = {KEY_ARN_STR2, KEY_ARN_STR1};
    auto builder = KmsKeyring::Builder().WithClientSupplier(KmsKeyring::CachingClientSupplier::Create());
    auto encrypting_keyring = builder.Build({keys[0], keys[1]});

    aws_cryptosdk_keyring *decrypting_keyrings[2] = {builder.Build({keys[0]}),
                                   builder.Build({keys[1]})};

    /* First iteration of loop, generate a data key. Second iteration, use the provided one. */
    struct aws_byte_buf pt_datakeys[2] = {{0}, aws_byte_buf_from_c_str("encrypt_me___16b")};
    for (struct aws_byte_buf &pt_datakey : pt_datakeys) {
        bool generated = !pt_datakey.buffer;
        Testing::Edks edks(alloc);

        TEST_ASSERT_SUCCESS(aws_cryptosdk_keyring_on_encrypt(encrypting_keyring,
                                                             alloc,
	                                                     &pt_datakey,
                                                             &keyring_trace,
	                                                     &edks.encrypted_data_keys,
                                                             &enc_context,
                                                             alg));
	TEST_ASSERT_INT_EQ(aws_array_list_length(&edks.encrypted_data_keys), 2);
        TEST_ASSERT_INT_EQ(aws_array_list_length(&keyring_trace), 2);
        TEST_ASSERT_SUCCESS(verify_encrypt_trace(0, generated, keys[0]));
        TEST_ASSERT_SUCCESS(verify_encrypt_trace(1, false, keys[1]));
        for (unsigned int i = 0; i < keys.size(); i++) {
            TEST_ASSERT_SUCCESS(test_keyring_datakey_decrypt_and_compare_with_pt_datakey(alloc,
                                                                                         &pt_datakey,
                                                                                         decrypting_keyrings[i],
                                                                                         &edks.encrypted_data_keys,
                                                                                         &enc_context,
                                                                                         alg,
                                                                                         keys[i]));
        }
        aws_byte_buf_clean_up(&pt_datakey);
        aws_cryptosdk_keyring_trace_clear(&keyring_trace);
    }
    aws_cryptosdk_keyring_release(encrypting_keyring);
    aws_cryptosdk_keyring_release(decrypting_keyrings[0]);
    aws_cryptosdk_keyring_release(decrypting_keyrings[1]);
    teardown_dataKeyEncryptAndDecrypt_tests();
    return 0;
}

//todo add more tests for grantTokens

/*
 * These RAII-style logging classes will buffer log entries until .clear() is called on the LoggingRAII object.
 * If a test fails, RUN_TEST will return from main without calling clear, and the destructor on LoggingRAII will dump
 * the buffered log entries for the specific failed test to stderr before exiting.
 */
namespace {
    class BufferedLogSystem : public Aws::Utils::Logging::FormattedLogSystem {
        private:
            std::mutex logMutex;
            std::vector<Aws::String> buffer;
        public:
            void clear() {
                std::lock_guard<std::mutex> guard(logMutex);

                buffer.clear();
            }

            void dump() {
                std::lock_guard<std::mutex> guard(logMutex);

                for (auto& str : buffer) {
                    std::cerr << str;
                }
            }

            BufferedLogSystem(Aws::Utils::Logging::LogLevel logLevel)
                : FormattedLogSystem(logLevel)
            {}
        protected:
            // Overrides FormattedLogSystem pure virtual function
            virtual void ProcessFormattedStatement(Aws::String &&statement) {
                std::lock_guard<std::mutex> guard(logMutex);

                buffer.push_back(std::move(statement));
            }
    };

    class LoggingRAII {
        std::shared_ptr<BufferedLogSystem> logSystem;

        public:
        LoggingRAII() {
            logSystem = Aws::MakeShared<BufferedLogSystem>("LoggingRAII", Aws::Utils::Logging::LogLevel::Trace);

            Aws::Utils::Logging::InitializeAWSLogging(logSystem);
        }

        void clear() {
            logSystem->clear();
        }

        ~LoggingRAII() {
            Aws::Utils::Logging::ShutdownAWSLogging();

            logSystem->dump();
        }
    };
}

int main() {
    aws_cryptosdk_load_error_strings();

    LoggingRAII logging;

    SDKOptions options;
    Aws::InitAPI(options);

    RUN_TEST(encryptAndDecrypt_sameKeyringKey1_returnSuccess());
    logging.clear();
    RUN_TEST(encryptAndDecrypt_sameKeyringKey2_returnSuccess());
    logging.clear();
    RUN_TEST(encryptAndDecrypt_twoDistinctKeyrings_returnSuccess());
    logging.clear();
    RUN_TEST(encryptAndDecrypt_discoveryKeyringDecrypts_returnSuccess());
    logging.clear();
    RUN_TEST(encryptAndDecrypt_oneKeyEncryptsTwoKeysForDecryptionConfigured_returnSuccess());
    logging.clear();
    RUN_TEST(encryptAndDecrypt_twoKeysEncryptsTwoKeyDecrypts_returnSuccess());
    logging.clear();
    RUN_TEST(encryptAndDecrypt_keyForDecryptionMismatch_returnErr());
    logging.clear();
    RUN_TEST(dataKeyEncrypt_discoveryKeyringEncryptIsNoOp_returnSuccess());
    logging.clear();
    RUN_TEST(dataKeyDecrypt_discoveryKeyringHandlesKeyItCannotAccess_returnSuccess());
    logging.clear();
    RUN_TEST(dataKeyDecrypt_doNotReturnDataKeyWhenKeyIdMismatchFromKms_returnSuccess());
    logging.clear();
    RUN_TEST(dataKeyEncryptAndDecrypt_singleKey_returnSuccess());
    logging.clear();
    RUN_TEST(dataKeyEncryptAndDecrypt_twoKeys_returnSuccess());
    logging.clear();
    RUN_TEST(dataKeyEncryptAndDecrypt_twoKeysSharedBuilderAndCache_returnSuccess());
    logging.clear();

    Aws::ShutdownAPI(options);
}
