/*
 * Copyright 2021 Amazon.com, Inc. or its affiliates. All Rights Reserved.
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

#include <fstream>

#include <aws/common/encoding.h>
#include <aws/core/utils/ARN.h>
#include <aws/core/utils/Array.h>
#include <aws/core/utils/FileSystemUtils.h>
#include <aws/core/utils/HashingUtils.h>
#include <aws/core/utils/json/JsonSerializer.h>
#include <aws/core/utils/logging/AWSLogging.h>
#include <aws/core/utils/logging/ConsoleLogSystem.h>

#include <aws/cryptosdk/cpp/kms_keyring.h>
#include <aws/cryptosdk/enc_ctx.h>
#include <aws/cryptosdk/materials.h>
#include <aws/cryptosdk/multi_keyring.h>
#include <aws/cryptosdk/private/header.h>

#include "credential_reusing_client_supplier.h"
#include "edks_utils.h"
#include "logutils.h"
#include "test_crypto.h"
#include "testutil.h"

#define BUFFER_SIZE (1 << 20)

using namespace Aws::Cryptosdk;
using namespace Aws::Utils::Json;

using Aws::SDKOptions;

const char *CLASS_CTAG = "Test KMS";

/* This special test key has been configured to allow Encrypt, Decrypt, and GenerateDataKey operations from any
 * AWS principal and should be used when adding new KMS tests.
 * You should never use it in production!
 */
const char *KEY_ARN = "arn:aws:kms:us-west-2:658956600833:key/b3537ef1-d8dc-4780-9f5a-55776cbb2f7f";
// const char *KEY_ARN_REGION = Aws::Region::US_WEST_2;

static const Aws::String PT_BYTES = "foobar";

static uint8_t encrypt_output[BUFFER_SIZE];
static uint8_t decrypt_output[BUFFER_SIZE];
static std::shared_ptr<KmsKeyring::ClientSupplier> client_supplier;

static void setup_all() {
    client_supplier = Aws::Cryptosdk::Testing::CredentialCachingClientSupplier::Create();
}

static void setup_test() {
    memset(encrypt_output, 0, sizeof(encrypt_output));
    memset(decrypt_output, 0, sizeof(decrypt_output));
}

static int do_encrypt(struct aws_cryptosdk_session *session, uint8_t *encrypt_output, size_t *output_len) {
    size_t input_len = PT_BYTES.size();
    size_t input_consumed;
    TEST_ASSERT_SUCCESS(aws_cryptosdk_session_set_message_size(session, input_len));
    int rv = aws_cryptosdk_session_process(
        session,
        encrypt_output,
        BUFFER_SIZE,
        output_len,
        (const uint8_t *)PT_BYTES.c_str(),
        input_len,
        &input_consumed);
    if (rv) return rv;
    TEST_ASSERT_INT_EQ(input_len, input_consumed);
    TEST_ASSERT(aws_cryptosdk_session_is_done(session));
    return 0;
}

static int do_decrypt(
    struct aws_cryptosdk_session *session, uint8_t *encrypt_output, size_t input_len, uint8_t *decrypt_output) {
    size_t output_len;
    size_t input_consumed;
    int rv = aws_cryptosdk_session_process(
        session, decrypt_output, BUFFER_SIZE, &output_len, encrypt_output, input_len, &input_consumed);
    if (rv) return rv;
    TEST_ASSERT_INT_EQ(input_len, input_consumed);
    TEST_ASSERT(aws_cryptosdk_session_is_done(session));
    TEST_ASSERT_INT_EQ(0, PT_BYTES.compare((const char *)decrypt_output));
    return 0;
}

static aws_cryptosdk_keyring *kms_keyring_with_n_edks(size_t num_edks) {
    Aws::Vector<Aws::String> extra_key_arns;
    for (size_t edk_idx = 1; edk_idx < num_edks; ++edk_idx) {
        extra_key_arns.push_back(KEY_ARN);
    }
    struct aws_cryptosdk_keyring *kr =
        Aws::Cryptosdk::KmsKeyring::Builder().WithClientSupplier(client_supplier).Build(KEY_ARN, extra_key_arns);
    if (!kr) abort();
    return kr;
}

static int do_encrypt_with_n_edks(size_t num_edks) {
    struct aws_cryptosdk_keyring *kr = kms_keyring_with_n_edks(num_edks);
    struct aws_cryptosdk_session *session =
        aws_cryptosdk_session_new_from_keyring_2(aws_default_allocator(), AWS_CRYPTOSDK_ENCRYPT, kr);
    TEST_ASSERT_ADDR_NOT_NULL(session);
    aws_cryptosdk_keyring_release(kr);
    TEST_ASSERT_SUCCESS(
        aws_cryptosdk_session_set_commitment_policy(session, COMMITMENT_POLICY_FORBID_ENCRYPT_ALLOW_DECRYPT));
    TEST_ASSERT_SUCCESS(aws_cryptosdk_session_set_max_encrypted_data_keys(session, 3));

    size_t output_len;
    int rv = do_encrypt(session, encrypt_output, &output_len);
    aws_cryptosdk_session_destroy(session);
    return rv;
}

static int do_decrypt_with_n_edks(size_t num_edks) {
    struct aws_cryptosdk_keyring *kr = kms_keyring_with_n_edks(num_edks);
    struct aws_cryptosdk_session *session =
        aws_cryptosdk_session_new_from_keyring_2(aws_default_allocator(), AWS_CRYPTOSDK_ENCRYPT, kr);
    TEST_ASSERT_ADDR_NOT_NULL(session);
    aws_cryptosdk_keyring_release(kr);
    TEST_ASSERT_SUCCESS(
        aws_cryptosdk_session_set_commitment_policy(session, COMMITMENT_POLICY_FORBID_ENCRYPT_ALLOW_DECRYPT));

    size_t output_len;
    TEST_ASSERT_SUCCESS(do_encrypt(session, encrypt_output, &output_len));
    TEST_ASSERT_SUCCESS(aws_cryptosdk_session_reset(session, AWS_CRYPTOSDK_DECRYPT));
    TEST_ASSERT_SUCCESS(aws_cryptosdk_session_set_max_encrypted_data_keys(session, 3));
    int rv = do_decrypt(session, encrypt_output, output_len, decrypt_output);
    aws_cryptosdk_session_destroy(session);
    return rv;
}

static int encrypt_less_than_max_edks() {
    setup_test();
    TEST_ASSERT_SUCCESS(do_encrypt_with_n_edks(2));
    return 0;
}

static int encrypt_equal_to_max_edks() {
    setup_test();
    TEST_ASSERT_SUCCESS(do_encrypt_with_n_edks(3));
    return 0;
}

static int encrypt_more_than_max_edks() {
    setup_test();
    TEST_ASSERT_ERROR(AWS_CRYPTOSDK_ERR_LIMIT_EXCEEDED, do_encrypt_with_n_edks(4));
    return 0;
}

static int decrypt_less_than_max_edks() {
    setup_test();
    TEST_ASSERT_SUCCESS(do_decrypt_with_n_edks(2));
    return 0;
}

static int decrypt_equal_to_max_edks() {
    setup_test();
    TEST_ASSERT_SUCCESS(do_decrypt_with_n_edks(3));
    return 0;
}

static int decrypt_more_than_max_edks() {
    setup_test();
    TEST_ASSERT_ERROR(AWS_CRYPTOSDK_ERR_LIMIT_EXCEEDED, do_decrypt_with_n_edks(4));
    return 0;
}

static int run_tests() {
    setup_all();
    RUN_TEST(encrypt_less_than_max_edks());
    RUN_TEST(encrypt_equal_to_max_edks());
    RUN_TEST(encrypt_more_than_max_edks());
    RUN_TEST(decrypt_less_than_max_edks());
    RUN_TEST(decrypt_equal_to_max_edks());
    RUN_TEST(decrypt_more_than_max_edks());
    return 0;
}

int main(int argc, char **argv) {
    aws_common_library_init(aws_default_allocator());
    aws_cryptosdk_load_error_strings();

    Aws::Cryptosdk::Testing::LoggingRAII logging;

    SDKOptions options;
    Aws::InitAPI(options);

    int error = run_tests();
    if (!error) {
        logging.clear();
    }

    Aws::ShutdownAPI(options);

    return error;
}
