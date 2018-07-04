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
const char *KEY_ARN_STR = "arn:aws:kms:us-west-2:658956600833:key/b3537ef1-d8dc-4780-9f5a-55776cbb2f7f";

struct TestData {
    struct aws_allocator *alloc;
    const uint8_t *pt_str = (uint8_t *) "Hello, world!";
    const struct aws_byte_buf pt_in;
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

    auto kms_c_master_key = Aws::New<KmsCMasterKey>(CLASS_CTAG, td.kms_client, KEY_ARN_STR, td.alloc);

    // encrypt
    TEST_ASSERT_SUCCESS(aws_cryptosdk_process(kms_c_master_key, AWS_CRYPTOSDK_ENCRYPT, &td.pt_in, &td_out.ct_out));

    // decrypt
    TEST_ASSERT_SUCCESS(aws_cryptosdk_process(kms_c_master_key, AWS_CRYPTOSDK_DECRYPT, &td_out.ct_out, &td_out.pt_out));

    TEST_ASSERT(aws_byte_buf_eq(&td.pt_in, &td_out.pt_out) == true);

    Aws::Delete(kms_c_master_key);

    return 0;
}

int t_decrypt_encrypt_two_mk() {
    TestData td;
    TestDataOut td_out;

    // encrypt
    auto kms_c_master_key_encrypt = Aws::New<KmsCMasterKey>(CLASS_CTAG, td.kms_client, KEY_ARN_STR, td.alloc);
    TEST_ASSERT_SUCCESS(aws_cryptosdk_process(kms_c_master_key_encrypt,
                                              AWS_CRYPTOSDK_ENCRYPT,
                                              &td.pt_in,
                                              &td_out.ct_out));
    Aws::Delete(kms_c_master_key_encrypt);

    // decrypt
    auto kms_c_master_key_decrypt = Aws::New<KmsCMasterKey>(CLASS_CTAG, td.kms_client, KEY_ARN_STR, td.alloc);
    TEST_ASSERT_SUCCESS(aws_cryptosdk_process(kms_c_master_key_decrypt,
                                              AWS_CRYPTOSDK_DECRYPT,
                                              &td_out.ct_out,
                                              &td_out.pt_out));
    Aws::Delete(kms_c_master_key_decrypt);

    TEST_ASSERT(aws_byte_buf_eq(&td.pt_in, &td_out.pt_out) == true);

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

    //Aws::Utils::Logging::ShutdownAWSLogging();

    Aws::ShutdownAPI(*options);
    Aws::Delete(options);
}

