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

#include "kms_shim_mock.h"

namespace Aws {
namespace Cryptosdk {
namespace Testing {

using Aws::KMS::KMSClient;

KmsShimMock::KmsShimMock() :
    KmsShim(std::shared_ptr<KMSClient>(), Aws::String()) {
    expect_generate_flag = false;
    expect_encrypt_flag = false;
}

Aws::KMS::Model::EncryptOutcome KmsShimMock::Encrypt(const Aws::Utils::ByteBuffer &value,
                                                     const Aws::Map<Aws::String, Aws::String> &encryption_context) {
    if (!expect_encrypt_flag) {
        throw std::exception();
    }

    if (expect_encrypt_value != value) {
        throw std::exception();
    }

    expect_encrypt_flag = false;
    return return_encrypt;
}

void KmsShimMock::ExpectEncrypt(Aws::Utils::ByteBuffer &expect_encrypt_value, Model::EncryptOutcome &return_encrypt) {
    expect_encrypt_flag = true;
    this->expect_encrypt_value = expect_encrypt_value;
    this->return_encrypt = return_encrypt;
}

Aws::KMS::Model::DecryptOutcome KmsShimMock::Decrypt(const Aws::Utils::ByteBuffer &value,
                                                     const Aws::Map<Aws::String, Aws::String> &encryption_context) {
    if (expected_decrypt_values.size() == 0) {
        throw std::exception();
    }
    ExpectedDecryptValues edv = expected_decrypt_values.front();
    expected_decrypt_values.pop_front();

    if (edv.expect_plaintext != value) {
        throw std::exception();
    }

    return edv.return_decrypt;
}

void KmsShimMock::ExpectDecrypt(Aws::Utils::ByteBuffer &expect_decrypt_value, Model::DecryptOutcome &return_decrypt) {
    ExpectedDecryptValues edv = {expect_decrypt_value, return_decrypt};
    expected_decrypt_values.push_back(edv);
}

Aws::KMS::Model::GenerateDataKeyOutcome KmsShimMock::GenerateDataKey(int key_len,
                                                                     const Aws::Map<Aws::String,
                                                                                    Aws::String> &encryption_context) {
    if (!expect_generate_flag) {
        throw std::exception();
    }

    if (expect_generate_key_len != key_len) {
        throw std::exception();
    }

    expect_generate_flag = false;
    return return_generate;
}

void KmsShimMock::ExpectGenerate(int expected_key_len, Model::GenerateDataKeyOutcome &return_generate) {
    expect_generate_flag = true;
    this->return_generate = return_generate;
    expect_generate_key_len = expected_key_len;

}

bool KmsShimMock::ExpectingOtherCalls() {
    return (expect_generate_flag || (expected_decrypt_values.size() != 0) || expect_encrypt_flag);
}

}  // namespace Testing
}  // namespace Cryptosdk
}  // namespace Aws
