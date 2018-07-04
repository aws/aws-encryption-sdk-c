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

#include "kms_client_mock.h"

namespace Aws {
namespace Cryptosdk {
namespace Testing {

KmsClientMock::KmsClientMock()
    : Aws::KMS::KMSClient(), expect_encrypt(false), expect_decrypt(false), expect_generate_dk(false) {}

Model::EncryptOutcome KmsClientMock::Encrypt(const Model::EncryptRequest &request) const {
    if (!expect_encrypt) {
        throw std::exception();
    }

    if (request.GetKeyId() != expected_encrypt_request.GetKeyId()) {
        throw std::exception();
    }

    if (request.GetPlaintext() != expected_encrypt_request.GetPlaintext()) {
        throw std::exception();
    }
    expect_encrypt = false;
    return encrypt_return;
}
void KmsClientMock::ExpectEncrypt(const Model::EncryptRequest &request, Model::EncryptOutcome encrypt_return) {
    expect_encrypt = true;
    expected_encrypt_request = request;
    this->encrypt_return = encrypt_return;
}

Model::DecryptOutcome KmsClientMock::Decrypt(const Model::DecryptRequest &request) const {
    if (!expect_decrypt) {
        throw std::exception();
    }

    if (request.GetCiphertextBlob() != expected_decrypt_request.GetCiphertextBlob()) {
        throw std::exception();
    }

    expect_decrypt = false;
    return decrypt_return;
}

void KmsClientMock::ExpectDecrypt(const Model::DecryptRequest &request, Model::DecryptOutcome decrypt_return) {
    expect_decrypt = true;
    expected_decrypt_request = request;
    this->decrypt_return = decrypt_return;
}

Model::GenerateDataKeyOutcome KmsClientMock::GenerateDataKey(const Model::GenerateDataKeyRequest &request) const {
    if (!expect_generate_dk) {
        throw std::exception();
    }

    if (request.GetKeyId() != expected_generate_dk_request.GetKeyId()) {
        throw std::exception();
    }

    if (request.GetNumberOfBytes() != expected_generate_dk_request.GetNumberOfBytes()) {
        throw std::exception();
    }

    return generate_dk_return;
}

void KmsClientMock::ExpectGenerateDataKey(const Model::GenerateDataKeyRequest &request,
                                          Model::GenerateDataKeyOutcome generate_dk_return) {
    expect_generate_dk = true;
    expected_generate_dk_request = request;
    this->generate_dk_return = generate_dk_return;
}

}  // namespace Testing
}  // namespace Cryptosdk
}  // namespace Aws

