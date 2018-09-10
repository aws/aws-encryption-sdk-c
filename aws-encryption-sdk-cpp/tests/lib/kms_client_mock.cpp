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
#include <stdexcept>

namespace Aws {
namespace Cryptosdk {
namespace Testing {
using std::logic_error;

KmsClientMock::KmsClientMock()
    : Aws::KMS::KMSClient(), expect_generate_dk(false) {}

Model::EncryptOutcome KmsClientMock::Encrypt(const Model::EncryptRequest &request) const {
    if (expected_encrypt_values.size() == 0) {
        throw logic_error("Unexpected call to encrypt");
    }

    ExpectedEncryptValues eev = expected_encrypt_values.front();
    expected_encrypt_values.pop_front();

    if (request.GetKeyId() != eev.expected_encrypt_request.GetKeyId()) {
        throw logic_error(std::string("Got :") + request.GetKeyId().c_str() + " expecting: "
                              + eev.expected_encrypt_request.GetKeyId().c_str());
    }

    if (request.GetPlaintext() != eev.expected_encrypt_request.GetPlaintext()) {
        throw logic_error(
            std::string("Got :") + reinterpret_cast<const char *>(request.GetPlaintext().GetUnderlyingData())
                + " expecting: "
                + reinterpret_cast<const char *>(eev.expected_encrypt_request.GetPlaintext().GetUnderlyingData()));
    }

    if (request.GetGrantTokens() != grant_tokens) {
        throw logic_error("Got another set of expected grant tokens");
    }

    return eev.encrypt_return;
}
void KmsClientMock::ExpectEncryptAccumulator(const Model::EncryptRequest &request, Model::EncryptOutcome encrypt_return) {
    ExpectedEncryptValues eev = { request, encrypt_return };
    this->expected_encrypt_values.push_back(eev);
}

Model::DecryptOutcome KmsClientMock::Decrypt(const Model::DecryptRequest &request) const {
    if (expected_decrypt_values.size() == 0) {
        throw std::exception();
    }
    ExpectedDecryptValues edv = expected_decrypt_values.front();
    expected_decrypt_values.pop_front();

    if (edv.expected_decrypt_request.GetCiphertextBlob() != request.GetCiphertextBlob()) {
        throw std::exception();
    }

    if (request.GetGrantTokens() != grant_tokens) {
        throw logic_error("Got another set of expected grant tokens");
    }

    return edv.return_decrypt;
}

void KmsClientMock::ExpectDecryptAccumulator(const Model::DecryptRequest &request,
                                             Model::DecryptOutcome decrypt_return) {
    ExpectedDecryptValues edv = {request, decrypt_return};
    this->expected_decrypt_values.push_back(edv);
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

    if (request.GetGrantTokens() != grant_tokens) {
        throw logic_error("Got another set of expected grant tokens");
    }

    expect_generate_dk = false;
    return generate_dk_return;
}

void KmsClientMock::ExpectGenerateDataKey(const Model::GenerateDataKeyRequest &request,
                                          Model::GenerateDataKeyOutcome generate_dk_return) {
    expect_generate_dk = true;
    expected_generate_dk_request = request;
    this->generate_dk_return = generate_dk_return;
}

bool KmsClientMock::ExpectingOtherCalls() {
    return (expected_decrypt_values.size() != 0) || (expected_encrypt_values.size() != 0) || expect_generate_dk;
}


void KmsClientMock::ExpectGrantTokens(const Aws::Vector<Aws::String> &grant_tokens) {
    this->grant_tokens = grant_tokens;
}

}  // namespace Testing
}  // namespace Cryptosdk
}  // namespace Aws

