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

#ifndef AWS_ENCRYPTION_SDK_KMS_SHIM_MOCK_H
#define AWS_ENCRYPTION_SDK_KMS_SHIM_MOCK_H

#include <deque>
#include <aws/cryptosdk/private/kms_shim.h>
#include <aws/kms/model/EncryptRequest.h>
#include <aws/kms/model/EncryptResult.h>
#include <aws/kms/model/DecryptRequest.h>
#include <aws/kms/model/DecryptResult.h>
#include <aws/kms/model/GenerateDataKeyRequest.h>
#include <aws/kms/model/GenerateDataKeyResult.h>

namespace Aws {
namespace Cryptosdk {
namespace Testing {

namespace Model = Aws::KMS::Model;

/**
 * This class simulates a mock for KmsShim. No cpp testing framework is allowed at this time
 */
//TODO check encryption_context
class KmsShimMock : public Aws::Cryptosdk::Private::KmsShim {
  public:
    KmsShimMock();

    Model::EncryptOutcome Encrypt(const Aws::Utils::ByteBuffer &value,
                                  const Aws::Map<Aws::String, Aws::String> &encryption_context);
    void ExpectEncrypt(Aws::Utils::ByteBuffer &expect_encrypt_value, Model::EncryptOutcome &return_encrypt);

    Model::DecryptOutcome Decrypt(const Aws::Utils::ByteBuffer &value,
                                  const Aws::Map<Aws::String, Aws::String> &encryption_context);
    void ExpectDecrypt(Aws::Utils::ByteBuffer &expect_decrypt_value, Model::DecryptOutcome &return_decrypt);

    Model::GenerateDataKeyOutcome GenerateDataKey(int key_len,
                                                  const Aws::Map<Aws::String, Aws::String> &encryption_context);
    void ExpectGenerate(int expected_key_len, Model::GenerateDataKeyOutcome &return_generate);

    bool ExpectingOtherCalls();

  private:
    bool expect_encrypt_flag;
    Aws::Utils::ByteBuffer expect_encrypt_value;
    Model::EncryptOutcome return_encrypt;

    struct ExpectedDecryptValues {
        Aws::Utils::ByteBuffer expect_plaintext;
        Model::DecryptOutcome return_decrypt;
    };
    std::deque<ExpectedDecryptValues> expected_decrypt_values;

    bool expect_generate_flag;
    int expect_generate_key_len;
    Model::GenerateDataKeyOutcome return_generate;
};

}  // namespace Testing
}  // namespace Cryptosdk
}  // namespace Aws

#endif //AWS_ENCRYPTION_SDK_KMS_SHIM_MOCK_H
