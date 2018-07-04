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
#ifndef AWS_ENCRYPTION_SDK_KMS_SHIM_H
#define AWS_ENCRYPTION_SDK_KMS_SHIM_H

#include <aws/core/utils/Outcome.h>
#include <aws/kms/KMSClient.h>
#include <aws/kms/model/EncryptRequest.h>
#include <aws/kms/model/EncryptRequest.h>
#include <aws/kms/model/EncryptResult.h>
#include <aws/kms/model/DecryptRequest.h>
#include <aws/kms/model/DecryptResult.h>
#include <aws/kms/model/GenerateDataKeyRequest.h>
#include <aws/kms/model/GenerateDataKeyResult.h>
#include <aws/cryptosdk/materials.h>

namespace Aws {
namespace Cryptosdk {
namespace Private {

/**
 * Class that handles communication with KMS
 */
class KmsShim {
  public:
    /**
     * Initializes KmsShim using the KMS::KMSClient and key_id
     * @param kms_client KMS client object
     * @param key_id A unique identifier for the customer master key (CMK).
     *               To specify a CMK, use its key ID, Amazon Resource Name (ARN), alias name, or alias ARN.
     *               This should be specified in the same structure as the one required by KMS client
     */
    KmsShim(std::shared_ptr<KMS::KMSClient> kms_client, const String &key_id);
    virtual ~KmsShim() {};

    // non-copyable
    KmsShim(const KmsShim &) = delete;
    KmsShim &operator=(const KmsShim &) = delete;

    /**
     * Encrypts plaintext into ciphertext by using a customer master key (CMK).
     */
    virtual Aws::KMS::Model::EncryptOutcome Encrypt(const Utils::ByteBuffer &plaintext,
        const Aws::Map<Aws::String, Aws::String> &encryption_context);

    /*
     * Decrypts ciphertext. Ciphertext is plaintext that has been previously
     * encrypted with KMS
     */
    virtual Aws::KMS::Model::DecryptOutcome Decrypt(const Utils::ByteBuffer &ciphertext,
                                               const Aws::Map<Aws::String, Aws::String> &encryption_context);

    /**
     * Returns a data encryption key that you can use in your application to encrypt data locally.
     * @param number_of_bytes The length of the data encryption key in bytes. For example, use the value 64
     *                        to generate a 512-bit data key (64 bytes is 512 bits).
     */
    virtual Aws::KMS::Model::GenerateDataKeyOutcome GenerateDataKey(int number_of_bytes,
        const Aws::Map<Aws::String, Aws::String> &encryption_context);

  private:
    std::shared_ptr<Aws::KMS::KMSClient> kms_client;
    const Aws::String key_id;
    //TODO add support for grant_tokens
    Aws::Vector<Aws::String> grant_tokens;

};

}  // namespace Private
}  // namespace Cryptosdk
}  // namespace Aws

#endif  // AWS_ENCRYPTION_SDK_KMS_SHIM_H
