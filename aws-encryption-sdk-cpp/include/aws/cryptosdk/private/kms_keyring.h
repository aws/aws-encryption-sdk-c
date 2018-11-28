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
#ifndef AWS_ENCRYPTION_SDK_PRIVATE_KMS_KEYRING_H
#define AWS_ENCRYPTION_SDK_PRIVATE_KMS_KEYRING_H

#include <aws/cryptosdk/kms_keyring.h>

namespace Aws {
namespace Cryptosdk {
namespace Private {

class KmsKeyringImpl : public aws_cryptosdk_keyring {
  public:
    ~KmsKeyringImpl();
    // non-copyable
    KmsKeyringImpl(const KmsKeyringImpl &) = delete;
    KmsKeyringImpl &operator=(const KmsKeyringImpl &) = delete;

  protected:
    /**
     * Constructor of KmsKeyring for internal use only. Use KmsKeyring::Builder to make a new KmsKeyring.
     *
     * @param key_ids List of KMS customer master keys (CMK)
     * @param grant_tokens A list of grant tokens.
     * @param default_region Region used for non-ARN key IDs.
     * @param supplier Object that supplies the KMSClient instances to use for each region.
     */
    KmsKeyringImpl(
        const Aws::Vector<Aws::String> &key_ids,
        const String &default_region,
        const Aws::Vector<Aws::String> &grant_tokens,
        std::shared_ptr<Aws::Cryptosdk::KmsKeyring::ClientSupplier> supplier);

    /**
     * This is the function that will be called virtually by calling aws_cryptosdk_keyring_on_decrypt
     * on the KmsKeyring pointer. See aws_cryptosdk_keyring_on_decrypt in
     * include/aws/cryptosdk/materials.h for general information on this interface.
     */
    static int OnDecrypt(struct aws_cryptosdk_keyring *keyring,
                         struct aws_allocator *request_alloc,
                         struct aws_byte_buf *unencrypted_data_key,
                         const struct aws_array_list *edks,
                         const struct aws_hash_table *enc_context,
                         enum aws_cryptosdk_alg_id alg);

    /**
     * This is the function that will be called virtually by calling aws_cryptosdk_keyring_on_encrypt
     * on the KmsKeyring pointer. See aws_cryptosdk_keyring_on_encrypt in
     * include/aws/cryptosdk/materials.h for general information on this interface.
     */
    static int OnEncrypt(struct aws_cryptosdk_keyring *keyring,
                         struct aws_allocator *request_alloc,
                         struct aws_byte_buf *unencrypted_data_key,
                         struct aws_array_list *edks,
                         const struct aws_hash_table *enc_context,
                         enum aws_cryptosdk_alg_id alg);

    /**
     * This is the function that will be called virtually by calling aws_cryptosdk_keyring_release
     * on the KmsKeyring pointer. See aws_cryptosdk_keyring_release in
     * include/aws/cryptosdk/materials.h for general information on this interface.
     */
    static void DestroyAwsCryptoKeyring(aws_cryptosdk_keyring *keyring);

    /**
     * Creates a new KMS Encrypt request
     */
    Aws::KMS::Model::EncryptRequest CreateEncryptRequest(const Aws::String &key_id,
                                                         const Aws::Vector<Aws::String> &grant_tokens,
                                                         const Utils::ByteBuffer &plaintext,
                                                         const Aws::Map<Aws::String,
                                                                        Aws::String> &encryption_context) const;

    /**
     * Creates a new KMS Decrypt request
     */
    Aws::KMS::Model::DecryptRequest CreateDecryptRequest(const Aws::Vector<Aws::String> &grant_tokens,
                                                         const Utils::ByteBuffer &ciphertext,
                                                         const Aws::Map<Aws::String,
                                                                        Aws::String> &encryption_context) const;

    /**
     * Creates a new KMS Generate Data Key request
     */
    Aws::KMS::Model::GenerateDataKeyRequest CreateGenerateDataKeyRequest(
        const Aws::String &key_id,
        const Aws::Vector<Aws::String> &grant_tokens,
        int number_of_bytes,
        const Aws::Map<Aws::String, Aws::String> &encryption_context) const;

    /**
     * Returns the KMS Client for a specific key ID
     */
    std::shared_ptr<KMS::KMSClient> GetKmsClient(const Aws::String &key_id) const;

  private:
    const aws_byte_buf key_provider;
    std::shared_ptr<Aws::Cryptosdk::KmsKeyring::ClientSupplier> kms_client_supplier;

    const Aws::String default_region;  // if no region can be extracted from key_id this will be used as default
    Aws::Vector<Aws::String> grant_tokens;
    Aws::Vector<Aws::String> key_ids;
};

}  // namespace Private
}  // namespace Cryptosdk
}  // namespace Aws

#endif // AWS_ENCRYPTION_SDK_PRIVATE_KMS_KEYRING_H
