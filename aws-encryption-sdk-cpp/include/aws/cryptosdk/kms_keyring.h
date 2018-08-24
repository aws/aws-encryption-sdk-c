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
#ifndef AWS_ENCRYPTION_SDK_KMS_KEYRING_H
#define AWS_ENCRYPTION_SDK_KMS_KEYRING_H

#include <aws/common/common.h>
#include <aws/core/utils/memory/AWSMemory.h>
#include <aws/core/utils/memory/stl/AWSString.h>
#include <aws/core/utils/memory/stl/AWSMap.h>
#include <aws/core/utils/memory/stl/AWSVector.h>
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

class KmsKeyring;

struct aws_cryptosdk_kms_keyring : aws_cryptosdk_keyring {
    struct aws_allocator *alloc;
    KmsKeyring *keyring_data;
};

/**
 * Class that allows C AWS Enc SDK to use C++ KMS Keyring
 */
class KmsKeyring : public aws_cryptosdk_kms_keyring {
  public:
    //todo move in a separate file
    class RegionalClientSupplier {
      public:
        virtual std::shared_ptr<KMS::KMSClient> getClient(const String &region_name) = 0;
        virtual ~RegionalClientSupplier() {};
    };

    class DefaultRegionalClientSupplier : public RegionalClientSupplier {
      public:
        std::shared_ptr<KMS::KMSClient> getClient(const String &region_name);
    };

    class SingleClientSupplier : public RegionalClientSupplier {
      public:
        SingleClientSupplier(const std::shared_ptr<KMS::KMSClient> &kms_client);
        std::shared_ptr<KMS::KMSClient> getClient(const String &region_name);
      private:
        std::shared_ptr<KMS::KMSClient> kms_client;
    };

    /**
     * Initializes KmsKeyring to use Aws::KMS::KMSClient with a key_id
     * @param kms_client KMS client object
     * @param key_id A unique identifier for the customer master key (KMS).
     *               To specify a master key, use its key ID, Amazon Resource Name (ARN), alias name, or alias ARN.
     *               This should be specified in the same structure as the one required by KMS client
     * @param alloc Allocator structure. An instance of this will be passed around for anything needing memory
     *              allocation
     */
    KmsKeyring(struct aws_allocator *alloc,
               std::shared_ptr<Aws::KMS::KMSClient> kms_client,
               const String &key_id);

    KmsKeyring(struct aws_allocator *alloc,
               Aws::List<Aws::String> key_ids,
               Aws::List<String> grantTokens = {},
               Aws::String defaultRegion = Aws::Region::US_EAST_1,
               std::shared_ptr<RegionalClientSupplier> supplier = std::make_shared<DefaultRegionalClientSupplier>());

    KmsKeyring(struct aws_allocator *alloc,
               Aws::String keyId);

    ~KmsKeyring();

    // non-copyable
    KmsKeyring(const KmsKeyring &) = delete;
    KmsKeyring &operator=(const KmsKeyring &) = delete;

  protected:

    /**
     * It attempts to find one of the EDKs to decrypt
     * This function will be automatically called when a Master Key needs to be decrypted
     * @param keyring Pointer to an aws_cryptosdk_keyring object
     * @param dec_mat Decryption Materials
     * @param request A structure that contains a list of EDKS and an encryption context.
     * @return On success AWS_OP_SUCCESS will be returned. This does not necessarily mean that the data key will be
     *         decrypted, as it is normal behavior that a particular keyring may not find an EDK that it can decrypt.
     *         To determine whether the data key was decrypted, check dec_mat->unencrypted_data_key.buffer. If the
     *         data key was not decrypted, that pointer will be set to NULL. If the data key was decrypted, that pointer
     *         will point to the raw bytes of the key.
     *         On internal failure, AWS_OP_ERR will be returned and an internal error code will be set.
     */
    static int DecryptDataKey(struct aws_cryptosdk_keyring *keyring,
                              struct aws_cryptosdk_decryption_materials *dec_mat,
                              const aws_cryptosdk_decryption_request *request);

    /**
     * The keyring attempts to encrypt the data key.
     * This function will be automatically called when a Master Key needs to be encrypted
     * @param keyring Pointer to an aws_cryptosdk_keyring object
     * @param enc_mat Encryption materials
     * @return  On success AWS_OP_SUCCESS is returned, the new EDK will be appended onto the list of EDKs.
     *          On failure AWS_OP_ERR is returned, an internal AWS error code is set, and no memory is allocated.
     */
    static int EncryptDataKey(aws_cryptosdk_keyring *keyring,
                              struct aws_cryptosdk_encryption_materials *enc_mat);

    /**
     * The keyring attempts to generate a new data key, and returns it in both unencrypted and encrypted form.
     * This function will be automatically called when a Master Key needs to generate a new pair of encrypted,
     * unencrypted data keys
     * @param keyring Pointer to an aws_cryptosdk_keyring object
     * @param enc_mat
     * @return On success (1) AWS_OP_SUCCESS is returned, (2) the unencrypted data key buffer will contain the raw
     *         bytes of the data key, and (3) an EDK will be appended onto the list of EDKs.
     *         On failure AWS_OP_ERR is returned, an internal AWS error code is set, and no memory is allocated.
     */
    static int GenerateDataKey(struct aws_cryptosdk_keyring *keyring,
                               struct aws_cryptosdk_encryption_materials *enc_mat);

    /**
     * Destroys all allocated structures, except self.
     * You will need to delete this class
     * @param keyring Pointer to an aws_cryptosdk_keyring object
     */
    static void DestroyAwsCryptoKeyring(aws_cryptosdk_keyring *keyring);

  protected:
    Aws::KMS::Model::EncryptRequest CreateEncryptRequest(const Aws::String &key_id,
                                                         const Aws::Vector<Aws::String> &grant_tokens,
                                                         const Utils::ByteBuffer &plaintext,
                                                         const Aws::Map<Aws::String, Aws::String> &encryption_context) const;

    Aws::KMS::Model::DecryptRequest CreateDecryptRequest(const Aws::String &key_id,
                                                         const Aws::Vector<Aws::String> &grant_tokens,
                                                         const Utils::ByteBuffer &ciphertext,
                                                         const Aws::Map<Aws::String, Aws::String> &encryption_context) const;

    Aws::KMS::Model::GenerateDataKeyRequest CreateGenerateDataKeyRequest(const Aws::String &key_id,
                                                                         const Aws::Vector<Aws::String> &grant_tokens,
                                                                         int number_of_bytes,
                                                                         const Aws::Map<Aws::String,
                                                                                        Aws::String> &encryption_context) const;

    Aws::Map<Aws::String, Aws::String> BuildKeyIDs(const Aws::List<Aws::String> &key_ids) const;

    Aws::String GetClientRegion(const Aws::String &key_id) const;
    std::shared_ptr<KMS::KMSClient> GetKmsClient(const Aws::String &region) const;
    void SaveKmsClientInCache(const Aws::String &region, std::shared_ptr<KMS::KMSClient> &kms_client);

  private:
    void Init(struct aws_allocator *alloc, const Aws::List<Aws::String> &in_key_ids);
    void InitAwsCryptosdkKeyring(struct aws_allocator *allocator);
    aws_cryptosdk_keyring_vt CreateAwsCryptosdkKeyring() const;

    const aws_byte_buf key_provider;
    std::shared_ptr<RegionalClientSupplier> kms_client_supplier;

    // key used for encryption/key generation
    Aws::String default_key_arn;
    // if no region can be extracted from key_id this will be used as default
    const Aws::String default_region;

    //TODO add support for grant_tokens
    Aws::Vector<Aws::String> grant_tokens;

    // A map of <region, kms-client>. A single Kms client is cached for each region. Note that in order to be cached a
    // client needs to have at least one successful request to KMS.
    Aws::Map<Aws::String, std::shared_ptr<Aws::KMS::KMSClient>> kms_cached_clients;

    // A map of <key-id, region>
    Aws::Map<Aws::String, Aws::String> key_ids;
};

}  // namespace Cryptosdk
}  // namespace Aws

#endif // AWS_ENCRYPTION_SDK_KMS_KEYRING_H
