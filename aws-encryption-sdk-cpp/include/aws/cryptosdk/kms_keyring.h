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

#include <mutex>
#include <aws/common/common.h>
#include <aws/core/utils/memory/AWSMemory.h>
#include <aws/core/utils/memory/stl/AWSString.h>
#include <aws/core/utils/memory/stl/AWSMap.h>
#include <aws/core/utils/memory/stl/AWSVector.h>
#include <aws/core/utils/Outcome.h>
#include <aws/kms/KMSClient.h>
#include <aws/kms/model/EncryptRequest.h>
#include <aws/kms/model/DecryptRequest.h>
#include <aws/kms/model/GenerateDataKeyRequest.h>
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
    class RegionalClientSupplier;
    /**
     *
     * @param constructor_key Parameter used to enforce calling of this constructor only from friend classes
     */
    ~KmsKeyring();

    // non-copyable
    KmsKeyring(const KmsKeyring &) = delete;
    KmsKeyring &operator=(const KmsKeyring &) = delete;

    /**
     * Returns cached clients from this object
     */
    const Map<Aws::String, std::shared_ptr<Aws::KMS::KMSClient>> GetKmsCachedClients() const;

  protected:
    /**
     * Initializes KmsKeyring using a list of KeyIds
     * Use KmsKeyring::Builder to allocate a new KmsKeyring.
     * @param alloc Allocator structure. An instance of this will be passed around for anything needing memory
     *              allocation
     * @param key_ids A list with unique identifier for the customer master key (KMS).
     *               To specify a master key, use its key ID, Amazon Resource Name (ARN), alias name, or alias ARN.
     *               This should be specified in the same structure as the one required by KMS client
     * @param grant_tokens A list of grant tokens. For more information, see <a
     *                    href="http://docs.aws.amazon.com/kms/latest/developerguide/concepts.html#grant_token">Grant
     *                    Tokens</a> in the <i>AWS Key Management Service Developer Guide</i>
     * @param default_region This region will be used when specifying key IDs for encryption that are not full ARNs,
     *                      but are instead bare key IDs or aliases.
     * @param supplier Object that supplies an KMSClient instance to use for a given region.
     * @param kms_client_cache A cache object for the kms clients. This allows re-usability of Kms clients among
     *                         multiple instances of KmsKeyring. Can be used in applications that frequently create new
     *                         keyrings and are sensitive to performance.
     */
    KmsKeyring(
        struct aws_allocator *alloc,
        const Aws::List<Aws::String> &key_ids,
        const String &default_region,
        const Aws::Vector<Aws::String> &grant_tokens,
        std::shared_ptr<RegionalClientSupplier> supplier,
        const Aws::Map<Aws::String, std::shared_ptr<Aws::KMS::KMSClient>> &kms_client_cache);

    /**
     * It attempts to find one of the EDKs to decrypt
     * This function will be automatically called when a Data Key needs to be decrypted
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
     * This function will be automatically called when a Data Key needs to be encrypted
     * @param keyring Pointer to an aws_cryptosdk_keyring object
     * @param enc_mat Encryption materials
     * @return  On success AWS_OP_SUCCESS is returned, the new EDK will be appended onto the list of EDKs.
     *          On failure AWS_OP_ERR is returned, an internal AWS error code is set, and no memory is allocated.
     */
    static int EncryptDataKey(aws_cryptosdk_keyring *keyring,
                              struct aws_cryptosdk_encryption_materials *enc_mat);

    /**
     * The keyring attempts to generate a new data key, and returns it in both unencrypted and encrypted form.
     * This function will be automatically called when a Keyring needs to generate a new pair of encrypted,
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
     * Destroys all allocated structures
     * @param keyring Pointer to an aws_cryptosdk_keyring object
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
    Aws::KMS::Model::DecryptRequest CreateDecryptRequest(const Aws::String &key_id,
                                                         const Aws::Vector<Aws::String> &grant_tokens,
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
     * Returns a new map <KeyId, KMS-Region>
     */
    Aws::Map<Aws::String, Aws::String> BuildKeyIds(const Aws::List<Aws::String> &key_ids) const;

    /**
     * Returns the region of the key_id or an empty string if it can't extract region
     */
    Aws::String GetRegionForConfiguredKmsKeys(const Aws::String &key_id) const;

    /**
     * Returns the KMS Client for a specific region. It can extract it either from the cache (if it exists) or it will
     * create a new one
     */
    std::shared_ptr<KMS::KMSClient> GetKmsClient(const Aws::String &region) const;

    /**
     * Saves a KMS Client for a specific region in the cache.
     * Note: a KMS Client can be saved in cache only after a succesful call was made to it
     * (to guarantee that the region exists)
     */
    void SaveKmsClientInCache(const Aws::String &region, std::shared_ptr<KMS::KMSClient> &kms_client);

  private:
    void Init(struct aws_allocator *alloc, const Aws::List<Aws::String> &in_key_ids);
    void InitAwsCryptosdkKeyring(struct aws_allocator *allocator);

    const aws_byte_buf key_provider;
    std::shared_ptr<RegionalClientSupplier> kms_client_supplier;

    Aws::String default_key_id;  // default key used for encryption/key generation
    const Aws::String default_region;  // if no region can be extracted from key_id this will be used as default

    //TODO add support for grant_tokens
    Aws::Vector<Aws::String> grant_tokens;

    //TODO use Aws::UnorderedMap
    // A map of <region, kms-client>. A single Kms client is cached for each region. Note that in order to be cached a
    // client needs to have at least one successful request to KMS.
    Aws::Map<Aws::String, std::shared_ptr<Aws::KMS::KMSClient>> kms_cached_clients;

    //TODO use Aws::UnorderedMap
    // A map of <key-id, region>
    Aws::Map<Aws::String, Aws::String> key_ids;

    mutable std::mutex keyring_cache_mutex;

  public:
    /**
     * Interface that supplies KmsKeyring with a new KMSClient in a specific region
     */
    class RegionalClientSupplier {
      public:
        /**
         * Returns a new KMSClient in the specified region
         */
        virtual std::shared_ptr<KMS::KMSClient> GetClient(const Aws::String &region_name) const = 0;
        virtual ~RegionalClientSupplier() {};
    };

    /**
     * Provides the default configured KMSClient in a specific region
     */
    class DefaultRegionalClientSupplier : public RegionalClientSupplier {
      public:
        std::shared_ptr<KMS::KMSClient> GetClient(const Aws::String &region_name) const;
    };

    /*
     * Provides the same KMS client initialized in the constructor regardless of the region
     * Note this Supplier is not suitable for multiple regions
     */
    class SingleClientSupplier : public RegionalClientSupplier {
      public:
        SingleClientSupplier(const std::shared_ptr<KMS::KMSClient> &kms_client);
        std::shared_ptr<KMS::KMSClient> GetClient(const Aws::String &region_name) const;
      private:
        std::shared_ptr<KMS::KMSClient> kms_client;
    };

  public:
    /**
     * Builds a new KmsKeyring object
     */
    class Builder {
      public:
        /**
         * Sets allocator structure. An instance of this will be passed around for anything needing memory
         * allocation.
         * If no allocator is set the aws_default_allocator() is used
         */
        Builder &SetAllocator(struct aws_allocator *alloc);

        /**
         * Sets default region. This region will be used when specifying key IDs for encryption that are not full ARNs,
         * but are instead bare key IDs or aliases.
         * If KMS Client is set then the RegionalClientSupplier and default_region parameters are ignored
         */
        Builder &SetDefaultRegion(const String &default_region);

        /**
         * Appends KMS keys to the already configured keys.
         * To specify a master key, use its key ID, Amazon Resource Name (ARN), alias name, or alias ARN.
         * This should be specified in the same structure as the one required by KMS client
         * At least one key needs to be configured!
         */
        Builder &AppendKeyIds(const Aws::List<Aws::String> &key_ids);

        /**
         * Appends a new KMS key to the already configured keys
         * To specify a master key, use its key ID, Amazon Resource Name (ARN), alias name, or alias ARN.
         * This should be specified in the same structure as the one required by KMS client
         * At least one key needs to be configured!
         */
        Builder &AppendKeyId(const Aws::String &key_id);

        /**
         * Sets a single KMS key to be used
         * To specify a master key, use its key ID, Amazon Resource Name (ARN), alias name, or alias ARN.
         * This should be specified in the same structure as the one required by KMS client
         * At least one key needs to be configured!
         */
        Builder &SetKeyId(const Aws::String &key_id);

        /**
         * Sets a list with unique identifiers for the customer master key (KMS)
         * To specify a master key, use its key ID, Amazon Resource Name (ARN), alias name, or alias ARN.
         * This should be specified in the same structure as the one required by KMS client
         * At least one key needs to be configured!
         */
        Builder &SetKeyIds(const Aws::List<Aws::String> &key_ids);

        /**
         *  A list of grant tokens. For more information, see
         *  <a href="http://docs.aws.amazon.com/kms/latest/developerguide/concepts.html#grant_token">Grant
         *  Tokens</a> in the <i>AWS Key Management Service Developer Guide</i>
         */
        Builder &SetGrantTokens(const Aws::Vector<Aws::String> &grant_tokens);

        /**
         * Sets the object that supplies a KMSClient instance to use for a given region.
         */
        Builder &SetRegionalClientSupplier(const std::shared_ptr<RegionalClientSupplier> &client_supplier);

        /**
         * Sets a cache object for the kms clients. This allows re-usability of Kms clients among
         * multiple instances of KmsKeyring. Can be used in applications that frequently create new
         * keyrings and are sensitive to performance.
         */
        Builder &SetKmsClientCache(const Aws::Map<Aws::String, std::shared_ptr<Aws::KMS::KMSClient>> &kms_key_cache);

        /**
         * KmsKeyring will use only this KMS Client regardless of the configured region.
         * If KMS Client is set then the RegionalClientSupplier and default_region parameters are ignored
         */
        Builder &SetKmsClient(std::shared_ptr<KMS::KMSClient> kms_client);

        /**
         * Creates a new KmsKeyring object or return NULL if parameters are invalid
         */
        KmsKeyring *Build() const;

        /**
         * Returns true if parameters are valid
         */
        bool ValidParameters() const;
      protected:
        Aws::String BuildDefaultRegion() const;
        std::shared_ptr<RegionalClientSupplier> BuildClientSupplier() const;
        struct aws_allocator * BuildAllocator() const;
      private:
        struct aws_allocator *alloc;
        Aws::List<Aws::String> key_ids;
        Aws::String default_region;
        std::shared_ptr<KMS::KMSClient> kms_client;
        Aws::Vector<Aws::String> grant_tokens;
        std::shared_ptr<RegionalClientSupplier> client_supplier;
        Aws::Map<Aws::String, std::shared_ptr<Aws::KMS::KMSClient>> kms_key_cache;
    };
};

}  // namespace Cryptosdk
}  // namespace Aws

#endif // AWS_ENCRYPTION_SDK_KMS_KEYRING_H
