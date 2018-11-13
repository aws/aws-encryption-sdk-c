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

class KmsKeyring : public aws_cryptosdk_keyring {
  public:
    class ClientSupplier;

    ~KmsKeyring();

    // non-copyable
    KmsKeyring(const KmsKeyring &) = delete;
    KmsKeyring &operator=(const KmsKeyring &) = delete;

  protected:
    /**
     * Initializes KmsKeyring using a list of KeyIds
     * Use KmsKeyring::Builder to allocate a new KmsKeyring.
     * @param key_ids A list with unique identifier for the customer master key (KMS).
     *               To specify a master key, use its key ID, Amazon Resource Name (ARN), alias name, or alias ARN.
     *               This should be specified in the same structure as the one required by KMS client
     * @param grant_tokens A list of grant tokens. For more information, see <a
     *                    href="http://docs.aws.amazon.com/kms/latest/developerguide/concepts.html#grant_token">Grant
     *                    Tokens</a> in the <i>AWS Key Management Service Developer Guide</i>
     * @param default_region This region will be used when specifying key IDs for encryption that are not full ARNs,
     *                      but are instead bare key IDs or aliases.
     * @param supplier Object that supplies an KMSClient instance to use for a given region.
     */
    KmsKeyring(
        const Aws::List<Aws::String> &key_ids,
        const String &default_region,
        const Aws::Vector<Aws::String> &grant_tokens,
        std::shared_ptr<ClientSupplier> supplier);

    /**
     * Attempts to find a valid KMS-keyring-generated EDK to decrypt, and if found
     * makes calls to KMS to decrypt it. Will attempt for any valid KMS-keyring-generated
     * EDK in the list until it succeeds in decrypting one.
     * @param keyring Pointer to an aws_cryptosdk_keyring object
     * @param request_alloc Allocator passed from the request, used for all per-decryption allocations.
     * @param unencrypted_data_key Pointer to byte buffer for output. Must be zeroed at call time.
     * @param edks Pointer to list of EDKs to attempt to decrypt.
     * @param enc_context Pointer to encryption context to be used as AAD in decryption.
     * @param alg Algorithm suite that was used to produce the ciphertext.
     * @return On success AWS_OP_SUCCESS will be returned. This does not necessarily mean that the data key will be
     *         decrypted, as it is normal behavior that a particular keyring may not find an EDK that it can decrypt.
     *         To determine whether the data key was decrypted, check unencrypted_data_key.buffer. If the
     *         data key was not decrypted, that pointer will be set to NULL. If the data key was decrypted, that pointer
     *         will point to the bytes of the key.
     *         On internal failure, AWS_OP_ERR will be returned and an internal error code will be set.
     */
    static int OnDecrypt(struct aws_cryptosdk_keyring *keyring,
                         struct aws_allocator *request_alloc,
                         struct aws_byte_buf *unencrypted_data_key,
                         const struct aws_array_list *edks,
                         const struct aws_hash_table *enc_context,
                         enum aws_cryptosdk_alg_id alg);

    /**
     * The keyring attempts to generate a new data key, if one is not provided in unencrypted data key buffer,
     * and attempts to encrypt either the newly generated data key or the one previously in the buffer.
     * @param keyring Pointer to an aws_cryptosdk_keyring object
     * @param request_alloc Allocator passed from the request, used for all per-encryption allocations.
     * @param unencrypted_data_key If zeroed, receives new data key as output, if not is input for data key encryption.
     * @param edks Pointer to previously allocated EDK list. If data key is encrypted, the new EDK will be appended.
     * @param enc_context Pointer to encryption context to be used as AAD in encryption.
     * @param alg Algorithm suite to be used to encrypt plaintext.
     * @return On success (1) AWS_OP_SUCCESS is returned, (2) the unencrypted data key buffer will contain the raw
     *         bytes of the data key, and (3) an EDK will be appended onto the list of EDKs.
     *         On failure AWS_OP_ERR is returned, an internal AWS error code is set, and no memory is allocated.
     */
    static int OnEncrypt(struct aws_cryptosdk_keyring *keyring,
                         struct aws_allocator *request_alloc,
                         struct aws_byte_buf *unencrypted_data_key,
                         struct aws_array_list *edks,
                         const struct aws_hash_table *enc_context,
                         enum aws_cryptosdk_alg_id alg);

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
     * Returns the KMS Client for a specific key ID
     */
    std::shared_ptr<KMS::KMSClient> GetKmsClient(const Aws::String &key_id) const;

    /**
     *  Creates a AWS C++ SDK KMS Client for region with default options.
     */
    static std::shared_ptr<KMS::KMSClient> CreateDefaultKmsClient(const Aws::String &region);

  private:
    const aws_byte_buf key_provider;
    std::shared_ptr<ClientSupplier> kms_client_supplier;

    const Aws::String default_region;  // if no region can be extracted from key_id this will be used as default
    Aws::Vector<Aws::String> grant_tokens;

    // FIXME: change to Aws::Vector in builder and here
    Aws::List<Aws::String> key_ids;

  public:
    /**
     * Interface that supplies KmsKeyring with KMS Client objects
     */
    class ClientSupplier {
      public:
        /**
         * Returns a KMS Client in the specified region. Does not acquire a lock on the cache.
         * Only to be used in cases where the cache is not being modified during operation of keyring.
         */
        virtual std::shared_ptr<KMS::KMSClient> UnlockedGetClient(const Aws::String &region_name) const = 0;
        virtual ~ClientSupplier() {};
    };

    /**
     * Provides KMS clients in multiple regions, and allows caching of clients between
     * multiple KMS keyrings.
     */
    class CachingClientSupplier : public ClientSupplier {
      public:
        std::shared_ptr<KMS::KMSClient> UnlockedGetClient(const Aws::String &region_name) const;

        /**
         * Returns a KMS Client in the specified region. Does acquire the cache lock.
         * Always use this instead of UnlockedGetClient if the cache can be modified during keyring
         * operation. (i.e., for Discovery Keyring)
         */
        std::shared_ptr<KMS::KMSClient> LockedGetClient(const Aws::String &region_name) const;

        /**
         * Stores the provided client as the cached client for the specified region. If the client
         * is not provided, constructs a default client for the specified region.
         */
	void PutClient(const Aws::String &region, std::shared_ptr<KMS::KMSClient> client = nullptr);
      private:
        /**
         * Acquired by both PutClient and LockedGetClient before accessing the cache.
         */
        mutable std::mutex cache_mutex;
        /**
         * Region name -> KMS Client.
         */
        Aws::Map<Aws::String, std::shared_ptr<Aws::KMS::KMSClient>> cache;
    };

    /**
     * Provides the same KMS client initialized in the constructor regardless of the region.
     * Note this Supplier is not suitable for multiple regions.
     */
    class SingleClientSupplier : public ClientSupplier {
      public:
        SingleClientSupplier(const std::shared_ptr<KMS::KMSClient> &kms_client);
        std::shared_ptr<KMS::KMSClient> UnlockedGetClient(const Aws::String &region_name) const;
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
         * Sets default region. This region will be used when specifying key IDs that are not full ARNs,
         * but are instead bare key IDs or aliases. If all key IDs provided are full ARNs, this is not
         * necessary. If KMS Client is set, then this parameter is ignored.
         */
        Builder &WithDefaultRegion(const Aws::String &default_region);

        /**
         * Adds multiple KMS keys to the already configured keys.
         * To specify a master key, use its key ID, Amazon Resource Name (ARN), alias name, or alias ARN.
         * At least one key needs to be configured!
         */
        Builder &WithKeyIds(const Aws::List<Aws::String> &key_ids);

        /**
         * Adds a new KMS key to the already configured keys.
         * To specify a master key, use its key ID, Amazon Resource Name (ARN), alias name, or alias ARN.
         * At least one key needs to be configured!
         */
        Builder &WithKeyId(const Aws::String &key_id);

        /**
         *  Adds a list of grant tokens. For more information, see
         *  <a href="http://docs.aws.amazon.com/kms/latest/developerguide/concepts.html#grant_token">Grant
         *  Tokens</a> in the <i>AWS Key Management Service Developer Guide</i>
         */
        Builder &WithGrantTokens(const Aws::Vector<Aws::String> &grant_tokens);

        /**
         *  Adds a single grant token.
         */
        Builder &WithGrantToken(const Aws::String &grant_token);

        /**
         * Sets the object that supplies and caches KMSClient instances. This allows re-usability of a
         * caching client supplier among more than one KMS keyring. This is optional. A client supplier
         * will be created if one is not provided.
         */
        Builder &WithCachingClientSupplier(const std::shared_ptr<CachingClientSupplier> &client_supplier);

        /**
         * KmsKeyring will use only this KMS Client regardless of the configured region.
         * If KMS Client is set then the ClientSupplier and default_region parameters are ignored.
         */
        Builder &WithKmsClient(std::shared_ptr<KMS::KMSClient> kms_client);

        /**
         * Creates a new KmsKeyring object or return NULL if parameters are invalid
         */
        aws_cryptosdk_keyring *Build() const;

        /**
         * Returns true if parameters are valid
         */
        bool ValidParameters() const;
      protected:
        std::shared_ptr<ClientSupplier> BuildClientSupplier() const;
      private:
        Aws::List<Aws::String> key_ids;
        Aws::String default_region;
        std::shared_ptr<KMS::KMSClient> kms_client;
        Aws::Vector<Aws::String> grant_tokens;
        std::shared_ptr<CachingClientSupplier> client_supplier;
    };
};

}  // namespace Cryptosdk
}  // namespace Aws

#endif // AWS_ENCRYPTION_SDK_KMS_KEYRING_H
