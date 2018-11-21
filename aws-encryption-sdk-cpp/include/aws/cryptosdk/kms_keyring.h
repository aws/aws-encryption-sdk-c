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

    /**
     * Helper class for building a new KmsKeyring object. You cannot construct a KmsKeyring directly
     * and must use this class instead. This class is the only API you need to interact with KmsKeyrings.
     * You will set all of the configuration of the KmsKeyring with this class before calling Build, and
     * once the keyring is built, its configuration cannot be changed.

     * After the KmsKeyring is constructed, the only ways you should interact with the
     * (aws_cryptosdk_keyring *) are to pass it to a CMM or another keyring (such as the multi-keyring)
     * and to release the pointer with aws_cryptosdk_keyring_release.
     *
     * For general documentation about keyrings see include/aws/cryptosdk/materials.h. This header will
     * only document what is specific to the KmsKeyring.
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
         * Adds a single grant token. For more information, see
         * http://docs.aws.amazon.com/kms/latest/developerguide/concepts.html#grant_token
         *
         * May be called multiple times, adding additional grant tokens to the list that the keyring
         * is configured with. Once a grant token is added to the builder, it is not removable.
         * To build a KmsKeyring with a different set of grant tokens, use a different builder.
         */
        Builder &WithGrantToken(const Aws::String &grant_token);
        
        /**
         * Adds multiple grant tokens. For more information, see
         * http://docs.aws.amazon.com/kms/latest/developerguide/concepts.html#grant_token
         *
         * May be called multiple times, adding additional grant tokens to the list that the keyring
         * is configured with. Once a grant token is added to the builder, it is not removable.
         * To build a KmsKeyring with a different set of grant tokens, use a different builder.
         */
        Builder &WithGrantTokens(const Aws::Vector<Aws::String> &grant_tokens);

        /**
         * Sets the object that supplies and caches KMSClient instances. This allows sharing of a
         * client cache among multiple KMS keyrings. A client supplier which caches KMS clients
         * only within this KMS keyring will be created by default if one is not provided.
         */
        Builder &WithClientSupplier(const std::shared_ptr<ClientSupplier> &client_supplier);

        /**
         * KmsKeyring will use only this KMS Client regardless of the configured region.
         * If KMS Client is set then the client supplier and default region parameters are ignored.
         */
        Builder &WithKmsClient(std::shared_ptr<KMS::KMSClient> kms_client);

        /**
         * Creates a new KmsKeyring object or returns NULL if parameters are invalid.
         *
         * You must specify at least one KMS CMK to use as a master key for encryption and decryption.
         * Encrypting with multiple keys gives users who have KMS DecryptDataKey access with *any one*
         * of those keys the ability to decrypt the data. Providing multiple CMKs for decryptions
         * allows the decryption of data that was encrypted using any of those keys.
         *
         * Key IDs for encryption may be specified in four different ways:
         *
         * (1) key ARN: arn:aws:kms:us-east-1:999999999999:key/01234567-89ab-cdef-fedc-ba9876543210
         * (2) key UUID:  01234567-89ab-cdef-fedc-ba9876543210
         * (3) alias ARN:  arn:aws:kms:us-east-1:999999999999:alias/MyCryptoKey
         * (4) alias name: alias/MyCryptoKey
         *
         * If you specify keys with either key ARN or alias ARN, the AWS Encryption SDK will
         * detect what region they are in and make the KMS calls to the correct region for each key.
         * If any of the keys you specify are in either key UUID or alias name format, then you must
         * specify a default region in which to make those KMS calls. All keys in those formats must be
         * in that same default region. If you want to use multiple default regions, set up separate
         * KmsKeyrings for each default region, and join them together with a multi-keyring.
         *
         * Key IDs for decryption must be specified as key ARNs *only*, i.e., format (1) above. Formats
         * (2) through (4) will not work for decryption. The AWS Encryption SDK will allow you to attempt
         * decrypts with a KmsKeyring configured with keys in formats (2) through (4) without errors, but
         * it will only succeed in decrypting data that was encrypted with keys that were specified in
         * key ARN format. This is a limitation of the message format of encryption and of the KMS APIs,
         * not of this software package.
         */
        aws_cryptosdk_keyring *Build(const Aws::Vector<Aws::String> &key_ids) const;

        /**
         * Creates a new KmsKeyring object with no KMS keys configured, i.e., in "discovery" mode.
         * This means the following:
         *
         * (1) The KmsKeyring may not be used for encryption at all. If you attempt to encrypt with
         *     a KmsKeyring in this mode, it will fail with error code AWS_CRYPTOSDK_ERR_BAD_STATE.
         *
         * (2) On attempts to decrypt, the AWS Encryption SDK will attempt KMS DecryptDataKey calls for
         *     every KMS key that was used to encrypt the data until it finds one that you have permission
         *     to use. This may include calls to any region and to KMS keys that are outside of your
         *     account, unless prevented by policies on the IAM user or role.
         */
        aws_cryptosdk_keyring *BuildDiscovery() const;

      protected:
        bool ValidParameters(const Aws::Vector<Aws::String> &key_ids) const;
        std::shared_ptr<ClientSupplier> BuildClientSupplier(const Aws::Vector<Aws::String> &key_ids) const;
      private:
        Aws::String default_region;
        std::shared_ptr<KMS::KMSClient> kms_client;
        Aws::Vector<Aws::String> grant_tokens;
        std::shared_ptr<ClientSupplier> client_supplier;
    };

    ~KmsKeyring();
    // non-copyable
    KmsKeyring(const KmsKeyring &) = delete;
    KmsKeyring &operator=(const KmsKeyring &) = delete;

  protected:
    /**
     * Constructor of KmsKeyring for internal use only. Use KmsKeyring::Builder to make a new KmsKeyring.
     *
     * @param key_ids List of KMS customer master keys (CMK)
     * @param grant_tokens A list of grant tokens.
     * @param default_region Region used for non-ARN key IDs.
     * @param supplier Object that supplies the KMSClient instances to use for each region.
     */
    KmsKeyring(
        const Aws::Vector<Aws::String> &key_ids,
        const String &default_region,
        const Aws::Vector<Aws::String> &grant_tokens,
        std::shared_ptr<ClientSupplier> supplier);

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
    std::shared_ptr<ClientSupplier> kms_client_supplier;

    const Aws::String default_region;  // if no region can be extracted from key_id this will be used as default
    Aws::Vector<Aws::String> grant_tokens;
    Aws::Vector<Aws::String> key_ids;

  public:
    /**
     * Provides KMS clients in multiple regions, and allows caching of clients between
     * multiple KMS keyrings.
     */
    class ClientSupplier {
      public:
        virtual ~ClientSupplier() {};
        /**
         * Returns a KMS client for the particular region. Sets the flag should_cache to recommend whether to
         * cache this client. Implementations that do not support caching should always set this flag to false,
         * and implementations that do support caching should set it to true when the client that is returned is
         * not already cached.
         *
         * Implementations of GetClient may return nullptr in order to limit KMS calls to particular regions.
         * However, if a keyring is configured with KMS keys in a particular set of regions and GetClient
         * returns nullptr for any of those regions, encryption will always fail with AWS_CRYPTOSDK_ERR_BAD_STATE.
         */
        virtual std::shared_ptr<KMS::KMSClient> GetClient(const Aws::String &region, bool &should_cache) const = 0;

        /**
         * If client supplier supports caching, stores the provided client as the cached client for the
         * specified region. Otherwise, it is a no-op.
         */
	virtual void CacheClient(const Aws::String &region, std::shared_ptr<KMS::KMSClient> client) {}
    };

    class CachingClientSupplier : public ClientSupplier {
        /**
         * If a client is already cached for this region, returns that one and sets should_cache false.
         * If a client is not already cached for this region, returns a KMS client with default settings
         * and sets should_cache true. Never returns nullptr.
         */
        std::shared_ptr<KMS::KMSClient> GetClient(const Aws::String &region, bool &should_cache) const;
        /**
         * Saves the KMS client in the cache for this region, overwriting the old one for this region
         * if there is one. This is as simple an implementation as possible. Cache entries never expire.
         */
        void CacheClient(const Aws::String &region, std::shared_ptr<KMS::KMSClient> client);
      protected:
        mutable std::mutex cache_mutex;
        /**
         * Region -> KMS Client.
         */
        Aws::Map<Aws::String, std::shared_ptr<Aws::KMS::KMSClient>> cache;
    };

    /**
     * Provides the same KMS client initialized in the constructor regardless of the region.
     * Note this Supplier is not suitable for multiple regions.
     */
    class SingleClientSupplier : public ClientSupplier {
      public:
        SingleClientSupplier(const std::shared_ptr<KMS::KMSClient> &kms_client) : kms_client(kms_client) {}
        std::shared_ptr<KMS::KMSClient> GetClient(const Aws::String &, bool &should_cache) const {
            should_cache = false;
            return kms_client;
        }
      private:
        std::shared_ptr<KMS::KMSClient> kms_client;
    };

};

}  // namespace Cryptosdk
}  // namespace Aws

#endif // AWS_ENCRYPTION_SDK_KMS_KEYRING_H
