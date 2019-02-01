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

#include <aws/cryptosdk/cpp/exports.h>

#include <aws/core/Aws.h>
#include <aws/core/utils/Outcome.h>
#include <aws/core/utils/memory/stl/AWSMap.h>
#include <aws/core/utils/memory/stl/AWSString.h>
#include <aws/core/utils/memory/stl/AWSVector.h>
#include <aws/cryptosdk/materials.h>
#include <aws/kms/KMSClient.h>
#include <functional>
#include <mutex>

namespace Aws {
namespace Cryptosdk {
namespace KmsKeyring {
class ClientSupplier;

/**
 * @defgroup kms_keyring KMS keyring (AWS SDK for C++)
 *
 * We have implemented a keyring on top of KMS, which uses the AWS SDK for C++
 * as its underlying KMS client.  This is compatible with the Java and Python
 * KMSMasterKeyProvider.
 *
 * Because there is no pure-C AWS KMS client at the moment, C++ is required to
 * use this keyring. We expect that a parallel pure-C API will be added in the
 * future when a pure-C KMS client becomes available.
 *
 * @{
 */

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
class AWS_CRYPTOSDK_CPP_API Builder {
   public:
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
     * KmsKeyring will use only this KMS Client. Note that this is only suitable if all
     * KMS keys are in one region. If this is set then the client supplied parameter is ignored.
     */
    Builder &WithKmsClient(const std::shared_ptr<KMS::KMSClient> &kms_client);

    /**
     * Creates a new KmsKeyring object or returns NULL if parameters are invalid.
     *
     * You must specify at least one KMS CMK to use as a master key for encryption and decryption
     * as the generator CMK. This CMK is the first one that will be used in all encryption and
     * decryption attempts, and it is the only key for which you need to have KMS GenerateDataKey
     * permissions in order to do encryption.
     *
     * If this keyring is called for encryption after another keyring has already generated the
     * data key (for example, in a multi-keyring) then the generator CMK will encrypt an existing
     * data key. In that case, you will need KMS Encrypt permissions on this CMK.
     *
     * Optionally, you may specify a list of additional CMKs to encrypt the data key with.
     * Encrypting with multiple CMKs gives users who have KMS Decrypt access with *any one*
     * of those CMKs the ability to decrypt the data. For encryption you will only need KMS Encrypt
     * permission on the additional CMKs. You will NEVER need KMS GenerateDataKey permission on them.
     *
     * Providing multiple CMKs for decryption allows the decryption of data that was encrypted using
     * any of those keys. You will need KMS Decrypt permission on the generator CMK and all other CMKs.
     *
     * Key IDs for encryption may be specified in two different ways:
     *
     * (1) key ARN: arn:aws:kms:us-east-1:999999999999:key/01234567-89ab-cdef-fedc-ba9876543210
     * (2) alias ARN:  arn:aws:kms:us-east-1:999999999999:alias/MyCryptoKey
     *
     * Key IDs for decryption must be specified as key ARNs only, i.e., format (1) above. Format
     * (2) will not work for decryption. The AWS Encryption SDK will allow you to attempt decrypts
     * with a KmsKeyring configured with keys in format (2) without errors, but it will only succeed
     * in decrypting data that was encrypted with keys that were specified in key ARN format. This
     * is a limitation of the message format of encryption and of the KMS APIs, not of this library.
     */
    aws_cryptosdk_keyring *Build(
        const Aws::String &generator_key_id, const Aws::Vector<Aws::String> &additional_key_ids = {}) const;

    /**
     * Creates a new KmsKeyring object with no KMS keys configured, i.e., in "discovery" mode.
     * This means the following:
     *
     * (1) This KmsKeyring will not do anything on encryption attempts. If you attempt encryption
     *     with this as your only keyring, it will fail. If you include this keyring as part of a
     *     multi-keyring and attempt encryption, the results will be the same as if this keyring
     *     was not included.
     *
     * (2) On attempts to decrypt, the AWS Encryption SDK will attempt KMS DecryptDataKey calls for
     *     every KMS key that was used to encrypt the data until it finds one that you have permission
     *     to use. This may include calls to any region and to KMS keys that are outside of your
     *     account, unless prevented by policies on the IAM user or role.
     */
    aws_cryptosdk_keyring *BuildDiscovery() const;

   private:
    std::shared_ptr<KMS::KMSClient> kms_client;
    Aws::Vector<Aws::String> grant_tokens;
    std::shared_ptr<ClientSupplier> client_supplier;
};

/**
 * Provides KMS clients in multiple regions, and allows caching of clients between
 * multiple KMS keyrings.
 */
class AWS_CRYPTOSDK_CPP_API ClientSupplier {
   public:
    virtual ~ClientSupplier(){};
    /**
     * Returns a KMS client for the particular region. Returns a callable at report_success which should be
     * called if the client is used successfully.
     *
     * Implementations of GetClient may return nullptr in order to limit KMS calls to particular regions.
     * However, if a keyring is configured with KMS keys in a particular set of regions and GetClient
     * returns nullptr for any of those regions, encryption will always fail with AWS_CRYPTOSDK_ERR_BAD_STATE.
     */
    virtual std::shared_ptr<KMS::KMSClient> GetClient(
        const Aws::String &region, std::function<void()> &report_success) = 0;
};

class AWS_CRYPTOSDK_CPP_API CachingClientSupplier : public ClientSupplier {
   public:
    /**
     * Helper function which creates a new CachingClientSupplier and returns a shared pointer to it.
     */
    static std::shared_ptr<CachingClientSupplier> Create();

    /**
     * If a client is already cached for this region, returns that one and provides a no-op callable.
     * If a client is not already cached for this region, returns a KMS client with default settings
     * and provides a callable which will cache the client. Never returns nullptr.
     */
    std::shared_ptr<KMS::KMSClient> GetClient(const Aws::String &region, std::function<void()> &report_success);

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
class AWS_CRYPTOSDK_CPP_API SingleClientSupplier : public ClientSupplier {
   public:
    /**
     * Helper function which creates a new SingleClientSupplier and returns a shared pointer to it.
     */
    static std::shared_ptr<SingleClientSupplier> Create(const std::shared_ptr<KMS::KMSClient> &kms_client);

    /**
     * Always returns the same KMS client this supplier was initialized with and provides a no-op callable.
     */
    std::shared_ptr<KMS::KMSClient> GetClient(const Aws::String &, std::function<void()> &report_success);

    SingleClientSupplier(const std::shared_ptr<KMS::KMSClient> &kms_client) : kms_client(kms_client) {}

   private:
    std::shared_ptr<KMS::KMSClient> kms_client;
};

/** @} */  // doxygen group kms_keyring

}  // namespace KmsKeyring

}  // namespace Cryptosdk
}  // namespace Aws

#endif  // AWS_ENCRYPTION_SDK_KMS_KEYRING_H
