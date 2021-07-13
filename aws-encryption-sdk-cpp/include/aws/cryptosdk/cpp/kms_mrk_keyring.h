/*
 * Copyright 2021 Amazon.com, Inc. or its affiliates. All Rights Reserved.
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
#ifndef AWS_ENCRYPTION_SDK_KMS_MRK_KEYRING_H
#define AWS_ENCRYPTION_SDK_KMS_MRK_KEYRING_H

#include <aws/cryptosdk/cpp/exports.h>
#include <aws/cryptosdk/cpp/kms_keyring.h>

#include <aws/core/Aws.h>
#include <aws/core/utils/Outcome.h>
#include <aws/core/utils/memory/stl/AWSMap.h>
#include <aws/core/utils/memory/stl/AWSSet.h>
#include <aws/core/utils/memory/stl/AWSString.h>
#include <aws/core/utils/memory/stl/AWSVector.h>
#include <aws/cryptosdk/materials.h>
#include <aws/kms/KMSClient.h>
#include <functional>
#include <mutex>

namespace Aws {
namespace Cryptosdk {
namespace KmsMrkAwareSymmetricKeyring {

/**
 * @defgroup kms_mrk_keyring KMS Multi-Region Key aware keyring (AWS SDK for C++)
 *
 * We have implemented a keyring on top of KMS, which uses the AWS SDK for C++
 * as its underlying KMS client.
 *
 * Because there is no pure-C AWS KMS client at the moment, C++ is required to
 * use this keyring. We expect that a parallel pure-C API will be added in the
 * future when a pure-C KMS client becomes available.
 *
 * @{
 */

/**
 * Helper class for building a new KmsMrkAwareSymmetricKeyring object. You
 * cannot construct a KmsMrkAwareSymmetricKeyring directly and must use this
 * class instead. This class is the only API you need to interact with these
 * keyrings. You will set all of the configuration of the keyring with this
 * class before calling Build, and once the keyring is built, its configuration
 * cannot be changed.

 * After the keyring is constructed, the only ways you should interact with the
 * (aws_cryptosdk_keyring *) are to pass it to a CMM or another keyring (such as the multi-keyring)
 * and to release the pointer with aws_cryptosdk_keyring_release.
 *
 * For general documentation about keyrings see include/aws/cryptosdk/materials.h. This header will
 * only document what is specific to the KmsMrkAwareSymmetricKeyring.
 */
class AWS_CRYPTOSDK_CPP_API Builder {
   public:
    /**
     * Adds a single grant token. For more information, see
     * http://docs.aws.amazon.com/kms/latest/developerguide/concepts.html#grant_token
     *
     * May be called multiple times, adding additional grant tokens to the list that the keyring
     * is configured with. Once a grant token is added to the builder, it is not removable.
     * To build a KmsMrkAwareSymmetricKeyring with a different set of grant tokens, use a different builder.
     */
    Builder &WithGrantToken(const Aws::String &grant_token);

    /**
     * Adds multiple grant tokens. For more information, see
     * http://docs.aws.amazon.com/kms/latest/developerguide/concepts.html#grant_token
     *
     * May be called multiple times, adding additional grant tokens to the list that the keyring
     * is configured with. Once a grant token is added to the builder, it is not removable.
     * To build a KmsMrkAwareSymmetricKeyring with a different set of grant tokens, use a different builder.
     */
    Builder &WithGrantTokens(const Aws::Vector<Aws::String> &grant_tokens);

    /**
     * Sets the object that supplies and caches KMSClient instances. This allows sharing of a
     * client cache among multiple KMS keyrings. A client supplier which caches KMS clients
     * only within this KMS keyring will be created by default if one is not provided.
     *
     * This option is invalid for a KmsMrkAwareSymmetricKeyring in discovery
     * mode. Instead, supply a single KMS client using WithKmsClient.
     */
    Builder &WithClientSupplier(const std::shared_ptr<KmsKeyring::ClientSupplier> &client_supplier);

    /**
     * KmsMrkAwareSymmetricKeyring will use only this KMS Client. Note that this is only suitable if all
     * KMS keys are in one region. If this is set then the client supplier parameter is ignored.
     *
     * This option is required for a KmsMrkAwareSymmetricKeyring in discovery mode.
     */
    Builder &WithKmsClient(const std::shared_ptr<KMS::KMSClient> &kms_client);

    /**
     * Creates a new KmsMrkAwareSymmetricKeyring object using the provided KMS
     * CMK, or returns NULL if parameters are invalid. The keyring will use the
     * CMK for both encryption and decryption. (If you need to encrypt or
     * decrypt with multiple KMS CMKs, use @ref MultiKeyringBuilder.)
     *
     * If this keyring is called for encryption after another keyring has
     * already generated the data key (for example, in a multi-keyring) then
     * the CMK will encrypt an existing data key. In that case, you will need
     * KMS Encrypt permissions on this CMK. Otherwise, if this keyring is
     * called for encryption before any other keyring has generated a data key,
     * then you additionally need KMS GenerateDataKey permissions.
     *
     * If this keyring is called for decryption, you will need KMS Decrypt
     * permission on the CMK.
     *
     * Key IDs for encryption may be specified in two different ways:
     *
     * (1) key ARN: arn:aws:kms:us-east-1:999999999999:key/01234567-89ab-cdef-fedc-ba9876543210
     * (2) alias ARN:  arn:aws:kms:us-east-1:999999999999:alias/MyCryptoKey
     *
     * Key IDs for decryption must be specified as key ARNs only, i.e., format
     * (1) above. Format (2) will not work for decryption. The AWS Encryption
     * SDK will allow you to attempt decrypts with a
     * KmsMrkAwareSymmetricKeyring configured with keys in format (2) without
     * errors, but it will only succeed in decrypting data that was encrypted
     * with keys that were specified in key ARN format. This is a limitation of
     * the message format of encryption and of the KMS APIs, not of this
     * library.
     */
    aws_cryptosdk_keyring *Build(const Aws::String &key_id) const;

    /**
     * Creates a new KmsMrkAwareSymmetricKeyring object with no KMS keys configured, i.e., in "discovery" mode.
     * This means the following:
     *
     * (1) This keyring will not do anything on encryption attempts. If you attempt encryption
     *     with this as your only keyring, it will fail.
     *
     * (2) On attempts to decrypt, the AWS Encryption SDK will attempt KMS DecryptDataKey calls for
     *     every KMS key that was used to encrypt the data until it finds one that you have permission
     *     to use, and is in the specified region. This may include calls to KMS keys that are outside
     *     of your account, unless prevented by policies on the IAM user or role.
     *
     * IMPORTANT: The provided region MUST match the region of the configured KMS client.
     *
     * If you need to decrypt in multiple regions, use @ref MultiKeyringBuilder.
     */
    aws_cryptosdk_keyring *BuildDiscovery(const Aws::String &region) const;

    /**
     * Creates a new KmsMrkAwareSymmetricKeyring object in discovery mode (i.e., no KMS keys
     * configured) but with a DiscoveryFilter. This means the following:
     *
     * (1) As in discovery mode without a DiscoveryFilter, this keyring will
     * not do anything on encryption attempts.
     *
     * (2) On attempts to decrypt, the AWS Encryption SDK will attempt KMS
     *     DecryptDataKey calls for every KMS key that was used to encrypt the
     *     data until it finds one that:
     *
     *       (a) you have permission to use, and
     *       (b) is in the specified region, and
     *       (c) is in an account specified by the DiscoveryFilter
     *
     * The discovery_filter argument must not be nullptr, or else this function
     * fails and returns nullptr.
     *
     * IMPORTANT: The provided region MUST match the region of the configured KMS client.
     *
     * If you need to decrypt in multiple regions, use @ref MultiKeyringBuilder.
     */
    aws_cryptosdk_keyring *BuildDiscovery(
        const Aws::String &region, std::shared_ptr<KmsKeyring::DiscoveryFilter> discovery_filter) const;

   private:
    std::shared_ptr<KMS::KMSClient> kms_client;
    Aws::Vector<Aws::String> grant_tokens;
    std::shared_ptr<KmsKeyring::ClientSupplier> client_supplier;
    Aws::String region;
};

/**
 * Helper class for building multi-keyrings composed of
 * KmsMrkAwareSymmetricKeyring objects.
 */
class AWS_CRYPTOSDK_CPP_API MultiKeyringBuilder {
   public:
    /**
     * Adds a single grant token. For more information, see
     * http://docs.aws.amazon.com/kms/latest/developerguide/concepts.html#grant_token
     *
     * May be called multiple times, adding additional grant tokens to the list that the keyring
     * is configured with. Once a grant token is added to the builder, it is not removable.
     * To build a KmsMrkAwareSymmetricKeyring with a different set of grant tokens, use a different builder.
     */
    MultiKeyringBuilder &WithGrantToken(const Aws::String &grant_token);

    /**
     * Adds multiple grant tokens. For more information, see
     * http://docs.aws.amazon.com/kms/latest/developerguide/concepts.html#grant_token
     *
     * May be called multiple times, adding additional grant tokens to the list that the keyring
     * is configured with. Once a grant token is added to the builder, it is not removable.
     * To build a KmsMrkAwareSymmetricKeyring with a different set of grant tokens, use a different builder.
     */
    MultiKeyringBuilder &WithGrantTokens(const Aws::Vector<Aws::String> &grant_tokens);

    /**
     * Sets the object that supplies and caches KMSClient instances. This allows sharing of a
     * client cache among multiple KMS keyrings. A client supplier which caches KMS clients
     * only within this KMS keyring will be created by default if one is not provided.
     */
    MultiKeyringBuilder &WithClientSupplier(const std::shared_ptr<KmsKeyring::ClientSupplier> &client_supplier);

    /**
     * Builds a strict-mode multi-keyring, i.e. a multi-keyring composed of
     * KmsMrkAwareSymmetricKeyring objects in strict mode. The resulting
     * multi-keyring will only attempt to encrypt or decrypt using key
     * identifiers provided as the generator key ID or additional key IDs, as
     * well as key identifiers which are multi-region replicas.
     */
    aws_cryptosdk_keyring *Build(
        const Aws::String &generator_key_id, const Aws::Vector<Aws::String> &additional_key_ids = {}) const;

    /**
     * Builds a strict-mode multi-keyring, i.e. a multi-keyring composed of
     * KmsMrkAwareSymmetricKeyring objects in strict mode. The resulting
     * multi-keyring will only attempt to encrypt or decrypt using the key
     * identifiers provided, well as key identifiers which are multi-region
     * replicas.
     *
     * It will not generate data keys - to create a strict-mode multi-keyring
     * that generates data keys, use @ref Build(const Aws::String &, const Aws::Vector<Aws::String> &).
     */
    aws_cryptosdk_keyring *Build(const Aws::Vector<Aws::String> &additional_key_ids = {}) const;

    /**
     * Builds a discovery-mode multi-keyring, i.e. a multi-keyring composed of
     * KmsMrkAwareSymmetricKeyring objects in discovery mode, one for each
     * provided region.
     */
    aws_cryptosdk_keyring *BuildDiscovery(
        const Aws::Set<Aws::String> &regions,
        std::shared_ptr<KmsKeyring::DiscoveryFilter> discovery_filter = nullptr) const;

   private:
    Aws::Vector<Aws::String> grant_tokens;
    std::shared_ptr<KmsKeyring::ClientSupplier> client_supplier;

    /**
     * Builds a strict-mode multi-keyring. `generator_key_id` may be blank to
     * indicate that the multi-keyring should not include a generator keyring.
     */
    aws_cryptosdk_keyring *_Build(
        const Aws::String &generator_key_id, const Aws::Vector<Aws::String> &additional_key_ids = {}) const;
};

/** @} */  // doxygen group kms_mrk_keyring

}  // namespace KmsMrkAwareSymmetricKeyring
}  // namespace Cryptosdk
}  // namespace Aws

#endif  // AWS_ENCRYPTION_SDK_KMS_KEYRING_H
