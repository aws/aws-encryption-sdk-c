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
#ifndef AWS_ENCRYPTION_SDK_PRIVATE_KMS_MRK_KEYRING_H
#define AWS_ENCRYPTION_SDK_PRIVATE_KMS_MRK_KEYRING_H

#include <assert.h>
#include <aws/cryptosdk/cpp/kms_mrk_keyring.h>

namespace Aws {
namespace Cryptosdk {
namespace Private {

//= compliance/framework/aws-kms/aws-kms-mrk-aware-symmetric-keyring.txt#2.5
//# MUST implement the AWS Encryption SDK Keyring interface (../keyring-
//# interface.md#interface)
//
//= compliance/framework/aws-kms/aws-kms-mrk-aware-symmetric-region-discovery-keyring.txt#2.5
//# MUST implement that AWS Encryption SDK Keyring interface (../keyring-
//# interface.md#interface)
class AWS_CRYPTOSDK_CPP_API KmsMrkAwareSymmetricKeyringImpl : public aws_cryptosdk_keyring {
    /* This entire class is a private implementation anyway, as users only handle
     * pointers to instances as (struct aws_cryptosdk_keyring *) types.
     * So there is not a strict need to make internal methods and variables private
     * or protected. Furthermore, the keyring virtual functions and unit tests must have
     * access to the internals of this class. The simplest way to do this is just to
     * make everything in the class public visibility.
     */
   public:
    ~KmsMrkAwareSymmetricKeyringImpl();
    // non-copyable
    KmsMrkAwareSymmetricKeyringImpl(const KmsMrkAwareSymmetricKeyringImpl &) = delete;
    KmsMrkAwareSymmetricKeyringImpl &operator=(const KmsMrkAwareSymmetricKeyringImpl &) = delete;

    /**
     * Constructor of KmsMrkAwareSymmetricKeyring for internal use only. Use
     * KmsMrkAwareSymmetricKeyring::Builder to make a new
     * KmsMrkAwareSymmetricKeyring.
     *
     * @param key_id KMS customer master key (CMK)
     * @param grant_tokens A list of grant tokens.
     * @param supplier Object that supplies the KMSClient instances to use for each region.
     */
    KmsMrkAwareSymmetricKeyringImpl(
        const Aws::String &key_id,
        const Aws::Vector<Aws::String> &grant_tokens,
        std::shared_ptr<KmsKeyring::ClientSupplier> supplier);

    /**
     * Constructor of KmsMrkAwareSymmetricKeyring for internal use only. Use
     * KmsMrkAwareSymmetricKeyring::Builder to make a new
     * KmsMrkAwareSymmetricKeyring.
     *
     * @param key_id KMS customer master key (CMK)
     * @param grant_tokens A list of grant tokens.
     * @param supplier Object that supplies the KMSClient instances to use for each region.
     * @param region The region in which to make all calls
     * @param discovery_filter DiscoveryFilter specifying authorized partition
     *        and account IDs. The stored pointer must not be nullptr.
     */
    KmsMrkAwareSymmetricKeyringImpl(
        const Aws::String &key_id,
        const Aws::Vector<Aws::String> &grant_tokens,
        const Aws::String &region,
        std::shared_ptr<KmsKeyring::ClientSupplier> supplier,
        std::shared_ptr<KmsKeyring::DiscoveryFilter> discovery_filter)
        : KmsMrkAwareSymmetricKeyringImpl(key_id, grant_tokens, supplier) {
        if (bool(discovery_filter)) {
            this->discovery_filter = discovery_filter;
        }
        this->region = region;
    }

    /**
     * Returns the KMS Client for a specific key ID
     */
    std::shared_ptr<KMS::KMSClient> GetKmsClient(const Aws::String &key_id) const;

    const aws_byte_buf key_provider;
    std::shared_ptr<KmsKeyring::ClientSupplier> kms_client_supplier;

    Aws::Vector<Aws::String> grant_tokens;
    Aws::String key_id;
    Aws::String region;

    /**
     * This is nullptr if and only if no DiscoveryFilter is configured during
     * construction.
     */
    std::shared_ptr<KmsKeyring::DiscoveryFilter> discovery_filter;
};

}  // namespace Private
}  // namespace Cryptosdk
}  // namespace Aws

#endif  // AWS_ENCRYPTION_SDK_PRIVATE_KMS_MRK_KEYRING_H
