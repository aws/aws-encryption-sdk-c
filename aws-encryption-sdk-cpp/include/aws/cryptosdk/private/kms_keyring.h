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

#include <aws/cryptosdk/cpp/kms_keyring.h>

namespace Aws {
namespace Cryptosdk {
namespace Private {

class AWS_CRYPTOSDK_CPP_API KmsKeyringImpl : public aws_cryptosdk_keyring {
    /* This entire class is a private implementation anyway, as users only handle
     * pointers to instances as (struct aws_cryptosdk_keyring *) types.
     * So there is not a strict need to make internal methods and variables private
     * or protected. Furthermore, the keyring virtual functions and unit tests must have
     * access to the internals of this class. The simplest way to do this is just to
     * make everything in the class public visibility.
     */
   public:
    ~KmsKeyringImpl();
    // non-copyable
    KmsKeyringImpl(const KmsKeyringImpl &) = delete;
    KmsKeyringImpl &operator=(const KmsKeyringImpl &) = delete;

    /**
     * Constructor of KmsKeyring for internal use only. Use KmsKeyring::Builder to make a new KmsKeyring.
     *
     * @param key_ids List of KMS customer master keys (CMK)
     * @param grant_tokens A list of grant tokens.
     * @param supplier Object that supplies the KMSClient instances to use for each region.
     */
    KmsKeyringImpl(
        const Aws::Vector<Aws::String> &key_ids,
        const Aws::Vector<Aws::String> &grant_tokens,
        std::shared_ptr<Aws::Cryptosdk::KmsKeyring::ClientSupplier> supplier);

    /**
     * Returns the KMS Client for a specific key ID
     */
    std::shared_ptr<KMS::KMSClient> GetKmsClient(const Aws::String &key_id) const;

    const aws_byte_buf key_provider;
    std::shared_ptr<Aws::Cryptosdk::KmsKeyring::ClientSupplier> kms_client_supplier;

    Aws::Vector<Aws::String> grant_tokens;
    Aws::Vector<Aws::String> key_ids;
};

}  // namespace Private
}  // namespace Cryptosdk
}  // namespace Aws

#endif  // AWS_ENCRYPTION_SDK_PRIVATE_KMS_KEYRING_H
