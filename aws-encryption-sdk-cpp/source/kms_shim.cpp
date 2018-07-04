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
#include <aws/cryptosdk/private/kms_shim.h>

#include <aws/core/utils/Array.h>

namespace Aws {
namespace Cryptosdk {
namespace Private {

KmsShim::KmsShim(std::shared_ptr<KMS::KMSClient> kms_client, const String &key_id)
    : kms_client(kms_client), key_id(key_id) {
}

Aws::KMS::Model::EncryptOutcome KmsShim::Encrypt(const Utils::ByteBuffer &plaintext,
                                                 const Aws::Map<Aws::String, Aws::String> &encryption_context) {
    KMS::Model::EncryptRequest encryption_request;
    encryption_request.SetKeyId(key_id);
    encryption_request.SetPlaintext(plaintext);

    encryption_request.SetEncryptionContext(encryption_context);
    encryption_request.SetGrantTokens(grant_tokens);

    return kms_client->Encrypt(encryption_request);
}

Aws::KMS::Model::DecryptOutcome KmsShim::Decrypt(const Utils::ByteBuffer &ciphertext,
                                                 const Aws::Map<Aws::String, Aws::String> &encryption_context) {
    KMS::Model::DecryptRequest request;
    request.SetCiphertextBlob(ciphertext);

    request.SetEncryptionContext(encryption_context);
    request.SetGrantTokens(grant_tokens);

    return kms_client->Decrypt(request);
}

Aws::KMS::Model::GenerateDataKeyOutcome KmsShim::GenerateDataKey(int number_of_bytes,
                                                                 const Aws::Map<Aws::String,
                                                                                Aws::String> &encryption_context) {
    KMS::Model::GenerateDataKeyRequest request;
    request.SetKeyId(key_id);
    request.SetNumberOfBytes(number_of_bytes);

    request.SetGrantTokens(grant_tokens);
    request.SetEncryptionContext(encryption_context);

    return kms_client->GenerateDataKey(request);
}

}  // namespace Private
}  // namespace Cryptosdk
}  // namespace Aws
