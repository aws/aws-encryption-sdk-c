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
#ifndef AWS_ENCRYPTION_SDK_KMS_C_MASTER_KEY_H
#define AWS_ENCRYPTION_SDK_KMS_C_MASTER_KEY_H

#include <aws/common/common.h>
#include <aws/core/utils/memory/AWSMemory.h>
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

// forward declaration of KmsShim
namespace Private {
class KmsShim;
}  // end namespace Private

/**
 * Class that allows C AWS Enc SDK to use C++ KMS Master Key
 */
class KmsCMasterKey : public aws_cryptosdk_keyring {
  public:
    /**
     * Initializes KmsCMasterKey to use Aws::KMS::KMSClient with a key_id
     * @param kms_client KMS client object
     * @param key_id A unique identifier for the customer master key (CMK).
     *               To specify a CMK, use its key ID, Amazon Resource Name (ARN), alias name, or alias ARN.
     *               This should be specified in the same structure as the one required by KMS client
     * @param alloc Allocator structure. An instance of this will be passed around for anything needing memory
     *              allocation
     */
    KmsCMasterKey(std::shared_ptr<KMS::KMSClient> kms_client,
                  const String &key_id,
                  struct aws_allocator *alloc);
    ~KmsCMasterKey();

    // non-copyable
    KmsCMasterKey(const KmsCMasterKey &) = delete;
    KmsCMasterKey &operator=(const KmsCMasterKey &) = delete;

  protected:
    /**
     * Constructor that is used for testing purposes. Do not use it.
     */
    KmsCMasterKey(std::shared_ptr<Private::KmsShim> &kms, struct aws_allocator *alloc);

    /**
     * It attempts to find one of the EDKs to decrypt
     * This function will be automatically called when a Master Key needs to be decrypted
     * @param mk Pointer to an aws_cryptosdk_keyring object
     * @param dec_mat Decryption Materials
     * @param request A structure that contains a list of EDKS and an encryption context.
     * @return On success AWS_OP_SUCCESS will be returned. This does not necessarily mean that the data key will be
     *         decrypted, as it is normal behavior that a particular MK/MKP may not find an EDK that it can decrypt.
     *         To determine whether the data key was decrypted, check dec_mat->unencrypted_data_key.buffer. If the
     *         data key was not decrypted, that pointer will be set to NULL. If the data key was decrypted, that pointer
     *         will point to the raw bytes of the key.
     *         On internal failure, AWS_OP_ERR will be returned and an internal error code will be set.
     */
    static int DecryptDataKey(struct aws_cryptosdk_keyring *mk,
                              struct aws_cryptosdk_decryption_materials *dec_mat,
                              const aws_cryptosdk_decryption_request *request);

    /**
     * The MK attempts to encrypt the data key.
     * This function will be automatically called when a Master Key needs to be encrypted
     * @param mk Pointer to an aws_cryptosdk_keyring object
     * @param enc_mat Encryption materials
     * @return  On success AWS_OP_SUCCESS is returned, the new EDK will be appended onto the list of EDKs.
     *          On failure AWS_OP_ERR is returned, an internal AWS error code is set, and no memory is allocated.
     */
    static int EncryptDataKey(aws_cryptosdk_keyring *mk,
                              struct aws_cryptosdk_encryption_materials *enc_mat);

    /**
     * The MK attempts to generate a new data key, and returns it in both unencrypted and encrypted form.
     * This function will be automatically called when a Master Key needs to generate a new pair of encrypted,
     * unencrypted data keys
     * @param mk Pointer to an aws_cryptosdk_keyring object
     * @param enc_mat
     * @return On success (1) AWS_OP_SUCCESS is returned, (2) the unencrypted data key buffer will contain the raw
     *         bytes of the data key, and (3) an EDK will be appended onto the list of EDKs.
     *         On failure AWS_OP_ERR is returned, an internal AWS error code is set, and no memory is allocated.
     */
    static int GenerateDataKey(struct aws_cryptosdk_keyring *mk,
                               struct aws_cryptosdk_encryption_materials *enc_mat);

    /**
     * Destroys all allocated structures, except self.
     * You will need to delete this class
     * @param mk Pointer to an aws_cryptosdk_keyring object
     */
    static void DestroyAwsCryptoMk(aws_cryptosdk_keyring *mk);

  private:
    void InitAwsCryptosdkMk(struct aws_allocator *allocator);

    struct aws_cryptosdk_keyring_vt kms_mk_vt;
    std::shared_ptr<Private::KmsShim> kms_shim;
    const aws_byte_buf key_provider;
};

}  // namespace Cryptosdk
}  // namespace Aws

#endif // AWS_ENCRYPTION_SDK_KMS_C_MASTER_KEY_H
