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
#include <aws/cryptosdk/kms_c_master_key.h>

#include <stddef.h>
#include <stdlib.h>
#include <aws/common/byte_buf.h>
#include <aws/core/utils/Outcome.h>
#include <aws/core/utils/logging/LogMacros.h>
#include <aws/core/utils/memory/stl/AWSAllocator.h>
#include <aws/core/utils/memory/MemorySystemInterface.h>
#include <aws/kms/KMSClient.h>
#include <aws/cryptosdk/cipher.h>
#include <aws/cryptosdk/error.h>
#include <aws/cryptosdk/materials.h>
#include <aws/cryptosdk/private/cpputils.h>
#include <aws/cryptosdk/private/kms_shim.h>

namespace Aws {
namespace Cryptosdk {

using Private::aws_utils_byte_buffer_from_c_aws_byte_buf;
using Private::aws_byte_buf_dup_from_aws_utils;
using Private::aws_map_from_c_aws_hash_table;
using Private::append_key_to_edks;
using Private::KmsShim;

static const char *AWS_CRYPTO_SDK_KMS_CLASS_TAG = "KmsCMasterKey";
static const char *KEY_PROVIDER_STR = "aws-kms";

void KmsCMasterKey::DestroyAwsCryptoMk(struct aws_cryptosdk_keyring *mk) {
    struct aws_cryptosdk_kms_mk *kms_mk = static_cast<aws_cryptosdk_kms_mk *>(mk);
    kms_mk->vtable = NULL;
    kms_mk->alloc = NULL;
    kms_mk->mk_data = NULL;
}

int KmsCMasterKey::EncryptDataKey(struct aws_cryptosdk_keyring *mk,
                                  struct aws_cryptosdk_encryption_materials *enc_mat) {
    struct aws_cryptosdk_kms_mk *kms_mk = static_cast<aws_cryptosdk_kms_mk *>(mk);
    if (!kms_mk || !kms_mk->mk_data || !kms_mk->alloc || !enc_mat || !enc_mat->unencrypted_data_key.buffer) {
        AWS_LOGSTREAM_ERROR(AWS_CRYPTO_SDK_KMS_CLASS_TAG, "KMS encrypt validation failed");
        aws_raise_error(AWS_CRYPTOSDK_ERR_KMS_FAILURE);
        abort();
    }

    auto self = kms_mk->mk_data;

    Aws::KMS::Model::EncryptOutcome outcome =
        self->kms_shim->Encrypt(aws_utils_byte_buffer_from_c_aws_byte_buf(&enc_mat->unencrypted_data_key),
                                aws_map_from_c_aws_hash_table(enc_mat->enc_context));
    if (!outcome.IsSuccess()) {
        AWS_LOGSTREAM_ERROR(AWS_CRYPTO_SDK_KMS_CLASS_TAG,
                            "KMS encryption error : " << outcome.GetError().GetExceptionName() << " Message: "
                                                      << outcome.GetError().GetMessage());
        return aws_raise_error(AWS_CRYPTOSDK_ERR_KMS_FAILURE);
    }

    return append_key_to_edks(
        kms_mk->alloc, &enc_mat->encrypted_data_keys, &outcome.GetResult().GetCiphertextBlob(),
        &outcome.GetResult().GetKeyId(),
        &self->key_provider);
}

int KmsCMasterKey::DecryptDataKey(struct aws_cryptosdk_keyring *mk,
                                  struct aws_cryptosdk_decryption_materials *dec_mat,
                                  const aws_cryptosdk_decryption_request *request) {
    struct aws_cryptosdk_kms_mk *kms_mk = static_cast<aws_cryptosdk_kms_mk *>(mk);
    if (!kms_mk || !kms_mk->mk_data || !kms_mk->alloc || !dec_mat || !request) {
        AWS_LOGSTREAM_ERROR(AWS_CRYPTO_SDK_KMS_CLASS_TAG, "KMS decrypt validation failed");
        aws_raise_error(AWS_CRYPTOSDK_ERR_KMS_FAILURE);
        abort();
    }

    auto self = kms_mk->mk_data;
    dec_mat->unencrypted_data_key = {0};

    Aws::StringStream error_buf;
    size_t num_elems = aws_array_list_length(&request->encrypted_data_keys);

    for (unsigned int idx = 0; idx < num_elems; idx++) {
        struct aws_cryptosdk_edk *edk;
        int rv = aws_array_list_get_at_ptr(&request->encrypted_data_keys, (void **) &edk, idx);
        if (rv != AWS_OP_SUCCESS) {
            continue;
        }

        if (!aws_byte_buf_eq(&edk->provider_id, &self->key_provider)) {
            error_buf << "Error: Provider of current key is not " << KEY_PROVIDER_STR << " ";
            continue;
        }

        Aws::KMS::Model::DecryptOutcome outcome =
            self->kms_shim->Decrypt(aws_utils_byte_buffer_from_c_aws_byte_buf(&edk->enc_data_key),
                                    aws_map_from_c_aws_hash_table(request->enc_context));
        if (!outcome.IsSuccess()) {
            error_buf << "Error: " << outcome.GetError().GetExceptionName() << " Message:"
                      << outcome.GetError().GetMessage() << " ";
            continue;
        }

        const Aws::String &outcome_key_id = outcome.GetResult().GetKeyId();
        aws_byte_buf
            outcome_key_id_bb = aws_byte_buf_from_array((u_char *) outcome_key_id.data(), outcome_key_id.size());
        if (aws_byte_buf_eq(&outcome_key_id_bb, &edk->provider_info)) {
            return aws_byte_buf_dup_from_aws_utils(kms_mk->alloc,
                                                   &dec_mat->unencrypted_data_key,
                                                   outcome.GetResult().GetPlaintext());
        }
    }

    AWS_LOGSTREAM_ERROR(AWS_CRYPTO_SDK_KMS_CLASS_TAG,
                        "Could not find any data key that can be decrypted by KMS. Errors:" << error_buf.str());
    // According to aws_cryptosdk_keyring_decrypt_data_key doc we should return success when no key was found
    return AWS_OP_SUCCESS;
}

int KmsCMasterKey::GenerateDataKey(struct aws_cryptosdk_keyring *mk,
                                   struct aws_cryptosdk_encryption_materials *enc_mat) {
    struct aws_cryptosdk_kms_mk *kms_mk = static_cast<aws_cryptosdk_kms_mk *>(mk);
    if (!kms_mk || !kms_mk->mk_data || !kms_mk->alloc || !enc_mat) {
        AWS_LOGSTREAM_ERROR(AWS_CRYPTO_SDK_KMS_CLASS_TAG, "KMS generate data key validation failed");
        aws_raise_error(AWS_CRYPTOSDK_ERR_KMS_FAILURE);
        abort();
    }

    auto self = kms_mk->mk_data;
    enc_mat->unencrypted_data_key = {0};

    const struct aws_cryptosdk_alg_properties *alg_prop = aws_cryptosdk_alg_props(enc_mat->alg);
    if (alg_prop == NULL) {
        AWS_LOGSTREAM_ERROR(AWS_CRYPTO_SDK_KMS_CLASS_TAG, "Invalid encryption materials algorithm properties");
        return aws_raise_error(AWS_CRYPTOSDK_ERR_CRYPTO_UNKNOWN);
    }

    Aws::KMS::Model::GenerateDataKeyOutcome outcome =
        self->kms_shim->GenerateDataKey(alg_prop->data_key_len, aws_map_from_c_aws_hash_table(enc_mat->enc_context));
    if (!outcome.IsSuccess()) {
        AWS_LOGSTREAM_ERROR(AWS_CRYPTO_SDK_KMS_CLASS_TAG, "Invalid encryption materials algorithm properties");
        return aws_raise_error(AWS_CRYPTOSDK_ERR_KMS_FAILURE);
    }

    int rv = aws_byte_buf_dup_from_aws_utils(kms_mk->alloc,
                                             &enc_mat->unencrypted_data_key,
                                             outcome.GetResult().GetPlaintext());
    if (rv != AWS_OP_SUCCESS) {
        return rv;
    }

    rv = append_key_to_edks(kms_mk->alloc,
                            &enc_mat->encrypted_data_keys,
                            &outcome.GetResult().GetCiphertextBlob(),
                            &outcome.GetResult().GetKeyId(),
                            &self->key_provider);
    if (rv != AWS_OP_SUCCESS) {
        aws_byte_buf_clean_up(&enc_mat->unencrypted_data_key);
        return rv;
    }

    return AWS_OP_SUCCESS;
}

aws_cryptosdk_keyring_vt KmsCMasterKey::CreateAwsCryptosdkMk() const {
    struct aws_cryptosdk_keyring_vt kms_mk_vt;
    aws_secure_zero(&kms_mk_vt, sizeof(struct aws_cryptosdk_keyring_vt));

    kms_mk_vt.vt_size = sizeof(struct aws_cryptosdk_keyring_vt);
    kms_mk_vt.name = KEY_PROVIDER_STR;
    kms_mk_vt.destroy = &KmsCMasterKey::DestroyAwsCryptoMk;
    kms_mk_vt.generate_data_key = &KmsCMasterKey::GenerateDataKey;
    kms_mk_vt.encrypt_data_key = &KmsCMasterKey::EncryptDataKey;
    kms_mk_vt.decrypt_data_key = &KmsCMasterKey::DecryptDataKey;
    return kms_mk_vt;
}

void KmsCMasterKey::InitAwsCryptosdkMk(struct aws_allocator *allocator) {
    static const aws_cryptosdk_keyring_vt kms_mk_vt = CreateAwsCryptosdkMk();
    vtable = &kms_mk_vt;
    alloc = allocator;
    mk_data = this;
}

Aws::Cryptosdk::KmsCMasterKey::KmsCMasterKey(std::shared_ptr<Aws::KMS::KMSClient> kms_client,
                                             const String &key_id,
                                             struct aws_allocator *alloc) :
        kms_shim(Aws::MakeShared<KmsShim>(AWS_CRYPTO_SDK_KMS_CLASS_TAG, std::move(kms_client), key_id)),
        key_provider(aws_byte_buf_from_c_str(KEY_PROVIDER_STR)) {
    InitAwsCryptosdkMk(alloc);
}

Aws::Cryptosdk::KmsCMasterKey::KmsCMasterKey(std::shared_ptr<KmsShim> &kms, struct aws_allocator *alloc) :
        kms_shim(kms), key_provider(aws_byte_buf_from_c_str(KEY_PROVIDER_STR)) {
    InitAwsCryptosdkMk(alloc);
}

Aws::Cryptosdk::KmsCMasterKey::~KmsCMasterKey() {
    DestroyAwsCryptoMk(this);
}

}  // namespace Cryptosdk
}  // namespace Aws
