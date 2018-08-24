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
    auto kms_region = self->GetClientRegion(self->default_key_arn);
    auto kms_client = self->GetKmsClient(kms_region);
    auto kms_client_request = self->CreateEncryptRequest(
        self->default_key_arn,
        self->grant_tokens,
        aws_utils_byte_buffer_from_c_aws_byte_buf(&enc_mat->unencrypted_data_key),
        aws_map_from_c_aws_hash_table(enc_mat->enc_context));

    Aws::KMS::Model::EncryptOutcome outcome = kms_client->Encrypt(kms_client_request);
    if (!outcome.IsSuccess()) {
        AWS_LOGSTREAM_ERROR(AWS_CRYPTO_SDK_KMS_CLASS_TAG,
                            "KMS encryption error : " << outcome.GetError().GetExceptionName() << " Message: "
                                                      << outcome.GetError().GetMessage());
        return aws_raise_error(AWS_CRYPTOSDK_ERR_KMS_FAILURE);
    }
    self->SaveKmsClientInCache(kms_region, kms_client);
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

        const Aws::String key_arn = Private::aws_string_from_c_aws_byte_buf(&edk->provider_info);
        auto kms_region = self->GetClientRegion(key_arn);
        if (kms_region == "") {
            error_buf << "Error: Key not configured";
            continue;
        }
        auto kms_client = self->GetKmsClient(kms_region);
        auto kms_request = self->CreateDecryptRequest(key_arn,
                                                      self->grant_tokens,
                                                      aws_utils_byte_buffer_from_c_aws_byte_buf(&edk->enc_data_key),
                                                      aws_map_from_c_aws_hash_table(request->enc_context));

        Aws::KMS::Model::DecryptOutcome outcome = kms_client->Decrypt(kms_request);
        if (!outcome.IsSuccess()) {
            error_buf << "Error: " << outcome.GetError().GetExceptionName() << " Message:"
                      << outcome.GetError().GetMessage() << " ";
            continue;
        }

        const Aws::String &outcome_key_id = outcome.GetResult().GetKeyId();
        if (outcome_key_id == key_arn) {
            self->SaveKmsClientInCache(kms_region, kms_client);
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

    auto kms_region = self->GetClientRegion(self->default_key_arn);
    auto kms_client = self->GetKmsClient(kms_region);
    auto kms_request = self->CreateGenerateDataKeyRequest(self->default_key_arn,
                                                          self->grant_tokens,
                                                          alg_prop->data_key_len,
                                                          aws_map_from_c_aws_hash_table(enc_mat->enc_context));

    Aws::KMS::Model::GenerateDataKeyOutcome outcome = kms_client->GenerateDataKey(kms_request);
    if (!outcome.IsSuccess()) {
        AWS_LOGSTREAM_ERROR(AWS_CRYPTO_SDK_KMS_CLASS_TAG, "Invalid encryption materials algorithm properties");
        return aws_raise_error(AWS_CRYPTOSDK_ERR_KMS_FAILURE);
    }
    self->SaveKmsClientInCache(kms_region, kms_client);

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

Aws::Cryptosdk::KmsCMasterKey::KmsCMasterKey(struct aws_allocator *alloc,
                                             std::shared_ptr<Aws::KMS::KMSClient> kms_client,
                                             const String &key_id) :
    key_provider(aws_byte_buf_from_c_str(KEY_PROVIDER_STR)),
    client_supplier(std::make_shared<SingleClientSupplier>(kms_client)),
    default_region("default_region") {
    Aws::List<Aws::String> keyIds;
    keyIds.push_back(key_id);
    Init(alloc, keyIds);
}

Aws::Cryptosdk::KmsCMasterKey::~KmsCMasterKey() {
    DestroyAwsCryptoMk(this);
}

Aws::Cryptosdk::KmsCMasterKey::KmsCMasterKey(struct aws_allocator *alloc,
                                             Aws::List<Aws::String> keyIds,
                                             Aws::List<String> grantTokens,
                                             Aws::String defaultRegion,
                                             std::shared_ptr<RegionalClientSupplier> regional_client_supplier)
    : key_provider(aws_byte_buf_from_c_str(KEY_PROVIDER_STR)),
      client_supplier(regional_client_supplier),
      default_region(defaultRegion) {
    Init(alloc, keyIds);
}

Aws::Cryptosdk::KmsCMasterKey::KmsCMasterKey(struct aws_allocator *alloc,
                                             Aws::String keyId) :
    KmsCMasterKey(alloc, Aws::List<Aws::String>{keyId}) {

}

Aws::KMS::Model::EncryptRequest KmsCMasterKey::CreateEncryptRequest(const Aws::String &key_id,
                                                                    const Aws::Vector<Aws::String> &grant_tokens,
                                                                    const Utils::ByteBuffer &plaintext,
                                                                    const Aws::Map<Aws::String,
                                                                                   Aws::String> &encryption_context) {
    KMS::Model::EncryptRequest encryption_request;
    encryption_request.SetKeyId(key_id);
    encryption_request.SetPlaintext(plaintext);

    encryption_request.SetEncryptionContext(encryption_context);
    encryption_request.SetGrantTokens(grant_tokens);

    return encryption_request;
}

Aws::KMS::Model::DecryptRequest KmsCMasterKey::CreateDecryptRequest(const Aws::String &key_id,
                                                                    const Aws::Vector<Aws::String> &grant_tokens,
                                                                    const Utils::ByteBuffer &ciphertext,
                                                                    const Aws::Map<Aws::String,
                                                                                   Aws::String> &encryption_context) {
    KMS::Model::DecryptRequest request;
    request.SetCiphertextBlob(ciphertext);

    request.SetEncryptionContext(encryption_context);
    request.SetGrantTokens(grant_tokens);

    return request;
}

Aws::KMS::Model::GenerateDataKeyRequest KmsCMasterKey::CreateGenerateDataKeyRequest(
    const Aws::String &key_id,
    const Aws::Vector<Aws::String> &grant_tokens,
    int number_of_bytes,
    const Aws::Map<Aws::String, Aws::String> &encryption_context) {

    KMS::Model::GenerateDataKeyRequest request;
    request.SetKeyId(key_id);
    request.SetNumberOfBytes(number_of_bytes);

    request.SetGrantTokens(grant_tokens);
    request.SetEncryptionContext(encryption_context);

    return request;
}

Aws::Map<Aws::String, Aws::String> KmsCMasterKey::BuildKeyIDs(Aws::List<Aws::String> in_key_ids) {
    Aws::Map<Aws::String, Aws::String> rv;
    for (auto key_id : in_key_ids) {
        String region = Private::parse_region_from_kms_key_arn(key_id);
        if (region == "") {
            rv[key_id] = default_region;
        } else {
            rv[key_id] = region;
        }
    }
    return rv;
}

void KmsCMasterKey::Init(struct aws_allocator *alloc, Aws::List<Aws::String> &in_key_ids) {
    InitAwsCryptosdkMk(alloc);
    default_key_arn = in_key_ids.front();
    key_ids = BuildKeyIDs(in_key_ids);
}

Aws::String KmsCMasterKey::GetClientRegion(const Aws::String &key_id) {
    if (key_ids.find(key_id) == key_ids.end()) {
        return "";
    }
    return key_ids[key_id];
}

std::shared_ptr<KMS::KMSClient> KmsCMasterKey::GetKmsClient(const Aws::String &region) {
    if (cached_clients.find(region) != cached_clients.end()) {
        return cached_clients[region];
    }

    return client_supplier->getClient(region);
}

void KmsCMasterKey::SaveKmsClientInCache(const Aws::String &region, std::shared_ptr<KMS::KMSClient> &kms_client) {
    if (cached_clients.find(region) != cached_clients.end()) {
        cached_clients[region] = kms_client;
    }
}

std::shared_ptr<KMS::KMSClient> KmsCMasterKey::DefaultRegionalClientSupplier::getClient(const String &region_name) {
    Aws::Client::ClientConfiguration client_configuration;
    client_configuration.region = region_name;
    return Aws::MakeShared<Aws::KMS::KMSClient>("AWS_CRYPTOSDK_REGIONAL_CLIENT_SUPPLIER", client_configuration);
}

std::shared_ptr<KMS::KMSClient> KmsCMasterKey::SingleClientSupplier::getClient(const String &region_name) {
    return kms_client;
}

KmsCMasterKey::SingleClientSupplier::SingleClientSupplier(const std::shared_ptr<KMS::KMSClient> &kms_client)
    : kms_client(kms_client) {

}


}  // namespace Cryptosdk
}  // namespace Aws
