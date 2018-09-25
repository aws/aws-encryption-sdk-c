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
#include <aws/cryptosdk/kms_keyring.h>

#include <stddef.h>
#include <stdlib.h>
#include <aws/common/byte_buf.h>
#include <aws/core/utils/Outcome.h>
#include <aws/core/utils/logging/LogMacros.h>
#include <aws/core/utils/memory/stl/AWSAllocator.h>
#include <aws/core/utils/memory/MemorySystemInterface.h>
#include <aws/kms/KMSClient.h>
#include <aws/kms/model/EncryptResult.h>
#include <aws/kms/model/DecryptResult.h>
#include <aws/kms/model/GenerateDataKeyResult.h>
#include <aws/cryptosdk/cipher.h>
#include <aws/cryptosdk/error.h>
#include <aws/cryptosdk/materials.h>
#include <aws/cryptosdk/private/cpputils.h>
#include <aws/cryptosdk/private/materials.h>

namespace Aws {
namespace Cryptosdk {

using Private::aws_utils_byte_buffer_from_c_aws_byte_buf;
using Private::aws_byte_buf_dup_from_aws_utils;
using Private::aws_map_from_c_aws_hash_table;
using Private::append_key_dup_to_edks;

static const char *AWS_CRYPTO_SDK_KMS_CLASS_TAG = "KmsKeyring";
static const char *KEY_PROVIDER_STR = "aws-kms";

void KmsKeyring::DestroyAwsCryptoKeyring(struct aws_cryptosdk_keyring *keyring) {
    struct aws_cryptosdk_kms_keyring *kms_keyring = static_cast<aws_cryptosdk_kms_keyring *>(keyring);
    if (kms_keyring->keyring_data != NULL){
        Aws::Delete(kms_keyring->keyring_data);
        kms_keyring->keyring_data = NULL;
    }
}

int KmsKeyring::EncryptDataKey(struct aws_cryptosdk_keyring *keyring,
                               struct aws_cryptosdk_encryption_materials *enc_mat) {
    // Class that prevents memory leak of aws_list (even if a function throws)
    // When the object will be destroyed it will call aws_cryptosdk_edk_list_clean_up
    class EdksRaii {
      public:
        ~EdksRaii() {
            if (initialized) {
                aws_cryptosdk_edk_list_clean_up(&aws_list);
                initialized = false;
            }
        }
        int Create(struct aws_allocator *alloc, size_t initial_item_allocation) {
            auto rv = aws_array_list_init_dynamic(&aws_list,
                                                  alloc,
                                                  initial_item_allocation,
                                                  sizeof(struct aws_cryptosdk_edk));
            initialized = (rv == AWS_OP_SUCCESS)?true:false;
            return rv;
        }
        bool initialized = false;
        struct aws_array_list aws_list;
    };

    struct aws_cryptosdk_kms_keyring *kms_keyring = static_cast<aws_cryptosdk_kms_keyring *>(keyring);
    if (!kms_keyring || !kms_keyring->keyring_data || !kms_keyring->alloc || !enc_mat
        || !enc_mat->unencrypted_data_key.buffer) {
        abort();
    }
    auto self = kms_keyring->keyring_data;

    EdksRaii edks;
    auto rv = edks.Create(enc_mat->alloc, self->key_ids.size());
    if (rv != AWS_OP_SUCCESS) {
        return AWS_OP_ERR;
    }

    for (auto key : self->key_ids) {
        auto kms_region = self->GetRegionForConfiguredKmsKeys(key.second);
        auto kms_client = self->GetKmsClient(kms_region);
        auto kms_client_request = self->CreateEncryptRequest(
            key.first,
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
        self->kms_client_cache->SaveInCache(kms_region, kms_client);
        auto rv = append_key_dup_to_edks(
            kms_keyring->alloc,
            &edks.aws_list,
            &outcome.GetResult().GetCiphertextBlob(),
            &outcome.GetResult().GetKeyId(),
            &self->key_provider);
        if (rv != AWS_OP_SUCCESS) {
            return AWS_OP_ERR;
        }
    }

    return aws_cryptosdk_transfer_edk_list(&enc_mat->encrypted_data_keys, &edks.aws_list);
}

int KmsKeyring::DecryptDataKey(struct aws_cryptosdk_keyring *keyring,
                               struct aws_cryptosdk_decryption_materials *dec_mat,
                               const aws_cryptosdk_decryption_request *request) {
    struct aws_cryptosdk_kms_keyring *kms_keyring = static_cast<aws_cryptosdk_kms_keyring *>(keyring);
    if (!kms_keyring || !kms_keyring->keyring_data || !kms_keyring->alloc || !dec_mat || !request) {
        abort();
    }

    auto self = kms_keyring->keyring_data;
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
        auto kms_region = self->GetRegionForConfiguredKmsKeys(key_arn);
        // If kms_region is empty this means that key_arn was never configured in KmsKeyring.
        // Key saved in provider_info must match the key that has been configured in the KmsKeyring. At this point is
        // not supported to use another key (like an alias)
        if (kms_region == "") {
            error_buf << "Error: KeyId for encrypted data_key is not configured in KmsKeyring";
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
            self->kms_client_cache->SaveInCache(kms_region, kms_client);
            return aws_byte_buf_dup_from_aws_utils(kms_keyring->alloc,
                                                   &dec_mat->unencrypted_data_key,
                                                   outcome.GetResult().GetPlaintext());
        }
    }

    AWS_LOGSTREAM_ERROR(AWS_CRYPTO_SDK_KMS_CLASS_TAG,
                        "Could not find any data key that can be decrypted by KMS. Errors:" << error_buf.str());
    // According to aws_cryptosdk_keyring_decrypt_data_key doc we should return success when no key was found
    return AWS_OP_SUCCESS;
}

int KmsKeyring::GenerateDataKey(struct aws_cryptosdk_keyring *keyring,
                                struct aws_cryptosdk_encryption_materials *enc_mat) {
    struct aws_cryptosdk_kms_keyring *kms_keyring = static_cast<aws_cryptosdk_kms_keyring *>(keyring);
    if (!kms_keyring || !kms_keyring->keyring_data || !kms_keyring->alloc || !enc_mat) {
        abort();
    }

    auto self = kms_keyring->keyring_data;
    enc_mat->unencrypted_data_key = {0};

    const struct aws_cryptosdk_alg_properties *alg_prop = aws_cryptosdk_alg_props(enc_mat->alg);
    if (alg_prop == NULL) {
        AWS_LOGSTREAM_ERROR(AWS_CRYPTO_SDK_KMS_CLASS_TAG, "Invalid encryption materials algorithm properties");
        return aws_raise_error(AWS_CRYPTOSDK_ERR_CRYPTO_UNKNOWN);
    }

    auto kms_region = self->GetRegionForConfiguredKmsKeys(self->default_key_id);
    auto kms_client = self->GetKmsClient(kms_region);
    auto kms_request = self->CreateGenerateDataKeyRequest(self->default_key_id,
                                                          self->grant_tokens,
                                                          alg_prop->data_key_len,
                                                          aws_map_from_c_aws_hash_table(enc_mat->enc_context));

    Aws::KMS::Model::GenerateDataKeyOutcome outcome = kms_client->GenerateDataKey(kms_request);
    if (!outcome.IsSuccess()) {
        AWS_LOGSTREAM_ERROR(AWS_CRYPTO_SDK_KMS_CLASS_TAG, "Invalid encryption materials algorithm properties");
        return aws_raise_error(AWS_CRYPTOSDK_ERR_KMS_FAILURE);
    }
    self->kms_client_cache->SaveInCache(kms_region, kms_client);

    int rv = aws_byte_buf_dup_from_aws_utils(kms_keyring->alloc,
                                             &enc_mat->unencrypted_data_key,
                                             outcome.GetResult().GetPlaintext());
    if (rv != AWS_OP_SUCCESS) {
        return rv;
    }

    rv = append_key_dup_to_edks(kms_keyring->alloc,
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

void KmsKeyring::InitAwsCryptosdkKeyring(struct aws_allocator *allocator) {
    static const aws_cryptosdk_keyring_vt kms_keyring_vt = {
        sizeof(struct aws_cryptosdk_keyring_vt),  // size
        KEY_PROVIDER_STR,  // name
        &KmsKeyring::DestroyAwsCryptoKeyring,  // destroy callback
        &KmsKeyring::GenerateDataKey,  // generate_data_key callback
        &KmsKeyring::EncryptDataKey,  // encrypt callback
        &KmsKeyring::DecryptDataKey   // decrypt callback
    };
    vtable = &kms_keyring_vt;
    alloc = allocator;
    keyring_data = this;
}

Aws::Cryptosdk::KmsKeyring::~KmsKeyring() {
}

Aws::Cryptosdk::KmsKeyring::KmsKeyring(struct aws_allocator *alloc,
                                       const Aws::List<Aws::String> &key_ids,
                                       const String &default_region,
                                       const Aws::Vector<Aws::String> &grant_tokens,
                                       std::shared_ptr<RegionalClientSupplier> regional_client_supplier,
                                       std::shared_ptr<KmsClientCache> kms_client_cache)
    : key_provider(aws_byte_buf_from_c_str(KEY_PROVIDER_STR)),
      kms_client_supplier(regional_client_supplier),
      default_region(default_region),
      grant_tokens(grant_tokens),
      kms_client_cache(kms_client_cache) {
    Init(alloc, key_ids);
}

Aws::KMS::Model::EncryptRequest KmsKeyring::CreateEncryptRequest(const Aws::String &key_id,
                                                                 const Aws::Vector<Aws::String> &grant_tokens,
                                                                 const Utils::ByteBuffer &plaintext,
                                                                 const Aws::Map<Aws::String,
                                                                                Aws::String> &encryption_context) const {
    KMS::Model::EncryptRequest encryption_request;
    encryption_request.SetKeyId(key_id);
    encryption_request.SetPlaintext(plaintext);

    encryption_request.SetEncryptionContext(encryption_context);
    encryption_request.SetGrantTokens(grant_tokens);

    return encryption_request;
}

Aws::KMS::Model::DecryptRequest KmsKeyring::CreateDecryptRequest(const Aws::String &key_id,
                                                                 const Aws::Vector<Aws::String> &grant_tokens,
                                                                 const Utils::ByteBuffer &ciphertext,
                                                                 const Aws::Map<Aws::String,
                                                                                Aws::String> &encryption_context) const {
    KMS::Model::DecryptRequest request;
    request.SetCiphertextBlob(ciphertext);

    request.SetEncryptionContext(encryption_context);
    request.SetGrantTokens(grant_tokens);

    return request;
}

Aws::KMS::Model::GenerateDataKeyRequest KmsKeyring::CreateGenerateDataKeyRequest(
    const Aws::String &key_id,
    const Aws::Vector<Aws::String> &grant_tokens,
    int number_of_bytes,
    const Aws::Map<Aws::String, Aws::String> &encryption_context) const {

    KMS::Model::GenerateDataKeyRequest request;
    request.SetKeyId(key_id);
    request.SetNumberOfBytes(number_of_bytes);

    request.SetGrantTokens(grant_tokens);
    request.SetEncryptionContext(encryption_context);

    return request;
}

Aws::Map<Aws::String, Aws::String> KmsKeyring::BuildKeyIds(const Aws::List<Aws::String> &in_key_ids) const {
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

void KmsKeyring::Init(struct aws_allocator *alloc, const Aws::List<Aws::String> &in_key_ids) {
    if (in_key_ids.size() == 0) {
        throw std::invalid_argument("Empty key id list");
    }
    if (in_key_ids.front().size() == 0) {
        throw std::invalid_argument("Invalid default key id");
    }
    if (default_region == "") {
        throw std::invalid_argument("Invalid default region");
    }

    if (!kms_client_cache) {
        kms_client_cache = Aws::MakeShared<KmsClientCache>(AWS_CRYPTO_SDK_KMS_CLASS_TAG);
    }

    InitAwsCryptosdkKeyring(alloc);
    default_key_id = in_key_ids.front();
    this->key_ids = BuildKeyIds(in_key_ids);
}

Aws::String KmsKeyring::GetRegionForConfiguredKmsKeys(const Aws::String &key_id) const {
    if (key_ids.find(key_id) == key_ids.end()) {
        return "";
    }
    return key_ids.at(key_id);
}

std::shared_ptr<KMS::KMSClient> KmsKeyring::GetKmsClient(const Aws::String &region) const {
    auto rv = kms_client_cache->GetCachedClient(region);
    if (rv != NULL) {
        return rv;
    }

    return kms_client_supplier->GetClient(region);
}


std::shared_ptr<KmsKeyring::KmsClientCache> KmsKeyring::GetKmsCachedClients() const {
    return kms_client_cache;
}

std::shared_ptr<KMS::KMSClient> KmsKeyring::DefaultRegionalClientSupplier::GetClient(
    const Aws::String &region_name) const {
    Aws::Client::ClientConfiguration client_configuration;
    client_configuration.region = region_name;
    return Aws::MakeShared<Aws::KMS::KMSClient>("AWS_CRYPTOSDK_REGIONAL_CLIENT_SUPPLIER", client_configuration);
}

std::shared_ptr<KMS::KMSClient> KmsKeyring::SingleClientSupplier::GetClient(const Aws::String &region_name) const {
    return kms_client;
}

KmsKeyring::SingleClientSupplier::SingleClientSupplier(const std::shared_ptr<KMS::KMSClient> &kms_client)
    : kms_client(kms_client) {

}

Aws::String KmsKeyring::Builder::BuildDefaultRegion() const {
    auto built_default_region = default_region;

    // If is a single key configured we try to extract default region from it
    if (built_default_region == "" && key_ids.size() == 1) {
        built_default_region = Private::parse_region_from_kms_key_arn(key_ids.front());
    }

    if (kms_client) {
        // we use a magic key when no region was supplied but kms_client was configured because we will use the
        // region already configured inside the kms_client
        built_default_region = "default_region";
    }

    return built_default_region;
}

std::shared_ptr<KmsKeyring::RegionalClientSupplier> KmsKeyring::Builder::BuildClientSupplier() const {
    auto built_client_supplier = client_supplier;

    if (kms_client) {
        built_client_supplier = Aws::MakeShared<SingleClientSupplier>(AWS_CRYPTO_SDK_KMS_CLASS_TAG, kms_client);
    }

    if (!built_client_supplier) {
        built_client_supplier = Aws::MakeShared<DefaultRegionalClientSupplier>(AWS_CRYPTO_SDK_KMS_CLASS_TAG);
    }

    return built_client_supplier;
}


bool KmsKeyring::Builder::ValidParameters() const {
    if (key_ids.size() == 0) {
        AWS_LOGSTREAM_ERROR(AWS_CRYPTO_SDK_KMS_CLASS_TAG, "No key_id was provided");
        return false;
    }

    for (auto key : key_ids) {
        if (key.size() == 0) {
            AWS_LOGSTREAM_ERROR(AWS_CRYPTO_SDK_KMS_CLASS_TAG, "A key that was provided is empty");
            return false;
        }
    }

    if (BuildDefaultRegion() == "") {
        AWS_LOGSTREAM_ERROR(AWS_CRYPTO_SDK_KMS_CLASS_TAG, "Default region was not provided");
        return false;
    }

    return true;
}

struct aws_allocator *KmsKeyring::Builder::BuildAllocator() const {
    return (alloc == NULL)? aws_default_allocator() : alloc;
}

aws_cryptosdk_keyring *KmsKeyring::Builder::Build() const {
    if (!ValidParameters()) {
        aws_raise_error(AWS_CRYPTOSDK_ERR_KMS_FAILURE);
        return NULL;
    }

    /**
     * Class that allows Aws::New to allocate a new KmsKeyring object despite of the protected constructor.
     * KmsKeyring should be constructed only through builder because during the DestroyAwsCryptoKeyring() phase we have
     * to destroy "self" and we assume that it was allocated using Aws::New and because we are doing some parameter
     * checks in builder rather than constructor (in the constructor we can't throw due to no-throw policy). Any other
     * method of allocating memory should be forbidden.
     * Aws::New accepts to allocate memory only for classes that have public constructors or friend classes. Since we
     * want to allow construction of KmsKeyring only through the builder, a friendship with Aws::New doesn't help
     * because would allow anyone to construct it without the builder. Instead the alternative was to declare a child
     * class with public constructor just for initialization
     */
    struct KmsKeyringWithPublicConstructor : public KmsKeyring {
        KmsKeyringWithPublicConstructor(struct aws_allocator *alloc,
                                        const Aws::List<Aws::String> &key_ids,
                                        const String &default_region,
                                        const Aws::Vector<Aws::String> &grant_tokens,
                                        std::shared_ptr<RegionalClientSupplier> client_supplier,
                                        std::shared_ptr<KmsKeyring::KmsClientCache> kms_client_cache) :
            KmsKeyring(alloc,
                       key_ids,
                       default_region,
                       grant_tokens,
                       client_supplier,
                       kms_client_cache) { /* no-op */ }
    };

    return Aws::New<KmsKeyringWithPublicConstructor>(AWS_CRYPTO_SDK_KMS_CLASS_TAG,
                                                     BuildAllocator(),
                                                     key_ids,
                                                     BuildDefaultRegion(),
                                                     grant_tokens,
                                                     BuildClientSupplier(),
                                                     kms_client_cache);
}

KmsKeyring::Builder &KmsKeyring::Builder::SetAllocator(struct aws_allocator *alloc) {
    this->alloc = alloc;
    return *this;
}

KmsKeyring::Builder &KmsKeyring::Builder::SetDefaultRegion(const String &default_region) {
    this->default_region = default_region;
    return *this;
}

KmsKeyring::Builder &KmsKeyring::Builder::AppendKeyIds(const Aws::List<Aws::String> &key_ids) {
    this->key_ids.insert(this->key_ids.end(), key_ids.begin(), key_ids.end());
    return *this;
}

KmsKeyring::Builder &KmsKeyring::Builder::AppendKeyId(const Aws::String &key_id) {
    this->key_ids.push_back(key_id);
    return *this;
}

KmsKeyring::Builder &KmsKeyring::Builder::SetKeyId(const Aws::String &key_id) {
    this->key_ids = {key_id};
    return *this;
}

KmsKeyring::Builder &KmsKeyring::Builder::SetKeyIds(const Aws::List<Aws::String> &key_ids) {
    this->key_ids = key_ids;
    return *this;
}

KmsKeyring::Builder &KmsKeyring::Builder::SetGrantTokens(const Aws::Vector<Aws::String> &grant_tokens) {
    this->grant_tokens = grant_tokens;
    return *this;
}

KmsKeyring::Builder &KmsKeyring::Builder::SetRegionalClientSupplier(
        const std::shared_ptr<RegionalClientSupplier> &client_supplier) {
    this->client_supplier = client_supplier;
    return *this;
}

KmsKeyring::Builder &KmsKeyring::Builder::SetKmsClientCache(
        std::shared_ptr<KmsKeyring::KmsClientCache> kms_client_cache) {
    this->kms_client_cache = kms_client_cache;
    return *this;
}

KmsKeyring::Builder &KmsKeyring::Builder::SetKmsClient(std::shared_ptr<KMS::KMSClient> kms_client) {
    this->kms_client = kms_client;
    return *this;
}

std::shared_ptr<KMS::KMSClient> KmsKeyring::KmsClientCache::GetCachedClient(const Aws::String &region) const {
    std::unique_lock<std::mutex> lock(keyring_cache_mutex);
    if (kms_cached_clients.find(region) != kms_cached_clients.end()) {
        return kms_cached_clients.at(region);
    }

    return NULL;
}

void KmsKeyring::KmsClientCache::SaveInCache(const Aws::String &region, std::shared_ptr<KMS::KMSClient> &kms_client) {
    std::unique_lock<std::mutex> lock(keyring_cache_mutex);
    if (kms_cached_clients.find(region) != kms_cached_clients.end()) {
        kms_cached_clients[region] = kms_client;
    }
}


}  // namespace Cryptosdk
}  // namespace Aws
