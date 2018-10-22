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
        auto keyring_data_ptr = kms_keyring->keyring_data;
        kms_keyring->keyring_data = NULL;
        Aws::Delete(keyring_data_ptr);
    }
}

int KmsKeyring::OnDecrypt(struct aws_cryptosdk_keyring *keyring,
                          struct aws_allocator *request_alloc,
                          struct aws_byte_buf *unencrypted_data_key,
                          const struct aws_array_list *edks,
                          const struct aws_hash_table *enc_context,
                          enum aws_cryptosdk_alg_id alg) {
    struct aws_cryptosdk_kms_keyring *kms_keyring = static_cast<aws_cryptosdk_kms_keyring *>(keyring);
    if (!kms_keyring || !kms_keyring->keyring_data || !request_alloc || !unencrypted_data_key || !edks || !enc_context) {
        abort();
    }

    auto self = kms_keyring->keyring_data;

    Aws::StringStream error_buf;
    size_t num_elems = aws_array_list_length(edks);

    for (unsigned int idx = 0; idx < num_elems; idx++) {
        struct aws_cryptosdk_edk *edk;
        int rv = aws_array_list_get_at_ptr(edks, (void **) &edk, idx);
        if (rv != AWS_OP_SUCCESS) {
            continue;
        }

        if (!aws_byte_buf_eq(&edk->provider_id, &self->key_provider)) {
            // FIXME: this is not an error, just means EDK belongs to a different keyring.
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
                                                      aws_map_from_c_aws_hash_table(enc_context));

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
                                                   unencrypted_data_key,
                                                   outcome.GetResult().GetPlaintext());
        }
    }

    AWS_LOGSTREAM_ERROR(AWS_CRYPTO_SDK_KMS_CLASS_TAG,
                        "Could not find any data key that can be decrypted by KMS. Errors:" << error_buf.str());
    // According to materials.h we should return success when no key was found
    return AWS_OP_SUCCESS;
}

int KmsKeyring::OnEncrypt(struct aws_cryptosdk_keyring *keyring,
                          struct aws_allocator *request_alloc,
                          struct aws_byte_buf *unencrypted_data_key,
                          struct aws_array_list *edk_list,
                          const struct aws_hash_table *enc_context,
                          enum aws_cryptosdk_alg_id alg) {
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
        int Create(struct aws_allocator *alloc) {
            auto rv = aws_cryptosdk_edk_list_init(alloc, &aws_list);
            initialized = (rv == AWS_OP_SUCCESS);
            return rv;
        }
        bool initialized = false;
        struct aws_array_list aws_list;
    };
    
    if (!keyring || !request_alloc || !unencrypted_data_key || !edk_list || !enc_context) {
            abort();
    }
    struct aws_cryptosdk_kms_keyring *kms_keyring = static_cast<aws_cryptosdk_kms_keyring *>(keyring);
    auto self = kms_keyring->keyring_data;
    bool generated_new_data_key = false;

    EdksRaii edks;
    int rv = edks.Create(request_alloc);
    if (rv != AWS_OP_SUCCESS) goto out;

    if (!unencrypted_data_key->buffer) {
        const struct aws_cryptosdk_alg_properties *alg_prop = aws_cryptosdk_alg_props(alg);
        if (alg_prop == NULL) {
            AWS_LOGSTREAM_ERROR(AWS_CRYPTO_SDK_KMS_CLASS_TAG, "Invalid encryption materials algorithm properties");
            rv = aws_raise_error(AWS_CRYPTOSDK_ERR_CRYPTO_UNKNOWN);
            goto out;
        }

        auto kms_region = self->GetRegionForConfiguredKmsKeys(self->default_key_id);
        auto kms_client = self->GetKmsClient(kms_region);
        auto kms_request = self->CreateGenerateDataKeyRequest(self->default_key_id,
                                                              self->grant_tokens,
                                                              alg_prop->data_key_len,
                                                              aws_map_from_c_aws_hash_table(enc_context));

        Aws::KMS::Model::GenerateDataKeyOutcome outcome = kms_client->GenerateDataKey(kms_request);
        if (!outcome.IsSuccess()) {
            AWS_LOGSTREAM_ERROR(AWS_CRYPTO_SDK_KMS_CLASS_TAG, "Invalid encryption materials algorithm properties");
            rv = aws_raise_error(AWS_CRYPTOSDK_ERR_KMS_FAILURE);
            goto out;
        }
        self->kms_client_cache->SaveInCache(kms_region, kms_client);

        rv = aws_byte_buf_dup_from_aws_utils(request_alloc,
                                             unencrypted_data_key,
                                             outcome.GetResult().GetPlaintext());
        if (rv != AWS_OP_SUCCESS) goto out;
        generated_new_data_key = true;

        rv = append_key_dup_to_edks(request_alloc,
                                    &edks.aws_list,
                                    &outcome.GetResult().GetCiphertextBlob(),
                                    &outcome.GetResult().GetKeyId(),
                                    &self->key_provider);
        if (rv != AWS_OP_SUCCESS) goto out;
    }

    for (auto key_region_pair : self->key_ids) {
        /* Default CMK used to generate data key is also in the list of key IDs.
         * Do not re-encrypt with that same one.
         */
        auto kms_cmk_name = key_region_pair.first;
        if (generated_new_data_key && kms_cmk_name == self->default_key_id) continue;
        auto kms_region = key_region_pair.second;
        auto kms_client = self->GetKmsClient(kms_region);
        auto kms_client_request = self->CreateEncryptRequest(
            kms_cmk_name,
            self->grant_tokens,
            aws_utils_byte_buffer_from_c_aws_byte_buf(unencrypted_data_key),
            aws_map_from_c_aws_hash_table(enc_context));

        Aws::KMS::Model::EncryptOutcome outcome = kms_client->Encrypt(kms_client_request);
        if (!outcome.IsSuccess()) {
            AWS_LOGSTREAM_ERROR(AWS_CRYPTO_SDK_KMS_CLASS_TAG,
                                "KMS encryption error : " << outcome.GetError().GetExceptionName() << " Message: "
                                                          << outcome.GetError().GetMessage());
            rv = aws_raise_error(AWS_CRYPTOSDK_ERR_KMS_FAILURE);
            goto out;
        }
        self->kms_client_cache->SaveInCache(kms_region, kms_client);
        rv = append_key_dup_to_edks(
            request_alloc,
            &edks.aws_list,
            &outcome.GetResult().GetCiphertextBlob(),
            &outcome.GetResult().GetKeyId(),
            &self->key_provider);
        if (rv != AWS_OP_SUCCESS) {
            goto out;
        }
    }
    rv = aws_cryptosdk_transfer_edk_list(edk_list, &edks.aws_list);
out:
    if (rv != AWS_OP_SUCCESS && generated_new_data_key) {
        aws_byte_buf_clean_up(unencrypted_data_key);
    }
    return rv;
}

void KmsKeyring::InitAwsCryptosdkKeyring(struct aws_allocator *allocator) {
    static const aws_cryptosdk_keyring_vt kms_keyring_vt = {
        sizeof(struct aws_cryptosdk_keyring_vt),  // size
        KEY_PROVIDER_STR,  // name
        &KmsKeyring::DestroyAwsCryptoKeyring,  // destroy callback
        &KmsKeyring::OnEncrypt, // on_encrypt callback
        &KmsKeyring::OnDecrypt  // on_decrypt callback
    };
    alloc = allocator;
    keyring_data = this;
    aws_cryptosdk_keyring_base_init(this, &kms_keyring_vt);
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
    if (!kms_client_cache) {
        kms_client_cache = Aws::MakeShared<KmsClientCache>(AWS_CRYPTO_SDK_KMS_CLASS_TAG);
    }

    InitAwsCryptosdkKeyring(alloc);
    default_key_id = in_key_ids.front();
    this->key_ids = BuildKeyIds(in_key_ids);
}

Aws::String KmsKeyring::GetRegionForConfiguredKmsKeys(const Aws::String &key_id) const {
    auto key_region_pair = key_ids.find(key_id);
    return key_region_pair == key_ids.end() ? "" : key_region_pair->second;
}

std::shared_ptr<KMS::KMSClient> KmsKeyring::GetKmsClient(const Aws::String &region) const {
    auto rv = kms_client_cache->GetCachedClient(region);
    if (rv != NULL) {
        return rv;
    }

    return kms_client_supplier->GetClient(region);
}

std::shared_ptr<KMS::KMSClient> KmsKeyring::DefaultRegionalClientSupplier::GetClient(
    const Aws::String &region_name) const {
    Aws::Client::ClientConfiguration client_configuration;
    client_configuration.region = region_name;
#ifdef VALGRIND_TESTS
    // When running under valgrind, the default timeouts are too slow
    client_configuration.requestTimeoutMs = 10000;
    client_configuration.connectTimeoutMs = 10000;
#endif

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

    // If a single key is configured, we try to extract default region from it.
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
     * We want to allow construction of a KmsKeyring object only through the builder, which is why
     * KmsKeyring has a protected constructor. Doing this allows us to guarantee that it is always
     * allocated with Aws::New. However, Aws::New only allocates memory for classes that have public
     * constructors or for which Aws::New is a friend function. Making Aws::New a friend function
     * would allow creation of a KmsKeyring without the builder. The solution was to make a nested
     * class in the builder which is just the KmsKeyring with a public constructor.
     */
    class KmsKeyringWithPublicConstructor : public KmsKeyring {
    public:
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

void KmsKeyring::KmsClientCache::SaveInCache(const Aws::String &region, std::shared_ptr<KMS::KMSClient> kms_client) {
    std::unique_lock<std::mutex> lock(keyring_cache_mutex);
    if (kms_cached_clients.find(region) == kms_cached_clients.end()) {
        kms_cached_clients[region] = kms_client;
    }
}


}  // namespace Cryptosdk
}  // namespace Aws
