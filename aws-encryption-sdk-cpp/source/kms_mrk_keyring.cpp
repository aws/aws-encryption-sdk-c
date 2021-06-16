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
#include <aws/cryptosdk/cpp/kms_keyring.h>
#include <aws/cryptosdk/private/kms_keyring.h>
#include <aws/cryptosdk/private/kms_mrk_keyring.h>

#include <aws/core/utils/ARN.h>
#include <aws/core/utils/Outcome.h>
#include <aws/core/utils/logging/LogMacros.h>
#include <aws/core/utils/memory/MemorySystemInterface.h>
#include <aws/core/utils/memory/stl/AWSAllocator.h>
#include <aws/cryptosdk/list_utils.h>
#include <aws/cryptosdk/multi_keyring.h>
#include <aws/cryptosdk/private/cpputils.h>
#include <aws/cryptosdk/private/user_agent.h>
#include <aws/kms/model/DecryptRequest.h>
#include <aws/kms/model/DecryptResult.h>
#include <aws/kms/model/EncryptRequest.h>
#include <aws/kms/model/EncryptResult.h>
#include <aws/kms/model/GenerateDataKeyRequest.h>
#include <aws/kms/model/GenerateDataKeyResult.h>

namespace Aws {
namespace Cryptosdk {

using Private::append_key_dup_to_edks;
using Private::aws_byte_buf_dup_from_aws_utils;
using Private::aws_map_from_c_aws_hash_table;
using Private::aws_utils_byte_buffer_from_c_aws_byte_buf;
using Private::BuildClientSupplier;
using Private::KmsMrkAwareSymmetricKeyringImpl;

using KmsKeyring::ClientSupplier;
using KmsKeyring::DiscoveryFilter;

using KmsMrkAwareSymmetricKeyring::Builder;
using KmsMrkAwareSymmetricKeyring::MultiKeyringBuilder;

static const char *AWS_CRYPTO_SDK_KMS_MRK_CLASS_TAG = "KmsMrkAwareSymmetricKeyring";
static const char *KEY_PROVIDER_STR                 = "aws-kms";

static void DestroyKeyring(struct aws_cryptosdk_keyring *keyring) {
    auto keyring_data_ptr = static_cast<KmsMrkAwareSymmetricKeyringImpl *>(keyring);
    Aws::Delete(keyring_data_ptr);
}

static bool is_discovery(const KmsMrkAwareSymmetricKeyringImpl *keyring) {
    return keyring->key_id.length() == 0;
}

/**
 * Returns the given ARN as a string, except with the region set to the given
 * region (instead of the region of the original ARN).
 */
static Aws::String replace_arn_region(const Aws::Utils::ARN &arn, const Aws::String &region) {
    Aws::OStringStream updated_arn;
    updated_arn << "arn:" << arn.GetPartition() << ":" << arn.GetService() << ":" << region << ":" << arn.GetAccountId()
                << ":" << arn.GetResource();
    return Aws::String(updated_arn.str());
}

//= compliance/framework/aws-kms/aws-kms-mrk-aware-symmetric-keyring.txt#2.8
//# OnDecrypt MUST take decryption materials (structures.md#decryption-
//# materials) and a list of encrypted data keys
//# (structures.md#encrypted-data-key) as input.
//
//= compliance/framework/aws-kms/aws-kms-mrk-aware-symmetric-region-discovery-keyring.txt#2.8
//# OnDecrypt MUST take decryption materials (structures.md#decryption-
//# materials) and a list of encrypted data keys
//# (structures.md#encrypted-data-key) as input.
static int OnDecrypt(
    struct aws_cryptosdk_keyring *keyring,
    struct aws_allocator *request_alloc,
    struct aws_byte_buf *unencrypted_data_key,
    struct aws_array_list *keyring_trace,
    const struct aws_array_list *edks,
    const struct aws_hash_table *enc_ctx,
    enum aws_cryptosdk_alg_id alg) {
    (void)alg;
    const struct aws_cryptosdk_alg_properties *props = aws_cryptosdk_alg_props(alg);

    auto self = static_cast<KmsMrkAwareSymmetricKeyringImpl *>(keyring);
    if (!self || !request_alloc || !unencrypted_data_key || !edks || !enc_ctx) {
        abort();
    }

    //= compliance/framework/aws-kms/aws-kms-mrk-aware-symmetric-keyring.txt#2.8
    //# If the decryption materials (structures.md#decryption-materials)
    //# already contained a valid plaintext data key OnDecrypt MUST
    //# immediately return the unmodified decryption materials
    //# (structures.md#decryption-materials).
    //
    //= compliance/framework/aws-kms/aws-kms-mrk-aware-symmetric-region-discovery-keyring.txt#2.8
    //# If the decryption materials (structures.md#decryption-materials)
    //# already contained a valid plaintext data key OnDecrypt MUST
    //# immediately return the unmodified decryption materials
    //# (structures.md#decryption-materials).
    if (unencrypted_data_key->len) {
        return AWS_OP_SUCCESS;
    }

    //= compliance/framework/aws-kms/aws-kms-mrk-aware-symmetric-keyring.txt#2.8
    //# If this attempt
    //# results in an error, then these errors MUST be collected.
    Aws::StringStream error_buf;

    const auto enc_ctx_cpp = aws_map_from_c_aws_hash_table(enc_ctx);

    //= compliance/framework/aws-kms/aws-kms-mrk-aware-symmetric-keyring.txt#2.8
    //# The set of encrypted data keys MUST first be filtered to match this
    //# keyring's configuration.
    //
    //= compliance/framework/aws-kms/aws-kms-mrk-aware-symmetric-keyring.txt#2.8
    //# For each encrypted data key in the filtered set, one at a time, the
    //# OnDecrypt MUST attempt to decrypt the data key.
    //
    //= compliance/framework/aws-kms/aws-kms-mrk-aware-symmetric-region-discovery-keyring.txt#2.8
    //# The set of encrypted data keys MUST first be filtered to match this
    //# keyring's configuration.
    //
    //= compliance/framework/aws-kms/aws-kms-mrk-aware-symmetric-region-discovery-keyring.txt#2.8
    //# For each encrypted data key in the filtered set, one at a time, the
    //# OnDecrypt MUST attempt to decrypt the data key.
    size_t num_elems            = aws_array_list_length(edks);
    bool failed_decrypt_attempt = false;
    for (unsigned int idx = 0; idx < num_elems; idx++) {
        struct aws_cryptosdk_edk *edk;
        int rv = aws_array_list_get_at_ptr(edks, (void **)&edk, idx);
        if (rv != AWS_OP_SUCCESS) {
            continue;
        }

        //= compliance/framework/aws-kms/aws-kms-mrk-aware-symmetric-keyring.txt#2.8
        //# *  Its provider ID MUST exactly match the value "aws-kms".
        //
        //= compliance/framework/aws-kms/aws-kms-mrk-aware-symmetric-region-discovery-keyring.txt#2.8
        //# *  Its provider ID MUST exactly match the value "aws-kms".
        if (!aws_byte_buf_eq(&edk->provider_id, &self->key_provider)) {
            continue;
        }

        //= compliance/framework/aws-kms/aws-kms-mrk-aware-symmetric-keyring.txt#2.8
        //# *  The provider info MUST be a valid AWS KMS ARN (aws-kms-key-
        //# arn.md#a-valid-aws-kms-arn) with a resource type of "key" or
        //# OnDecrypt MUST fail.
        //
        //= compliance/framework/aws-kms/aws-kms-mrk-aware-symmetric-region-discovery-keyring.txt#2.8
        //# *  The provider info MUST be a valid AWS KMS ARN (aws-kms-key-
        //# arn.md#a-valid-aws-kms-arn) with a resource type of "key" or
        //# OnDecrypt MUST fail.
        const Aws::String provider_info_key = Private::aws_string_from_c_aws_byte_buf(&edk->provider_info);
        const Aws::Utils::ARN provider_info_key_arn(provider_info_key);
        // Precondition: The provider info MUST be a well formed AWS KMS ARN.
        if (!Private::is_valid_kms_key_arn(provider_info_key_arn) ||
            !Private::starts_with(provider_info_key_arn.GetResource(), "key")) {
            error_buf << "Error: Malformed ciphertext. Provider ID field of KMS EDK is invalid KMS CMK ARN: "
                      << provider_info_key_arn.GetARNString() << " ";
            continue;
        }

        bool is_mrk                = Private::is_kms_mrk_identifier(provider_info_key_arn.GetARNString());
        Aws::String key_kms_region = provider_info_key_arn.GetRegion();
        Aws::String decrypting_key_kms_region;
        if (is_discovery(self)) {
            decrypting_key_kms_region = self->region;
            //= compliance/framework/aws-kms/aws-kms-mrk-aware-symmetric-region-discovery-keyring.txt#2.8
            //# *  If the provider info is not identified as a multi-Region key (aws-
            //# kms-key-arn.md#identifying-an-aws-kms-multi-region-key), then the
            //# provider info's Region MUST match the AWS KMS client region.
            if (!is_mrk && self->region != key_kms_region) {
                continue;
            }

            //= compliance/framework/aws-kms/aws-kms-mrk-aware-symmetric-region-discovery-keyring.txt#2.8
            //# *  If a discovery filter is configured, its partition and the
            //# provider info partition MUST match.
            //
            //= compliance/framework/aws-kms/aws-kms-mrk-aware-symmetric-region-discovery-keyring.txt#2.8
            //# *  If a discovery filter is configured, its set of accounts MUST
            //# contain the provider info account.
            if (self->discovery_filter && !self->discovery_filter->IsAuthorized(provider_info_key_arn.GetARNString())) {
                continue;
            }
        } else {
            const Aws::Utils::ARN key_arn(self->key_id);
            decrypting_key_kms_region = key_arn.GetRegion();
            if (!is_mrk) {
                if (self->key_id != provider_info_key) {
                    continue;
                }
            } else {
                //= compliance/framework/aws-kms/aws-kms-mrk-aware-symmetric-keyring.txt#2.8
                //# *  The the function AWS KMS MRK Match for Decrypt (aws-kms-mrk-match-
                //# for-decrypt.md#implementation) called with the configured AWS KMS
                //# key identifier and the provider info MUST return "true".
                if (!Private::kms_mrk_match_for_decrypt(self->key_id, provider_info_key_arn.GetARNString())) {
                    continue;
                }
            }
        }

        std::function<void()> report_success;
        auto kms_client = self->kms_client_supplier->GetClient(decrypting_key_kms_region, report_success);
        if (!kms_client) {
            // Client supplier does not serve this region. Skip.
            continue;
        }

        //= compliance/framework/aws-kms/aws-kms-mrk-aware-symmetric-region-discovery-keyring.txt#2.8
        //# *  "KeyId": If the provider info's resource type is "key" and its
        //# resource is a multi-Region key then a new ARN MUST be created
        //# where the region part MUST equal the AWS KMS client region and
        //# every other part MUST equal the provider info.
        Aws::String decrypt_key_arn;
        if (is_mrk) {
            if (is_discovery(self)) {
                if (Private::starts_with(provider_info_key_arn.GetResource(), "key")) {
                    decrypt_key_arn = replace_arn_region(provider_info_key_arn, self->region);
                } else {
                    decrypt_key_arn = provider_info_key;
                }
            } else {
                decrypt_key_arn = self->key_id;
            }
        } else {
            //= compliance/framework/aws-kms/aws-kms-mrk-aware-symmetric-region-discovery-keyring.txt#2.8
            //# Otherwise it MUST
            //# be the provider info.
            decrypt_key_arn = provider_info_key;
        }

        //= compliance/framework/aws-kms/aws-kms-mrk-aware-symmetric-keyring.txt#2.8
        //# When calling AWS KMS Decrypt
        //# (https://docs.aws.amazon.com/kms/latest/APIReference/
        //# API_Decrypt.html), the keyring MUST call with a request constructed
        //# as follows:
        //
        //= compliance/framework/aws-kms/aws-kms-mrk-aware-symmetric-region-discovery-keyring.txt#2.8
        //# When calling AWS KMS Decrypt
        //# (https://docs.aws.amazon.com/kms/latest/APIReference/
        //# API_Decrypt.html), the keyring MUST call with a request constructed
        //# as follows:
        Aws::KMS::Model::DecryptRequest kms_request;
        kms_request.WithKeyId(decrypt_key_arn)
            .WithCiphertextBlob(aws_utils_byte_buffer_from_c_aws_byte_buf(&edk->ciphertext))
            .WithEncryptionContext(enc_ctx_cpp)
            .WithGrantTokens(self->grant_tokens);

        //= compliance/framework/aws-kms/aws-kms-mrk-aware-symmetric-keyring.txt#2.8
        //# To attempt to decrypt a particular encrypted data key
        //# (structures.md#encrypted-data-key), OnDecrypt MUST call AWS KMS
        //# Decrypt (https://docs.aws.amazon.com/kms/latest/APIReference/
        //# API_Decrypt.html) with the configured AWS KMS client.
        //
        //= compliance/framework/aws-kms/aws-kms-mrk-aware-symmetric-region-discovery-keyring.txt#2.8
        //# To attempt to decrypt a particular encrypted data key
        //# (structures.md#encrypted-data-key), OnDecrypt MUST call AWS KMS
        //# Decrypt (https://docs.aws.amazon.com/kms/latest/APIReference/
        //# API_Decrypt.html) with the configured AWS KMS client.
        Aws::KMS::Model::DecryptOutcome outcome = kms_client->Decrypt(kms_request);
        if (!outcome.IsSuccess()) {
            // Failing on this call is normal behavior in discovery mode, but not in strict mode.
            if (!is_discovery(self)) {
                error_buf << "Error: " << outcome.GetError().GetExceptionName()
                          << " Message:" << outcome.GetError().GetMessage() << " ";
                failed_decrypt_attempt = true;
            }
            continue;
        }
        report_success();

        const Aws::String &outcome_key_id = outcome.GetResult().GetKeyId();

        // NOTE: these citations appear duplicated, but in fact some are for
        // the strict keyring, and the others are for the discovery keyring

        //= compliance/framework/aws-kms/aws-kms-mrk-aware-symmetric-keyring.txt#2.8
        //# *  The length of the response's "Plaintext" MUST equal the key
        //# derivation input length (algorithm-suites.md#key-derivation-input-
        //# length) specified by the algorithm suite (algorithm-suites.md)
        //# included in the input decryption materials
        //# (structures.md#decryption-materials).
        //
        //= compliance/framework/aws-kms/aws-kms-mrk-aware-symmetric-region-discovery-keyring.txt#2.8
        //# *  The length of the response's "Plaintext" MUST equal the key
        //# derivation input length (algorithm-suites.md#key-derivation-input-
        //# length) specified by the algorithm suite (algorithm-suites.md)
        //# included in the input decryption materials
        //# (structures.md#decryption-materials).
        //
        //= compliance/framework/aws-kms/aws-kms-mrk-aware-symmetric-keyring.txt#2.8
        //# *  The "KeyId" field in the response MUST equal the configured AWS
        //# KMS key identifier.
        //
        //= compliance/framework/aws-kms/aws-kms-mrk-aware-symmetric-region-discovery-keyring.txt#2.8
        //# *  The "KeyId" field in the response MUST equal the requested "KeyId"
        //
        //= compliance/framework/aws-kms/aws-kms-mrk-aware-symmetric-keyring.txt#2.8
        //# If the response does not satisfies these requirements then an error
        //# MUST be collected and the next encrypted data key in the filtered set
        //# MUST be attempted.
        //
        //= compliance/framework/aws-kms/aws-kms-mrk-aware-symmetric-region-discovery-keyring.txt#2.8
        //# If the response does not satisfies these requirements then an error
        //# is collected and the next encrypted data key in the filtered set MUST
        //# be attempted.
        if (outcome.GetResult().GetPlaintext().GetLength() != props->content_key_len) {
            failed_decrypt_attempt = true;
            error_buf << "Malformed plaintext in response. ";
            continue;
        }
        if (outcome_key_id != decrypt_key_arn) {
            failed_decrypt_attempt = true;
            error_buf << "Incorrect key used for KMS Decrypt. ";
            continue;
        }

        //= compliance/framework/aws-kms/aws-kms-mrk-aware-symmetric-keyring.txt#2.8
        //# If the response does satisfies these requirements then OnDecrypt MUST
        //# do the following with the response:
        //
        //= compliance/framework/aws-kms/aws-kms-mrk-aware-symmetric-region-discovery-keyring.txt#2.8
        //# Since the response does satisfies these requirements then OnDecrypt
        //# MUST do the following with the response:
        //
        //   - set the plaintext data key on the [decryption materials](structures.md#decryption-materials) as the
        //   response Plaintext.
        //   - immediately return the modified [decryption materials](structures.md#decryption-materials).
        int ret =
            aws_byte_buf_dup_from_aws_utils(request_alloc, unencrypted_data_key, outcome.GetResult().GetPlaintext());
        if (ret == AWS_OP_SUCCESS) {
            aws_cryptosdk_keyring_trace_add_record_c_str(
                request_alloc,
                keyring_trace,
                KEY_PROVIDER_STR,
                provider_info_key_arn.GetARNString().c_str(),
                AWS_CRYPTOSDK_WRAPPING_KEY_DECRYPTED_DATA_KEY | AWS_CRYPTOSDK_WRAPPING_KEY_VERIFIED_ENC_CTX);
        }
        return ret;
    }

    //= compliance/framework/aws-kms/aws-kms-mrk-aware-symmetric-keyring.txt#2.8
    //# If OnDecrypt fails to successfully decrypt any encrypted data key
    //# (structures.md#encrypted-data-key), then it MUST yield an error that
    //# includes all the collected errors.
    //
    //= compliance/framework/aws-kms/aws-kms-mrk-aware-symmetric-region-discovery-keyring.txt#2.8
    //# If OnDecrypt fails to successfully decrypt any encrypted data key
    //# (structures.md#encrypted-data-key), then it MUST yield an error that
    //# includes all collected errors.
    AWS_LOGSTREAM_ERROR(
        AWS_CRYPTO_SDK_KMS_MRK_CLASS_TAG,
        "Could not find any data key that can be decrypted by KMS. Errors:" << error_buf.str());
    if (failed_decrypt_attempt) {
        return aws_raise_error(AWS_CRYPTOSDK_ERR_KMS_FAILURE);
    }

    // According to materials.h we should return success when no key was found
    return AWS_OP_SUCCESS;
}

//= compliance/framework/aws-kms/aws-kms-mrk-aware-symmetric-keyring.txt#2.7
//# OnEncrypt MUST take encryption materials (structures.md#encryption-
//# materials) as input.
static int OnEncrypt(
    struct aws_cryptosdk_keyring *keyring,
    struct aws_allocator *request_alloc,
    struct aws_byte_buf *unencrypted_data_key,
    struct aws_array_list *keyring_trace,
    struct aws_array_list *edk_list,
    const struct aws_hash_table *enc_ctx,
    enum aws_cryptosdk_alg_id alg) {
    if (!keyring || !request_alloc || !unencrypted_data_key || !edk_list || !enc_ctx) {
        abort();
    }
    auto self = static_cast<KmsMrkAwareSymmetricKeyringImpl *>(keyring);

    //= compliance/framework/aws-kms/aws-kms-mrk-aware-symmetric-region-discovery-keyring.txt#2.7
    //# This function MUST fail.
    if (is_discovery(self)) {
        AWS_LOGSTREAM_ERROR(AWS_CRYPTO_SDK_KMS_MRK_CLASS_TAG, "Cannot encrypt with a KMS keyring in discovery mode");
        return aws_raise_error(AWS_CRYPTOSDK_ERR_BAD_STATE);
    }

    Private::ListRaii my_edks(aws_cryptosdk_edk_list_init, aws_cryptosdk_edk_list_clean_up);
    Private::ListRaii my_keyring_trace(aws_cryptosdk_keyring_trace_init, aws_cryptosdk_keyring_trace_clean_up);
    int rv = my_edks.Create(request_alloc);
    if (rv) return rv;
    rv = my_keyring_trace.Create(request_alloc);
    if (rv) return rv;

    const auto enc_ctx_cpp = aws_map_from_c_aws_hash_table(enc_ctx);

    //= compliance/framework/aws-kms/aws-kms-mrk-aware-symmetric-keyring.txt#2.7
    //# If the input encryption materials (structures.md#encryption-
    //# materials) do not contain a plaintext data key OnEncrypt MUST attempt
    //# to generate a new plaintext data key by calling AWS KMS
    //# GenerateDataKey (https://docs.aws.amazon.com/kms/latest/APIReference/
    //# API_GenerateDataKey.html).
    bool generated_new_data_key = false;
    if (!unencrypted_data_key->buffer) {
        const struct aws_cryptosdk_alg_properties *alg_prop = aws_cryptosdk_alg_props(alg);
        if (alg_prop == NULL) {
            AWS_LOGSTREAM_ERROR(AWS_CRYPTO_SDK_KMS_MRK_CLASS_TAG, "Invalid encryption materials algorithm properties");
            return aws_raise_error(AWS_CRYPTOSDK_ERR_CRYPTO_UNKNOWN);
        }
        // Already checked on keyring build that this will succeed.
        Aws::String key_kms_region = Private::parse_region_from_kms_key_arn(self->key_id);

        //= compliance/framework/aws-kms/aws-kms-mrk-aware-symmetric-keyring.txt#2.7
        //# If the keyring calls AWS KMS GenerateDataKeys, it MUST use the
        //# configured AWS KMS client to make the call.
        std::function<void()> report_success;
        auto kms_client = self->kms_client_supplier->GetClient(key_kms_region, report_success);
        if (!kms_client) {
            /* Client supplier is allowed to return NULL if, for example, user wants to exclude particular
             * regions. But if we are here it means that user configured keyring with a KMS key that was
             * incompatible with the client supplier in use.
             */
            return aws_raise_error(AWS_CRYPTOSDK_ERR_BAD_STATE);
        }

        //= compliance/framework/aws-kms/aws-kms-mrk-aware-symmetric-keyring.txt#2.7
        //# The keyring MUST call
        //# AWS KMS GenerateDataKeys with a request constructed as follows:
        Aws::KMS::Model::GenerateDataKeyRequest kms_request;
        kms_request.WithKeyId(self->key_id)
            .WithNumberOfBytes((int)alg_prop->data_key_len)
            .WithEncryptionContext(enc_ctx_cpp)
            .WithGrantTokens(self->grant_tokens);

        Aws::KMS::Model::GenerateDataKeyOutcome outcome = kms_client->GenerateDataKey(kms_request);

        //= compliance/framework/aws-kms/aws-kms-mrk-aware-symmetric-keyring.txt#2.7
        //# If the call to AWS KMS GenerateDataKey
        //# (https://docs.aws.amazon.com/kms/latest/APIReference/
        //# API_GenerateDataKey.html) does not succeed, OnEncrypt MUST NOT modify
        //# the encryption materials (structures.md#encryption-materials) and
        //# MUST fail.
        if (!outcome.IsSuccess()) {
            AWS_LOGSTREAM_ERROR(AWS_CRYPTO_SDK_KMS_MRK_CLASS_TAG, "Invalid encryption materials algorithm properties");
            return aws_raise_error(AWS_CRYPTOSDK_ERR_KMS_FAILURE);
        }

        //= compliance/framework/aws-kms/aws-kms-mrk-aware-symmetric-keyring.txt#2.7
        //# If the Generate Data Key call succeeds, OnEncrypt MUST verify that
        //# the response "Plaintext" length matches the specification of the
        //# algorithm suite (algorithm-suites.md)'s Key Derivation Input Length
        //# field.
        if (outcome.GetResult().GetPlaintext().GetLength() != alg_prop->content_key_len) {
            AWS_LOGSTREAM_ERROR(AWS_CRYPTO_SDK_KMS_MRK_CLASS_TAG, "Malformed plaintext in response");
            return aws_raise_error(AWS_CRYPTOSDK_ERR_KMS_FAILURE);
        }

        //= compliance/framework/aws-kms/aws-kms-mrk-aware-symmetric-keyring.txt#2.7
        //# The Generate Data Key response's "KeyId" MUST be A valid AWS
        //# KMS key ARN (aws-kms-key-arn.md#identifying-an-aws-kms-multi-region-
        //# key).
        Aws::Utils::ARN response_key_arn(outcome.GetResult().GetKeyId());
        if (!Private::is_valid_kms_key_arn(response_key_arn)) {
            AWS_LOGSTREAM_ERROR(AWS_CRYPTO_SDK_KMS_MRK_CLASS_TAG, "Malformed key ARN in response");
            return aws_raise_error(AWS_CRYPTOSDK_ERR_KMS_FAILURE);
        }
        report_success();

        //= compliance/framework/aws-kms/aws-kms-mrk-aware-symmetric-keyring.txt#2.7
        //# If verified, OnEncrypt MUST do the following with the response
        //# from AWS KMS GenerateDataKey
        //# (https://docs.aws.amazon.com/kms/latest/APIReference/
        //# API_GenerateDataKey.html):
        //   * append a new [encrypted data key](structures.md#encrypted-data-key) to the encrypted data key
        //     list in the [encryption materials](structures.md#encryption-materials)
        rv = append_key_dup_to_edks(
            request_alloc,
            &my_edks.list,
            &outcome.GetResult().GetCiphertextBlob(),
            &outcome.GetResult().GetKeyId(),
            &self->key_provider);
        if (rv != AWS_OP_SUCCESS) return rv;

        //   * set the plaintext data key on the [encryption materials](structures.md#encryption-materials) as the
        //   response Plaintext
        rv = aws_byte_buf_dup_from_aws_utils(request_alloc, unencrypted_data_key, outcome.GetResult().GetPlaintext());
        if (rv != AWS_OP_SUCCESS) return rv;
        generated_new_data_key = true;
        aws_cryptosdk_keyring_trace_add_record_c_str(
            request_alloc,
            &my_keyring_trace.list,
            KEY_PROVIDER_STR,
            self->key_id.c_str(),
            AWS_CRYPTOSDK_WRAPPING_KEY_GENERATED_DATA_KEY | AWS_CRYPTOSDK_WRAPPING_KEY_ENCRYPTED_DATA_KEY |
                AWS_CRYPTOSDK_WRAPPING_KEY_SIGNED_ENC_CTX);

        //= compliance/framework/aws-kms/aws-kms-mrk-aware-symmetric-keyring.txt#2.7
        //# *  OnEncrypt MUST output the modified encryption materials
        //# (structures.md#encryption-materials)
        // (implicit)
    } else {
        const auto unencrypted_data_key_cpp = aws_utils_byte_buffer_from_c_aws_byte_buf(unencrypted_data_key);

        //= compliance/framework/aws-kms/aws-kms-mrk-aware-symmetric-keyring.txt#2.7
        //# Given a plaintext data key in the encryption materials
        //# (structures.md#encryption-materials), OnEncrypt MUST attempt to
        //# encrypt the plaintext data key using the configured AWS KMS key
        //# identifier.

        // Already checked on keyring build that this will succeed.
        Aws::String key_kms_region = Private::parse_region_from_kms_key_arn(self->key_id);

        //= compliance/framework/aws-kms/aws-kms-mrk-aware-symmetric-keyring.txt#2.7
        //# The keyring MUST call AWS KMS Encrypt
        //# (https://docs.aws.amazon.com/kms/latest/APIReference/
        //# API_Encrypt.html) using the configured AWS KMS client.
        std::function<void()> report_success;
        auto kms_client = self->kms_client_supplier->GetClient(key_kms_region, report_success);
        if (!kms_client) {
            /* Client supplier is allowed to return NULL if, for example, user wants to exclude particular
             * regions. But if we are here it means that user configured keyring with a KMS key that was
             * incompatible with the client supplier in use.
             */
            rv = aws_raise_error(AWS_CRYPTOSDK_ERR_BAD_STATE);
            goto out;
        }

        //= compliance/framework/aws-kms/aws-kms-mrk-aware-symmetric-keyring.txt#2.7
        //# The keyring
        //# MUST AWS KMS Encrypt call with a request constructed as follows:
        Aws::KMS::Model::EncryptRequest kms_request;
        kms_request.WithKeyId(self->key_id)
            .WithPlaintext(unencrypted_data_key_cpp)
            .WithEncryptionContext(enc_ctx_cpp)
            .WithGrantTokens(self->grant_tokens);

        //= compliance/framework/aws-kms/aws-kms-mrk-aware-symmetric-keyring.txt#2.7
        //# If the call to AWS KMS Encrypt
        //# (https://docs.aws.amazon.com/kms/latest/APIReference/
        //# API_Encrypt.html) does not succeed, OnEncrypt MUST fail.
        Aws::KMS::Model::EncryptOutcome outcome = kms_client->Encrypt(kms_request);
        if (!outcome.IsSuccess()) {
            AWS_LOGSTREAM_ERROR(
                AWS_CRYPTO_SDK_KMS_MRK_CLASS_TAG,
                "KMS encryption error : " << outcome.GetError().GetExceptionName()
                                          << " Message: " << outcome.GetError().GetMessage());
            rv = aws_raise_error(AWS_CRYPTOSDK_ERR_KMS_FAILURE);
            goto out;
        }
        //= compliance/framework/aws-kms/aws-kms-mrk-aware-symmetric-keyring.txt#2.7
        //# If the Encrypt call succeeds The response's "KeyId" MUST be A valid
        //# AWS KMS key ARN (aws-kms-key-arn.md#identifying-an-aws-kms-multi-
        //# region-key).
        if (!Private::is_valid_kms_key_arn(outcome.GetResult().GetKeyId())) {
            AWS_LOGSTREAM_ERROR(AWS_CRYPTO_SDK_KMS_MRK_CLASS_TAG, "Malformed key ARN in response");
            return aws_raise_error(AWS_CRYPTOSDK_ERR_KMS_FAILURE);
        }
        report_success();

        //= compliance/framework/aws-kms/aws-kms-mrk-aware-symmetric-keyring.txt#2.7
        //# If verified, OnEncrypt MUST do the following with the
        //# response from AWS KMS Encrypt
        //# (https://docs.aws.amazon.com/kms/latest/APIReference/
        //# API_Encrypt.html):
        //   * append a new [encrypted data key](structures.md#encrypted-data-key)
        //     to the encrypted data key list in the
        //     [encryption materials](structures.md#encryption-materials)
        rv = append_key_dup_to_edks(
            request_alloc,
            &my_edks.list,
            &outcome.GetResult().GetCiphertextBlob(),
            &outcome.GetResult().GetKeyId(),
            &self->key_provider);
        if (rv != AWS_OP_SUCCESS) {
            goto out;
        }
        aws_cryptosdk_keyring_trace_add_record_c_str(
            request_alloc,
            &my_keyring_trace.list,
            KEY_PROVIDER_STR,
            self->key_id.c_str(),
            AWS_CRYPTOSDK_WRAPPING_KEY_ENCRYPTED_DATA_KEY | AWS_CRYPTOSDK_WRAPPING_KEY_SIGNED_ENC_CTX);
    }

    //= compliance/framework/aws-kms/aws-kms-mrk-aware-symmetric-keyring.txt#2.7
    //# If all Encrypt calls succeed, OnEncrypt MUST output the modified
    //# encryption materials (structures.md#encryption-materials).
    // (implicit)

    rv = aws_cryptosdk_transfer_list(edk_list, &my_edks.list);
    if (rv == AWS_OP_SUCCESS) {
        aws_cryptosdk_transfer_list(keyring_trace, &my_keyring_trace.list);
    }
out:
    if (rv != AWS_OP_SUCCESS && generated_new_data_key) {
        aws_byte_buf_clean_up(unencrypted_data_key);
    }
    return rv;
}

KmsMrkAwareSymmetricKeyringImpl::~KmsMrkAwareSymmetricKeyringImpl() {}

KmsMrkAwareSymmetricKeyringImpl::KmsMrkAwareSymmetricKeyringImpl(
    const Aws::String &key_id,
    const Aws::Vector<Aws::String> &grant_tokens,
    std::shared_ptr<Aws::Cryptosdk::KmsKeyring::ClientSupplier> client_supplier)
    : key_provider(aws_byte_buf_from_c_str(KEY_PROVIDER_STR)),
      kms_client_supplier(client_supplier),
      grant_tokens(grant_tokens),
      key_id(key_id) {
    static const aws_cryptosdk_keyring_vt kms_keyring_vt = {
        sizeof(struct aws_cryptosdk_keyring_vt), KEY_PROVIDER_STR, &DestroyKeyring, &OnEncrypt, &OnDecrypt
    };

    aws_cryptosdk_keyring_base_init(this, &kms_keyring_vt);
}

//= compliance/framework/aws-kms/aws-kms-mrk-aware-symmetric-keyring.txt#2.6
//# On initialization the caller MUST provide:
aws_cryptosdk_keyring *Builder::Build(const Aws::String &key_id) const {
    //= compliance/framework/aws-kms/aws-kms-mrk-aware-symmetric-keyring.txt#2.6
    //# The AWS KMS key identifier MUST NOT be null or empty.
    //
    //= compliance/framework/aws-kms/aws-kms-mrk-aware-symmetric-keyring.txt#2.6
    //# The AWS KMS
    //# key identifier MUST be a valid identifier (aws-kms-key-arn.md#a-
    //# valid-aws-kms-identifier).
    if (key_id.empty() || !Private::is_valid_kms_identifier(key_id)) {
        AWS_LOGSTREAM_ERROR(AWS_CRYPTO_SDK_KMS_MRK_CLASS_TAG, "Key identifier is not valid");
        aws_raise_error(AWS_ERROR_INVALID_ARGUMENT);
        return NULL;
    }

    Aws::Vector<Aws::String> my_key_ids = { key_id };
    return Aws::New<KmsMrkAwareSymmetricKeyringImpl>(
        AWS_CRYPTO_SDK_KMS_MRK_CLASS_TAG,
        key_id,
        grant_tokens,
        Private::BuildClientSupplier(my_key_ids, kms_client, client_supplier));
}

//= compliance/framework/aws-kms/aws-kms-mrk-aware-symmetric-region-discovery-keyring.txt#2.6
//# On initialization the caller MUST provide:
//
//= compliance/framework/aws-kms/aws-kms-mrk-aware-symmetric-region-discovery-keyring.txt#2.6
//# The keyring MUST know what Region the AWS KMS client is in.
//
//= compliance/framework/aws-kms/aws-kms-mrk-aware-symmetric-region-discovery-keyring.txt#2.6
//# It SHOULD have a Region parameter and
//# SHOULD try to identify mismatched configurations.
aws_cryptosdk_keyring *Builder::BuildDiscovery(const Aws::String &region) const {
    if (client_supplier || !kms_client) {
        AWS_LOGSTREAM_ERROR(
            AWS_CRYPTO_SDK_KMS_MRK_CLASS_TAG, "KmsMrkAwareSymmetricKeyring in discovery mode requires a KMS client");
        aws_raise_error(AWS_ERROR_INVALID_ARGUMENT);
        return nullptr;
    }

    Aws::String empty_key_id;
    return Aws::New<KmsMrkAwareSymmetricKeyringImpl>(
        AWS_CRYPTO_SDK_KMS_MRK_CLASS_TAG,
        "",
        grant_tokens,
        region,
        KmsKeyring::SingleClientSupplier::Create(kms_client),
        nullptr);
}

aws_cryptosdk_keyring *Builder::BuildDiscovery(
    const Aws::String &region, std::shared_ptr<DiscoveryFilter> discovery_filter) const {
    if (region.size() == 0) {
        return nullptr;
    }

    if (client_supplier || !kms_client) {
        AWS_LOGSTREAM_ERROR(
            AWS_CRYPTO_SDK_KMS_MRK_CLASS_TAG, "KmsMrkAwareSymmetricKeyring in discovery mode requires a KMS client");
        aws_raise_error(AWS_ERROR_INVALID_ARGUMENT);
        return nullptr;
    }

    Aws::Vector<Aws::String> empty_key_ids_list;
    return Aws::New<KmsMrkAwareSymmetricKeyringImpl>(
        AWS_CRYPTO_SDK_KMS_MRK_CLASS_TAG,
        "",
        grant_tokens,
        region,
        KmsKeyring::SingleClientSupplier::Create(kms_client),
        discovery_filter);
}

Builder &Builder::WithGrantTokens(const Aws::Vector<Aws::String> &grant_tokens) {
    this->grant_tokens.insert(this->grant_tokens.end(), grant_tokens.begin(), grant_tokens.end());
    return *this;
}

Builder &Builder::WithGrantToken(const Aws::String &grant_token) {
    this->grant_tokens.push_back(grant_token);
    return *this;
}

Builder &Builder::WithClientSupplier(const std::shared_ptr<ClientSupplier> &client_supplier) {
    this->client_supplier = client_supplier;
    return *this;
}

Builder &Builder::WithKmsClient(const std::shared_ptr<KMS::KMSClient> &kms_client) {
    this->kms_client = kms_client;
    return *this;
}

MultiKeyringBuilder &MultiKeyringBuilder::WithGrantToken(const Aws::String &grant_token) {
    this->grant_tokens.push_back(grant_token);
    return *this;
}

MultiKeyringBuilder &MultiKeyringBuilder::WithGrantTokens(const Aws::Vector<Aws::String> &grant_tokens) {
    this->grant_tokens.insert(this->grant_tokens.end(), grant_tokens.begin(), grant_tokens.end());
    return *this;
}

MultiKeyringBuilder &MultiKeyringBuilder::WithClientSupplier(const std::shared_ptr<ClientSupplier> &client_supplier) {
    this->client_supplier = client_supplier;
    return *this;
}

aws_cryptosdk_keyring *MultiKeyringBuilder::Build(
    const Aws::String &generator_key_id, const Aws::Vector<Aws::String> &additional_key_ids) const {
    if (generator_key_id.size() == 0) {
        return nullptr;
    }

    return _Build(generator_key_id, additional_key_ids);
}

aws_cryptosdk_keyring *MultiKeyringBuilder::Build(const Aws::Vector<Aws::String> &additional_key_ids) const {
    Aws::String empty_key_id;
    return _Build(empty_key_id, additional_key_ids);
}

//= compliance/framework/aws-kms/aws-kms-mrk-aware-multi-keyrings.txt#2.6
//# The caller MUST provide:
aws_cryptosdk_keyring *MultiKeyringBuilder::_Build(
    const Aws::String &generator_key_id, const Aws::Vector<Aws::String> &additional_key_ids) const {
    bool has_generator_input = generator_key_id.size() > 0;

    //= compliance/framework/aws-kms/aws-kms-mrk-aware-multi-keyrings.txt#2.6
    //# If any of the AWS KMS key identifiers is null or an empty string this
    //# function MUST fail.
    //
    // NOTE: generator_key_id may be blank to indicate that this multi-keyring
    // should not generate data keys. But this method isn't exposed as a public
    // API - the public Build methods either accept a non-empty string or no
    // string at all.
    Aws::Vector<Aws::String> all_key_ids;
    if (has_generator_input) {
        all_key_ids.push_back(generator_key_id);
    }
    for (auto child_key_id = additional_key_ids.begin(); child_key_id != additional_key_ids.end(); child_key_id++) {
        if (child_key_id->size() == 0) {
            return nullptr;
        }
        all_key_ids.push_back(*child_key_id);
    }

    //= compliance/framework/aws-kms/aws-kms-mrk-aware-multi-keyrings.txt#2.6
    //# At least one non-null or non-empty string AWS
    //# KMS key identifiers exists in the input this function MUST fail.
    if (all_key_ids.size() == 0) {
        return nullptr;
    }

    //= compliance/framework/aws-kms/aws-kms-mrk-aware-multi-keyrings.txt#2.6
    //# All
    //# AWS KMS identifiers are passed to Assert AWS KMS MRK are unique (aws-
    //# kms-mrk-are-unique.md#Implementation) and the function MUST return
    //# success otherwise this MUST fail.
    if (Private::find_duplicate_kms_mrk_ids(all_key_ids).size() > 0) {
        return nullptr;
    }

    //= compliance/framework/aws-kms/aws-kms-mrk-aware-multi-keyrings.txt#2.6
    //# If a regional client supplier is
    //# not passed, then a default MUST be created that takes a region string
    //# and generates a default AWS SDK client for the given region.
    const std::shared_ptr<ClientSupplier> client_supplier_or_default =
        this->client_supplier ? this->client_supplier : KmsKeyring::CachingClientSupplier::Create();

    // Must initialize these before any goto's
    struct aws_cryptosdk_keyring *generator_keyring = nullptr;
    struct aws_cryptosdk_keyring *multi_keyring     = nullptr;
    Aws::Vector<aws_cryptosdk_keyring *> child_keyrings;

    //= compliance/framework/aws-kms/aws-kms-mrk-aware-multi-keyrings.txt#2.6
    //# If there is a generator input then the generator keyring MUST be a
    //# AWS KMS MRK Aware Symmetric Keyring (aws-kms-mrk-aware-symmetric-
    //# keyring.md) initialized with
    if (has_generator_input) {
        //= compliance/framework/aws-kms/aws-kms-mrk-aware-multi-keyrings.txt#2.6
        //# *  The AWS KMS client that MUST be created by the regional client
        //# supplier when called with the region part of the generator ARN or
        //# a signal for the AWS SDK to select the default region.
        //
        // Note: if `generator_key_id` isn't an ARN, `region` will be the empty
        // string and the client supplier will use the SDK's default region
        const Aws::String region             = Private::parse_region_from_kms_key_arn(generator_key_id);
        std::function<void()> report_success = [] {};
        const std::shared_ptr<KMS::KMSClient> kms_client =
            client_supplier_or_default->GetClient(region, report_success);
        if (!kms_client) {
            goto cleanup;
        }
        generator_keyring =
            Builder().WithKmsClient(kms_client).WithGrantTokens(this->grant_tokens).Build(generator_key_id);
        if (!generator_keyring) {
            goto cleanup;
        }
    }

    //= compliance/framework/aws-kms/aws-kms-mrk-aware-multi-keyrings.txt#2.6
    //# Then a Multi-Keyring (../multi-keyring.md#inputs) MUST be initialize
    //# by using this generator keyring as the generator keyring (../multi-
    //# keyring.md#generator-keyring) and this set of child keyrings as the
    //# child keyrings (../multi-keyring.md#child-keyrings).
    multi_keyring = aws_cryptosdk_multi_keyring_new(aws_default_allocator(), generator_keyring);
    if (!multi_keyring) {
        goto cleanup;
    }

    //= compliance/framework/aws-kms/aws-kms-mrk-aware-multi-keyrings.txt#2.6
    //# If there is a set of child identifiers then a set of AWS KMS MRK
    //# Aware Symmetric Keyring (aws-kms-mrk-aware-symmetric-keyring.md) MUST
    //# be created for each AWS KMS key identifier by initialized each
    //# keyring with
    for (auto child_key_id = additional_key_ids.begin(); child_key_id != additional_key_ids.end(); child_key_id++) {
        //= compliance/framework/aws-kms/aws-kms-mrk-aware-multi-keyrings.txt#2.6
        //# *  The AWS KMS client that MUST be created by the regional client
        //# supplier when called with the region part of the AWS KMS key
        //# identifier or a signal for the AWS SDK to select the default
        //# region.
        const Aws::String region = Private::parse_region_from_kms_key_arn(*child_key_id);
        if (!region.size()) {
            goto cleanup;
        }
        std::function<void()> report_success = [] {};
        const std::shared_ptr<KMS::KMSClient> kms_client =
            client_supplier_or_default->GetClient(region, report_success);
        if (!kms_client) {
            goto cleanup;
        }

        struct aws_cryptosdk_keyring *child_keyring =
            Builder().WithKmsClient(kms_client).WithGrantTokens(this->grant_tokens).Build(*child_key_id);
        if (!child_keyring) {
            goto cleanup;
        }
        child_keyrings.push_back(child_keyring);
        if (AWS_OP_SUCCESS != aws_cryptosdk_multi_keyring_add_child(multi_keyring, child_keyring)) {
            goto cleanup;
        }
    }

    //= compliance/framework/aws-kms/aws-kms-mrk-aware-multi-keyrings.txt#2.6
    //# NOTE: The AWS Encryption SDK SHOULD NOT attempt to evaluate its own
    //# default region.
    // (implicit)

    //= compliance/framework/aws-kms/aws-kms-mrk-aware-multi-keyrings.txt#2.6
    //# This Multi-
    //# Keyring MUST be this functions output.
    return multi_keyring;

cleanup:
    if (generator_keyring) {
        aws_cryptosdk_keyring_release(generator_keyring);
    }
    for (auto child_keyring = child_keyrings.begin(); child_keyring != child_keyrings.end(); child_keyring++) {
        aws_cryptosdk_keyring_release(*child_keyring);
    }
    if (multi_keyring) {
        aws_cryptosdk_keyring_release(multi_keyring);
    }
    return nullptr;
}

//= compliance/framework/aws-kms/aws-kms-mrk-aware-multi-keyrings.txt#2.5
//# The caller MUST provide:
aws_cryptosdk_keyring *MultiKeyringBuilder::BuildDiscovery(
    const Aws::Set<Aws::String> &regions, std::shared_ptr<DiscoveryFilter> discovery_filter) const {
    //= compliance/framework/aws-kms/aws-kms-mrk-aware-multi-keyrings.txt#2.5
    //# If an empty set of Region is provided this function MUST fail.
    if (regions.size() == 0) {
        return nullptr;
    }

    //= compliance/framework/aws-kms/aws-kms-mrk-aware-multi-keyrings.txt#2.5
    //# If
    //# any element of the set of regions is null or an empty string this
    //# function MUST fail.
    for (auto region = regions.begin(); region != regions.end(); region++) {
        if (region->size() == 0) {
            return nullptr;
        }
    }

    //= compliance/framework/aws-kms/aws-kms-mrk-aware-multi-keyrings.txt#2.5
    //# If a regional client supplier is not passed,
    //# then a default MUST be created that takes a region string and
    //# generates a default AWS SDK client for the given region.
    const std::shared_ptr<ClientSupplier> client_supplier_or_default =
        this->client_supplier ? this->client_supplier : KmsKeyring::CachingClientSupplier::Create();

    // Must initialize this before any goto's
    Aws::Vector<aws_cryptosdk_keyring *> child_keyrings;

    //= compliance/framework/aws-kms/aws-kms-mrk-aware-multi-keyrings.txt#2.5
    //# Then a Multi-Keyring (../multi-keyring.md#inputs) MUST be initialize
    //# by using this set of discovery keyrings as the child keyrings
    //# (../multi-keyring.md#child-keyrings).
    struct aws_cryptosdk_keyring *multi_keyring = aws_cryptosdk_multi_keyring_new(aws_default_allocator(), nullptr);
    if (!multi_keyring) {
        goto cleanup;
    }

    //= compliance/framework/aws-kms/aws-kms-mrk-aware-multi-keyrings.txt#2.5
    //# A set of AWS KMS clients MUST be created by calling regional client
    //# supplier for each region in the input set of regions.
    //
    //= compliance/framework/aws-kms/aws-kms-mrk-aware-multi-keyrings.txt#2.5
    //# Then a set of AWS KMS MRK Aware Symmetric Region Discovery Keyring
    //# (aws-kms-mrk-aware-symmetric-region-discovery-keyring.md) MUST be
    //# created for each AWS KMS client by initializing each keyring with
    for (auto region = regions.begin(); region != regions.end(); region++) {
        std::function<void()> report_success = [] {};
        const std::shared_ptr<KMS::KMSClient> kms_client =
            client_supplier_or_default->GetClient(*region, report_success);
        if (!kms_client) {
            goto cleanup;
        }
        struct aws_cryptosdk_keyring *child_keyring = Builder()
                                                          .WithKmsClient(kms_client)
                                                          .WithGrantTokens(this->grant_tokens)
                                                          .BuildDiscovery(*region, discovery_filter);
        if (!child_keyring) {
            goto cleanup;
        }
        child_keyrings.push_back(child_keyring);
        if (AWS_OP_SUCCESS != aws_cryptosdk_multi_keyring_add_child(multi_keyring, child_keyring)) {
            goto cleanup;
        }
    }

    //= compliance/framework/aws-kms/aws-kms-mrk-aware-multi-keyrings.txt#2.5
    //# This Multi-Keyring MUST be
    //# this functions output.
    return multi_keyring;

cleanup:
    for (auto child_keyring = child_keyrings.begin(); child_keyring != child_keyrings.end(); child_keyring++) {
        aws_cryptosdk_keyring_release(*child_keyring);
    }
    if (multi_keyring) {
        aws_cryptosdk_keyring_release(multi_keyring);
    }
    return nullptr;
}

}  // namespace Cryptosdk
}  // namespace Aws
