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

#include <aws/common/byte_buf.h>
#include <aws/cryptosdk/enc_ctx.h>
#include <aws/cryptosdk/private/cpputils.h>
#include <aws/cryptosdk/private/kms_keyring.h>
#include <aws/cryptosdk/private/kms_mrk_keyring.h>
#include <aws/cryptosdk/private/multi_keyring.h>

#include "edks_utils.h"
#include "kms_client_mock.h"
#include "testutil.h"

using namespace Aws::Cryptosdk;
using namespace Aws::Cryptosdk::Private;
using namespace Aws::Cryptosdk::Testing;

using namespace Aws::Cryptosdk::KmsMrkAwareSymmetricKeyring;

const char *CLASS_TAG = "KMS_MRK_UNIT_TESTS_CTAG";

struct TestValues {
    const enum aws_cryptosdk_alg_id ALG = ALG_AES256_GCM_HKDF_SHA512_COMMIT_KEY;

    struct aws_allocator *request_alloc;
    struct aws_byte_buf unencrypted_data_key;
    struct aws_array_list keyring_trace;
    struct aws_array_list edks;
    struct aws_hash_table enc_ctx;
    enum aws_cryptosdk_alg_id alg;

    const struct aws_cryptosdk_alg_properties *alg_props;
    struct aws_byte_buf ciphertext_blob;

    TestValues()
        : request_alloc(aws_default_allocator()),
          alg(ALG),
          ciphertext_blob(aws_byte_buf_from_c_str("CIPHERTEXT_BLOB")) {
        alg_props = aws_cryptosdk_alg_props(alg);
        if (!alg_props) abort();

        if (aws_byte_buf_init(&unencrypted_data_key, request_alloc, alg_props->data_key_len)) abort();
        if (!aws_byte_buf_write_u8_n(&unencrypted_data_key, 0xED, unencrypted_data_key.capacity)) abort();
        if (aws_cryptosdk_keyring_trace_init(request_alloc, &keyring_trace)) abort();
        if (aws_cryptosdk_edk_list_init(request_alloc, &edks)) abort();
        if (aws_cryptosdk_enc_ctx_init(request_alloc, &enc_ctx)) abort();
    }

    ~TestValues() {
        aws_byte_buf_clean_up(&unencrypted_data_key);
        aws_cryptosdk_keyring_trace_clean_up(&keyring_trace);
        aws_cryptosdk_edk_list_clean_up(&edks);
        aws_cryptosdk_enc_ctx_clean_up(&enc_ctx);
        aws_byte_buf_clean_up(&ciphertext_blob);
    }

    Model::EncryptRequest GetEncryptRequest(const Aws::String &key_id) {
        Model::EncryptRequest request;
        request.SetKeyId(key_id);
        request.SetPlaintext(aws_utils_byte_buffer_from_c_aws_byte_buf(&unencrypted_data_key));
        request.SetEncryptionContext(aws_map_from_c_aws_hash_table(&enc_ctx));
        return request;
    }

    Model::EncryptResult GetEncryptSuccessResult(const Aws::String &key_id) {
        Model::EncryptResult result;
        result.SetKeyId(key_id);
        result.SetCiphertextBlob(aws_utils_byte_buffer_from_c_aws_byte_buf(&ciphertext_blob));
        return result;
    }

    Model::GenerateDataKeyRequest GetGenerateDataKeyRequest(const Aws::String &key_id) {
        Model::GenerateDataKeyRequest request;
        request.SetKeyId(key_id);
        request.SetNumberOfBytes(alg_props->content_key_len);
        request.SetEncryptionContext(aws_map_from_c_aws_hash_table(&enc_ctx));
        return request;
    }

    Model::GenerateDataKeyResult GetGenerateDataKeySuccessResult(const Aws::String &key_id) {
        Model::GenerateDataKeyResult result;
        result.SetKeyId(key_id);
        result.SetCiphertextBlob(aws_utils_byte_buffer_from_c_aws_byte_buf(&ciphertext_blob));
        result.SetPlaintext(aws_utils_byte_buffer_from_c_aws_byte_buf(&unencrypted_data_key));
        return result;
    }

    Model::DecryptRequest GetDecryptRequest(const Aws::String &key_id) {
        Model::DecryptRequest request;
        request.SetKeyId(key_id);
        request.SetCiphertextBlob(aws_utils_byte_buffer_from_c_aws_byte_buf(&ciphertext_blob));
        request.SetEncryptionContext(aws_map_from_c_aws_hash_table(&enc_ctx));
        return request;
    }

    Model::DecryptResult GetDecryptSuccessResult(const Aws::String &key_id) {
        Model::DecryptResult result;
        result.SetKeyId(key_id);
        result.SetPlaintext(aws_utils_byte_buffer_from_c_aws_byte_buf(&unencrypted_data_key));
        return result;
    }

    int AddEdk(const char *provider_id, const char *provider_info) {
        auto ciphertext = aws_utils_byte_buffer_from_c_aws_byte_buf(&ciphertext_blob);
        return t_append_c_str_key_to_edks(request_alloc, &edks, &ciphertext, provider_info, provider_id);
    }
};

int strict_initialization_validInputs() {
    //= compliance/framework/aws-kms/aws-kms-mrk-aware-symmetric-keyring.txt#2.5
    //= type=test
    //# MUST implement the AWS Encryption SDK Keyring interface (../keyring-
    //# interface.md#interface)
    // (implicit)

    //= compliance/framework/aws-kms/aws-kms-mrk-aware-symmetric-keyring.txt#2.6
    //= type=test
    //# On initialization the caller MUST provide:
    // (implicit)

    //= compliance/framework/aws-kms/aws-kms-mrk-aware-symmetric-keyring.txt#2.6
    //= type=test
    //# The AWS KMS key identifier MUST NOT be null or empty.
    TEST_ASSERT(KmsMrkAwareSymmetricKeyring::Builder().Build("") == nullptr);

    //= compliance/framework/aws-kms/aws-kms-mrk-aware-symmetric-keyring.txt#2.6
    //= type=test
    //# The AWS KMS
    //# key identifier MUST be a valid identifier (aws-kms-key-arn.md#a-
    //# valid-aws-kms-identifier).
    TEST_ASSERT(KmsMrkAwareSymmetricKeyring::Builder().Build("not:an:arn") == nullptr);

    return 0;
}

int strict_onEncrypt_generateDataKey_happyPath() {
    std::shared_ptr<KmsClientMock> kms_client_mock(Aws::MakeShared<KmsClientMock>(CLASS_TAG));
    const Aws::String key_id = "arn:aws:kms:us-west-2:000011110000:key/mrk-foobar";
    const Aws::Vector<Aws::String> grant_tokens{ "grant-foo", "grant-bar" };
    auto keyring = KmsMrkAwareSymmetricKeyring::Builder()
                       .WithKmsClient(kms_client_mock)
                       .WithGrantTokens(grant_tokens)
                       .Build(key_id);
    TEST_ASSERT_ADDR_NOT_NULL(keyring);

    struct TestValues test_values;
    struct aws_byte_buf empty_unencrypted_data_key;
    aws_byte_buf_init(&empty_unencrypted_data_key, test_values.request_alloc, 0);

    //= compliance/framework/aws-kms/aws-kms-mrk-aware-symmetric-keyring.txt#2.7
    //= type=test
    //# If the input encryption materials (structures.md#encryption-
    //# materials) do not contain a plaintext data key OnEncrypt MUST attempt
    //# to generate a new plaintext data key by calling AWS KMS
    //# GenerateDataKey (https://docs.aws.amazon.com/kms/latest/APIReference/
    //# API_GenerateDataKey.html).
    //
    //= compliance/framework/aws-kms/aws-kms-mrk-aware-symmetric-keyring.txt#2.7
    //= type=test
    //# If the keyring calls AWS KMS GenerateDataKeys, it MUST use the
    //# configured AWS KMS client to make the call.
    //
    //= compliance/framework/aws-kms/aws-kms-mrk-aware-symmetric-keyring.txt#2.7
    //= type=test
    //# The keyring MUST call
    //# AWS KMS GenerateDataKeys with a request constructed as follows:
    kms_client_mock->ExpectGrantTokens(grant_tokens);
    kms_client_mock->ExpectGenerateDataKey(
        test_values.GetGenerateDataKeyRequest(key_id), test_values.GetGenerateDataKeySuccessResult(key_id));
    // also need to expect an encrypt, since it will follow a successful GenerateDataKey call
    kms_client_mock->ExpectEncryptAccumulator(
        test_values.GetEncryptRequest(key_id), test_values.GetEncryptSuccessResult(key_id));

    //= compliance/framework/aws-kms/aws-kms-mrk-aware-symmetric-keyring.txt#2.7
    //= type=test
    //# OnEncrypt MUST take encryption materials (structures.md#encryption-
    //# materials) as input.
    TEST_ASSERT_SUCCESS(aws_cryptosdk_keyring_on_encrypt(
        keyring,
        test_values.request_alloc,
        &empty_unencrypted_data_key,
        &test_values.keyring_trace,
        &test_values.edks,
        &test_values.enc_ctx,
        test_values.alg));

    //= compliance/framework/aws-kms/aws-kms-mrk-aware-symmetric-keyring.txt#2.7
    //= type=test
    //# If verified, OnEncrypt MUST do the following with the response
    //# from AWS KMS GenerateDataKey
    //# (https://docs.aws.amazon.com/kms/latest/APIReference/
    //# API_GenerateDataKey.html):
    //
    //= compliance/framework/aws-kms/aws-kms-mrk-aware-symmetric-keyring.txt#2.7
    //= type=test
    //# *  OnEncrypt MUST output the modified encryption materials
    //# (structures.md#encryption-materials)
    //
    // append a new encrypted data key (structures.md#encrypted-data-key)
    // to the encrypted data key list in the encryption materials
    // (structures.md#encryption-materials), constructed as follows:
    TEST_ASSERT_SUCCESS(t_assert_edks_with_single_element_contains_expected_values(
        &test_values.edks,
        // the ciphertext (structures.md#ciphertext) is the response
        // "CiphertextBlob".
        (const char *)test_values.ciphertext_blob.buffer,
        // the key provider information (structures.md#key-provider-
        // information) is the response "KeyId".
        key_id.c_str(),
        // The key provider id (structures.md#key-provider-id) is "aws-
        // kms".
        "aws-kms",
        test_values.request_alloc));

    // set the plaintext data key on the encryption materials
    // (structures.md#encryption-materials) as the response "Plaintext".
    TEST_ASSERT(aws_byte_buf_eq(&empty_unencrypted_data_key, &test_values.unencrypted_data_key));

    aws_byte_buf_clean_up(&empty_unencrypted_data_key);
    return 0;
}

int strict_onEncrypt_generateDataKeyCallFails() {
    std::shared_ptr<KmsClientMock> kms_client_mock(Aws::MakeShared<KmsClientMock>(CLASS_TAG));
    const Aws::String key_id = "arn:aws:kms:us-west-2:000011110000:key/mrk-foobar";
    auto keyring             = KmsMrkAwareSymmetricKeyring::Builder().WithKmsClient(kms_client_mock).Build(key_id);
    TEST_ASSERT_ADDR_NOT_NULL(keyring);

    struct TestValues test_values;
    struct aws_byte_buf empty_unencrypted_data_key;
    aws_byte_buf_init(&empty_unencrypted_data_key, test_values.request_alloc, 0);

    //= compliance/framework/aws-kms/aws-kms-mrk-aware-symmetric-keyring.txt#2.7
    //= type=test
    //# If the call to AWS KMS GenerateDataKey
    //# (https://docs.aws.amazon.com/kms/latest/APIReference/
    //# API_GenerateDataKey.html) does not succeed, OnEncrypt MUST NOT modify
    //# the encryption materials (structures.md#encryption-materials) and
    //# MUST fail.
    kms_client_mock->ExpectGenerateDataKey(test_values.GetGenerateDataKeyRequest(key_id), Aws::KMS::KMSError());
    TEST_ASSERT_ERROR(
        AWS_CRYPTOSDK_ERR_KMS_FAILURE,
        aws_cryptosdk_keyring_on_encrypt(
            keyring,
            test_values.request_alloc,
            &empty_unencrypted_data_key,
            &test_values.keyring_trace,
            &test_values.edks,
            &test_values.enc_ctx,
            test_values.alg));

    TEST_ASSERT(aws_array_list_length(&test_values.edks) == 0);
    TEST_ASSERT(aws_array_list_length(&test_values.keyring_trace) == 0);
    TEST_ASSERT(aws_byte_buf_is_valid(&empty_unencrypted_data_key));
    TEST_ASSERT(empty_unencrypted_data_key.len == 0);

    aws_byte_buf_clean_up(&empty_unencrypted_data_key);
    return 0;
}

int strict_onEncrypt_generateDataKeyResponseHasInvalidPlaintextLength() {
    std::shared_ptr<KmsClientMock> kms_client_mock(Aws::MakeShared<KmsClientMock>(CLASS_TAG));
    const Aws::String key_id = "arn:aws:kms:us-west-2:000011110000:key/mrk-foobar";
    auto keyring             = KmsMrkAwareSymmetricKeyring::Builder().WithKmsClient(kms_client_mock).Build(key_id);
    TEST_ASSERT_ADDR_NOT_NULL(keyring);

    struct TestValues test_values;
    struct aws_byte_buf empty_unencrypted_data_key;
    aws_byte_buf_init(&empty_unencrypted_data_key, test_values.request_alloc, 0);

    //= compliance/framework/aws-kms/aws-kms-mrk-aware-symmetric-keyring.txt#2.7
    //= type=test
    //# If the Generate Data Key call succeeds, OnEncrypt MUST verify that
    //# the response "Plaintext" length matches the specification of the
    //# algorithm suite (algorithm-suites.md)'s Key Derivation Input Length
    //# field.
    auto expected_request = test_values.GetGenerateDataKeyRequest(key_id);
    auto expected_result  = test_values.GetGenerateDataKeySuccessResult(key_id);
    expected_result.SetPlaintext(Aws::Utils::CryptoBuffer(1));

    kms_client_mock->ExpectGenerateDataKey(expected_request, expected_result);
    TEST_ASSERT_ERROR(
        AWS_CRYPTOSDK_ERR_KMS_FAILURE,
        aws_cryptosdk_keyring_on_encrypt(
            keyring,
            test_values.request_alloc,
            &empty_unencrypted_data_key,
            &test_values.keyring_trace,
            &test_values.edks,
            &test_values.enc_ctx,
            test_values.alg));

    aws_byte_buf_clean_up(&empty_unencrypted_data_key);
    return 0;
}

int strict_onEncrypt_generateDataKeyResponseHasInvalidKeyId() {
    std::shared_ptr<KmsClientMock> kms_client_mock(Aws::MakeShared<KmsClientMock>(CLASS_TAG));
    const Aws::String key_id = "arn:aws:kms:us-west-2:000011110000:key/mrk-foobar";
    auto keyring             = KmsMrkAwareSymmetricKeyring::Builder().WithKmsClient(kms_client_mock).Build(key_id);
    TEST_ASSERT_ADDR_NOT_NULL(keyring);

    struct TestValues test_values;
    struct aws_byte_buf empty_unencrypted_data_key;
    aws_byte_buf_init(&empty_unencrypted_data_key, test_values.request_alloc, 0);

    //= compliance/framework/aws-kms/aws-kms-mrk-aware-symmetric-keyring.txt#2.7
    //= type=test
    //# The Generate Data Key response's "KeyId" MUST be A valid AWS
    //# KMS key ARN (aws-kms-key-arn.md#identifying-an-aws-kms-multi-region-
    //# key).
    auto expected_request = test_values.GetGenerateDataKeyRequest(key_id);
    auto expected_result  = test_values.GetGenerateDataKeySuccessResult(key_id);
    expected_result.SetKeyId("not-an-arn");

    kms_client_mock->ExpectGenerateDataKey(expected_request, expected_result);
    TEST_ASSERT_ERROR(
        AWS_CRYPTOSDK_ERR_KMS_FAILURE,
        aws_cryptosdk_keyring_on_encrypt(
            keyring,
            test_values.request_alloc,
            &empty_unencrypted_data_key,
            &test_values.keyring_trace,
            &test_values.edks,
            &test_values.enc_ctx,
            test_values.alg));

    aws_byte_buf_clean_up(&empty_unencrypted_data_key);
    return 0;
}

int strict_onEncrypt_encrypt_happyPath() {
    std::shared_ptr<KmsClientMock> kms_client_mock(Aws::MakeShared<KmsClientMock>(CLASS_TAG));
    const Aws::String key_id = "arn:aws:kms:us-west-2:000011110000:key/mrk-foobar";
    const Aws::Vector<Aws::String> grant_tokens{ "grant-foo", "grant-bar" };
    auto keyring = KmsMrkAwareSymmetricKeyring::Builder()
                       .WithKmsClient(kms_client_mock)
                       .WithGrantTokens(grant_tokens)
                       .Build(key_id);
    TEST_ASSERT_ADDR_NOT_NULL(keyring);

    struct TestValues test_values;

    //= compliance/framework/aws-kms/aws-kms-mrk-aware-symmetric-keyring.txt#2.7
    //= type=test
    //# Given a plaintext data key in the encryption materials
    //# (structures.md#encryption-materials), OnEncrypt MUST attempt to
    //# encrypt the plaintext data key using the configured AWS KMS key
    //# identifier.
    //
    //= compliance/framework/aws-kms/aws-kms-mrk-aware-symmetric-keyring.txt#2.7
    //= type=test
    //# The keyring MUST call AWS KMS Encrypt
    //# (https://docs.aws.amazon.com/kms/latest/APIReference/
    //# API_Encrypt.html) using the configured AWS KMS client.
    //
    //= compliance/framework/aws-kms/aws-kms-mrk-aware-symmetric-keyring.txt#2.7
    //= type=test
    //# The keyring
    //# MUST AWS KMS Encrypt call with a request constructed as follows:
    auto expected_request = test_values.GetEncryptRequest(key_id);
    kms_client_mock->ExpectGrantTokens(grant_tokens);
    kms_client_mock->ExpectEncryptAccumulator(expected_request, test_values.GetEncryptSuccessResult(key_id));
    TEST_ASSERT_SUCCESS(aws_cryptosdk_keyring_on_encrypt(
        keyring,
        test_values.request_alloc,
        &test_values.unencrypted_data_key,
        &test_values.keyring_trace,
        &test_values.edks,
        &test_values.enc_ctx,
        test_values.alg));

    //= compliance/framework/aws-kms/aws-kms-mrk-aware-symmetric-keyring.txt#2.7
    //= type=test
    //# If verified, OnEncrypt MUST do the following with the
    //# response from AWS KMS Encrypt
    //# (https://docs.aws.amazon.com/kms/latest/APIReference/
    //# API_Encrypt.html):
    //
    //= compliance/framework/aws-kms/aws-kms-mrk-aware-symmetric-keyring.txt#2.7
    //= type=test
    //# If all Encrypt calls succeed, OnEncrypt MUST output the modified
    //# encryption materials (structures.md#encryption-materials).
    //
    // append a new encrypted data key (structures.md#encrypted-data-key)
    // to the encrypted data key list in the encryption materials
    // (structures.md#encryption-materials), constructed as follows:
    TEST_ASSERT_SUCCESS(t_assert_edks_with_single_element_contains_expected_values(
        &test_values.edks,
        // The ciphertext (structures.md#ciphertext) is the response "CiphertextBlob".
        (const char *)test_values.ciphertext_blob.buffer,
        // The key provider information (structures.md#key-provider-
        // information) is the response "KeyId".  Note that the "KeyId" in
        // the response is always in key ARN format.
        key_id.c_str(),
        // The key provider id (structures.md#key-provider-id) is "aws-
        // kms".
        "aws-kms",
        test_values.request_alloc));

    return 0;
}

int strict_onEncrypt_encryptCallFails() {
    std::shared_ptr<KmsClientMock> kms_client_mock(Aws::MakeShared<KmsClientMock>(CLASS_TAG));
    const Aws::String key_id = "arn:aws:kms:us-west-2:000011110000:key/mrk-foobar";
    auto keyring             = KmsMrkAwareSymmetricKeyring::Builder().WithKmsClient(kms_client_mock).Build(key_id);
    TEST_ASSERT_ADDR_NOT_NULL(keyring);

    struct TestValues test_values;
    auto expected_request = test_values.GetEncryptRequest(key_id);

    //= compliance/framework/aws-kms/aws-kms-mrk-aware-symmetric-keyring.txt#2.7
    //= type=test
    //# If the call to AWS KMS Encrypt
    //# (https://docs.aws.amazon.com/kms/latest/APIReference/
    //# API_Encrypt.html) does not succeed, OnEncrypt MUST fail.
    kms_client_mock->ExpectEncryptAccumulator(expected_request, Aws::KMS::KMSError());
    TEST_ASSERT_ERROR(
        AWS_CRYPTOSDK_ERR_KMS_FAILURE,
        aws_cryptosdk_keyring_on_encrypt(
            keyring,
            test_values.request_alloc,
            &test_values.unencrypted_data_key,
            &test_values.keyring_trace,
            &test_values.edks,
            &test_values.enc_ctx,
            test_values.alg));

    return 0;
}

int strict_onEncrypt_encryptResponseHasInvalidKeyId() {
    std::shared_ptr<KmsClientMock> kms_client_mock(Aws::MakeShared<KmsClientMock>(CLASS_TAG));
    const Aws::String key_id = "arn:aws:kms:us-west-2:000011110000:key/mrk-foobar";
    auto keyring             = KmsMrkAwareSymmetricKeyring::Builder().WithKmsClient(kms_client_mock).Build(key_id);
    TEST_ASSERT_ADDR_NOT_NULL(keyring);

    struct TestValues test_values;
    auto expected_request = test_values.GetEncryptRequest(key_id);

    //= compliance/framework/aws-kms/aws-kms-mrk-aware-symmetric-keyring.txt#2.7
    //= type=test
    //# If the Encrypt call succeeds The response's "KeyId" MUST be A valid
    //# AWS KMS key ARN (aws-kms-key-arn.md#identifying-an-aws-kms-multi-
    //# region-key).
    auto expected_result = test_values.GetEncryptSuccessResult(key_id);
    expected_result.SetKeyId("not-an-arn");
    kms_client_mock->ExpectEncryptAccumulator(expected_request, expected_result);
    TEST_ASSERT_ERROR(
        AWS_CRYPTOSDK_ERR_KMS_FAILURE,
        aws_cryptosdk_keyring_on_encrypt(
            keyring,
            test_values.request_alloc,
            &test_values.unencrypted_data_key,
            &test_values.keyring_trace,
            &test_values.edks,
            &test_values.enc_ctx,
            test_values.alg));

    return 0;
}

int strict_onDecrypt_happyPath() {
    static const char *key1              = "arn:aws:kms:us-west-2:000011110000:key/mrk-foobar";
    static const char *key1_alias_type   = "arn:aws:kms:us-west-2:000011110000:alias/mrk-foobar";
    static const char *key1_other_region = "arn:aws:kms:eu-central-1:000011110000:key/mrk-foobar";
    static const char *key2              = "arn:aws:kms:eu-central-1:000011110000:key/mrk-baz";

    std::shared_ptr<KmsClientMock> kms_client_mock(Aws::MakeShared<KmsClientMock>(CLASS_TAG));
    const Aws::Vector<Aws::String> grant_tokens{ "grant-foo", "grant-bar" };
    auto keyring =
        KmsMrkAwareSymmetricKeyring::Builder().WithKmsClient(kms_client_mock).WithGrantTokens(grant_tokens).Build(key1);
    TEST_ASSERT_ADDR_NOT_NULL(keyring);

    struct TestValues test_values;
    struct aws_byte_buf output_unencrypted_data_key;
    aws_byte_buf_init(&output_unencrypted_data_key, test_values.request_alloc, 0);

    // We expect these two EDKs to pass the filter, but the rest should fail to
    // meet one of the EDK-matching requirements.
    TEST_ASSERT_SUCCESS(test_values.AddEdk("aws-kms", key1));
    TEST_ASSERT_SUCCESS(test_values.AddEdk("aws-kms", key1_other_region));
    //= compliance/framework/aws-kms/aws-kms-mrk-aware-symmetric-keyring.txt#2.8
    //= type=test
    //# *  Its provider ID MUST exactly match the value "aws-kms".
    TEST_ASSERT_SUCCESS(test_values.AddEdk("NOT-kms", key1));
    //= compliance/framework/aws-kms/aws-kms-mrk-aware-symmetric-keyring.txt#2.8
    //= type=test
    //# *  The provider info MUST be a valid AWS KMS ARN (aws-kms-key-
    //# arn.md#a-valid-aws-kms-arn) with a resource type of "key" or
    //# OnDecrypt MUST fail.
    TEST_ASSERT_SUCCESS(test_values.AddEdk("aws-kms", key1_alias_type));
    //= compliance/framework/aws-kms/aws-kms-mrk-aware-symmetric-keyring.txt#2.8
    //= type=test
    //# *  The the function AWS KMS MRK Match for Decrypt (aws-kms-mrk-match-
    //# for-decrypt.md#implementation) called with the configured AWS KMS
    //# key identifier and the provider info MUST return "true".
    TEST_ASSERT_SUCCESS(test_values.AddEdk("aws-kms", key2));

    //= compliance/framework/aws-kms/aws-kms-mrk-aware-symmetric-keyring.txt#2.8
    //= type=test
    //# The set of encrypted data keys MUST first be filtered to match this
    //# keyring's configuration.
    //
    //= compliance/framework/aws-kms/aws-kms-mrk-aware-symmetric-keyring.txt#2.8
    //= type=test
    //# For each encrypted data key in the filtered set, one at a time, the
    //# OnDecrypt MUST attempt to decrypt the data key.
    //
    //= compliance/framework/aws-kms/aws-kms-mrk-aware-symmetric-keyring.txt#2.8
    //= type=test
    //# To attempt to decrypt a particular encrypted data key
    //# (structures.md#encrypted-data-key), OnDecrypt MUST call AWS KMS
    //# Decrypt (https://docs.aws.amazon.com/kms/latest/APIReference/
    //# API_Decrypt.html) with the configured AWS KMS client.
    //
    //= compliance/framework/aws-kms/aws-kms-mrk-aware-symmetric-keyring.txt#2.8
    //= type=test
    //# When calling AWS KMS Decrypt
    //# (https://docs.aws.amazon.com/kms/latest/APIReference/
    //# API_Decrypt.html), the keyring MUST call with a request constructed
    //# as follows:
    kms_client_mock->ExpectDecryptAccumulator(test_values.GetDecryptRequest(key1), Aws::KMS::KMSError());
    kms_client_mock->ExpectDecryptAccumulator(
        test_values.GetDecryptRequest(key1), test_values.GetDecryptSuccessResult(key1));

    kms_client_mock->ExpectGrantTokens(grant_tokens);

    TEST_ASSERT_SUCCESS(aws_cryptosdk_keyring_on_decrypt(
        keyring,
        test_values.request_alloc,
        &output_unencrypted_data_key,
        &test_values.keyring_trace,
        &test_values.edks,
        &test_values.enc_ctx,
        test_values.alg));

    //= compliance/framework/aws-kms/aws-kms-mrk-aware-symmetric-keyring.txt#2.8
    //= type=test
    //# If the response does satisfies these requirements then OnDecrypt MUST
    //# do the following with the response:
    TEST_ASSERT(aws_byte_buf_eq(&output_unencrypted_data_key, &test_values.unencrypted_data_key));

    return 0;
}

int strict_onDecrypt_materialsAlreadyContainsPlaintextDataKey() {
    std::shared_ptr<KmsClientMock> kms_client_mock(Aws::MakeShared<KmsClientMock>(CLASS_TAG));
    const Aws::String key_id = "arn:aws:kms:us-west-2:000011110000:key/mrk-foobar";
    auto keyring             = KmsMrkAwareSymmetricKeyring::Builder().WithKmsClient(kms_client_mock).Build(key_id);
    TEST_ASSERT_ADDR_NOT_NULL(keyring);

    //= compliance/framework/aws-kms/aws-kms-mrk-aware-symmetric-keyring.txt#2.8
    //= type=test
    //# OnDecrypt MUST take decryption materials (structures.md#decryption-
    //# materials) and a list of encrypted data keys
    //# (structures.md#encrypted-data-key) as input.
    //
    //= compliance/framework/aws-kms/aws-kms-mrk-aware-symmetric-keyring.txt#2.8
    //= type=test
    //# If the decryption materials (structures.md#decryption-materials)
    //# already contained a valid plaintext data key OnDecrypt MUST
    //# immediately return the unmodified decryption materials
    //# (structures.md#decryption-materials).
    struct TestValues test_values;
    struct aws_byte_buf unencrypted_data_key_copy;
    aws_byte_buf_init_copy(&unencrypted_data_key_copy, test_values.request_alloc, &test_values.unencrypted_data_key);
    TEST_ASSERT_ERROR(
        AWS_CRYPTOSDK_ERR_BAD_STATE,
        aws_cryptosdk_keyring_on_decrypt(
            keyring,
            test_values.request_alloc,
            &test_values.unencrypted_data_key,
            &test_values.keyring_trace,
            &test_values.edks,
            &test_values.enc_ctx,
            test_values.alg));
    TEST_ASSERT(aws_byte_buf_eq(&unencrypted_data_key_copy, &test_values.unencrypted_data_key));

    return 0;
}

int strict_onDecrypt_decryptResponseIsInvalid() {
    std::shared_ptr<KmsClientMock> kms_client_mock(Aws::MakeShared<KmsClientMock>(CLASS_TAG));
    const char *key_id = "arn:aws:kms:us-west-2:000011110000:key/mrk-foobar";
    auto keyring       = KmsMrkAwareSymmetricKeyring::Builder().WithKmsClient(kms_client_mock).Build(key_id);
    TEST_ASSERT_ADDR_NOT_NULL(keyring);

    struct TestValues test_values;
    struct aws_byte_buf output_unencrypted_data_key;
    aws_byte_buf_init(&output_unencrypted_data_key, test_values.request_alloc, 0);

    TEST_ASSERT_SUCCESS(test_values.AddEdk("aws-kms", key_id));
    TEST_ASSERT_SUCCESS(test_values.AddEdk("aws-kms", key_id));
    TEST_ASSERT_SUCCESS(test_values.AddEdk("aws-kms", key_id));

    //= compliance/framework/aws-kms/aws-kms-mrk-aware-symmetric-keyring.txt#2.8
    //= type=test
    //# *  The "KeyId" field in the response MUST equal the configured AWS
    //# KMS key identifier.
    kms_client_mock->ExpectDecryptAccumulator(
        test_values.GetDecryptRequest(key_id), test_values.GetDecryptSuccessResult(key_id).WithKeyId("wrong-key-id"));

    //= compliance/framework/aws-kms/aws-kms-mrk-aware-symmetric-keyring.txt#2.8
    //= type=test
    //# *  The length of the response's "Plaintext" MUST equal the key
    //# derivation input length (algorithm-suites.md#key-derivation-input-
    //# length) specified by the algorithm suite (algorithm-suites.md)
    //# included in the input decryption materials
    //# (structures.md#decryption-materials).
    kms_client_mock->ExpectDecryptAccumulator(
        test_values.GetDecryptRequest(key_id),
        test_values.GetDecryptSuccessResult(key_id).WithPlaintext(Aws::Utils::CryptoBuffer(1)));

    kms_client_mock->ExpectDecryptAccumulator(test_values.GetDecryptRequest(key_id), Aws::KMS::KMSError());

    //= compliance/framework/aws-kms/aws-kms-mrk-aware-symmetric-keyring.txt#2.8
    //= type=test
    //# If the response does not satisfies these requirements then an error
    //# MUST be collected and the next encrypted data key in the filtered set
    //# MUST be attempted.
    //
    //= compliance/framework/aws-kms/aws-kms-mrk-aware-symmetric-keyring.txt#2.8
    //= type=test
    //# If this attempt
    //# results in an error, then these errors MUST be collected.
    //
    //= compliance/framework/aws-kms/aws-kms-mrk-aware-symmetric-keyring.txt#2.8
    //= type=test
    //# If OnDecrypt fails to successfully decrypt any encrypted data key
    //# (structures.md#encrypted-data-key), then it MUST yield an error that
    //# includes all the collected errors.
    TEST_ASSERT_ERROR(
        AWS_CRYPTOSDK_ERR_KMS_FAILURE,
        aws_cryptosdk_keyring_on_decrypt(
            keyring,
            test_values.request_alloc,
            &output_unencrypted_data_key,
            &test_values.keyring_trace,
            &test_values.edks,
            &test_values.enc_ctx,
            test_values.alg));

    TEST_ASSERT(output_unencrypted_data_key.len == 0);

    return 0;
}

int discovery_initialization_validInputs() {
    //= compliance/framework/aws-kms/aws-kms-mrk-aware-symmetric-region-discovery-keyring.txt#2.5
    //= type=test
    //# MUST implement that AWS Encryption SDK Keyring interface (../keyring-
    //# interface.md#interface)
    // (implicit)

    //= compliance/framework/aws-kms/aws-kms-mrk-aware-symmetric-region-discovery-keyring.txt#2.6
    //= type=test
    //# On initialization the caller MUST provide:
    // (implicit)

    //= compliance/framework/aws-kms/aws-kms-mrk-aware-symmetric-region-discovery-keyring.txt#2.6
    //= type=test
    //# The keyring MUST know what Region the AWS KMS client is in.
    //
    //= compliance/framework/aws-kms/aws-kms-mrk-aware-symmetric-region-discovery-keyring.txt#2.6
    //= type=test
    //# It SHOULD have a Region parameter and
    //# SHOULD try to identify mismatched configurations.
    //
    // note - we cannot access a KMS client's configured region, and therefore
    // cannot identify mismatched configurations
    std::shared_ptr<Aws::KMS::KMSClient> kms_client_mock(Aws::MakeShared<KmsClientMock>(CLASS_TAG));
    TEST_ASSERT_ADDR_NOT_NULL(
        KmsMrkAwareSymmetricKeyring::Builder().WithKmsClient(kms_client_mock).BuildDiscovery("us-west-2"));

    return 0;
}

int discovery_onEncrypt_happyPath() {
    std::shared_ptr<Aws::KMS::KMSClient> kms_client_mock(Aws::MakeShared<KmsClientMock>(CLASS_TAG));
    auto keyring = KmsMrkAwareSymmetricKeyring::Builder().WithKmsClient(kms_client_mock).BuildDiscovery("us-west-2");
    TEST_ASSERT_ADDR_NOT_NULL(keyring);

    //= compliance/framework/aws-kms/aws-kms-mrk-aware-symmetric-region-discovery-keyring.txt#2.7
    //= type=test
    //# This function MUST fail.
    struct TestValues test_values;
    TEST_ASSERT_ERROR(
        AWS_CRYPTOSDK_ERR_BAD_STATE,
        aws_cryptosdk_keyring_on_encrypt(
            keyring,
            test_values.request_alloc,
            &test_values.unencrypted_data_key,
            &test_values.keyring_trace,
            &test_values.edks,
            &test_values.enc_ctx,
            test_values.alg));

    return 0;
}

int discovery_onDecrypt_happyPath() {
    std::shared_ptr<KmsClientMock> kms_client_mock(Aws::MakeShared<KmsClientMock>(CLASS_TAG));
    const Aws::Vector<Aws::String> grant_tokens{ "grant-foo", "grant-bar" };
    auto discovery_filter = KmsKeyring::DiscoveryFilter::Builder("aws").AddAccount("000011110000").Build();
    auto keyring          = KmsMrkAwareSymmetricKeyring::Builder()
                       .WithKmsClient(kms_client_mock)
                       .WithGrantTokens(grant_tokens)
                       .BuildDiscovery("us-west-2", discovery_filter);
    TEST_ASSERT_ADDR_NOT_NULL(keyring);

    static const char *key1                     = "arn:aws:kms:us-west-2:000011110000:key/mrk-foobar";
    static const char *key1_alias_type          = "arn:aws:kms:us-west-2:000011110000:alias/mrk-foobar";
    static const char *key1_not_arn             = "alias/foobar";
    static const char *key1_other_partition     = "arn:NOT-aws:kms:us-west-2:000011110000:key/mrk-foobar";
    static const char *key1_other_account       = "arn:aws:kms:us-west-2:999999999999:key/mrk-foobar";
    static const char *key2                     = "arn:aws:kms:eu-central-1:000011110000:key/mrk-baz";
    static const char *key2_in_local_region     = "arn:aws:kms:us-west-2:000011110000:key/mrk-baz";
    static const char *srk_outside_local_region = "arn:aws:kms:eu-central-2:000011110000:key/NOT-mrk";

    struct TestValues test_values;
    struct aws_byte_buf output_unencrypted_data_key;
    aws_byte_buf_init(&output_unencrypted_data_key, test_values.request_alloc, 0);

    // We expect these two EDKs to pass the filter, but the rest should fail to
    // meet one of the EDK-matching requirements.
    TEST_ASSERT_SUCCESS(test_values.AddEdk("aws-kms", key1));
    TEST_ASSERT_SUCCESS(test_values.AddEdk("aws-kms", key2));
    //= compliance/framework/aws-kms/aws-kms-mrk-aware-symmetric-region-discovery-keyring.txt#2.8
    //= type=test
    //# *  Its provider ID MUST exactly match the value "aws-kms".
    TEST_ASSERT_SUCCESS(test_values.AddEdk("NOT-kms", key1));
    //= compliance/framework/aws-kms/aws-kms-mrk-aware-symmetric-region-discovery-keyring.txt#2.8
    //= type=test
    //# *  The provider info MUST be a valid AWS KMS ARN (aws-kms-key-
    //# arn.md#a-valid-aws-kms-arn) with a resource type of "key" or
    //# OnDecrypt MUST fail.
    TEST_ASSERT_SUCCESS(test_values.AddEdk("aws-kms", key1_alias_type));
    // Precondition: The provider info MUST be a well formed AWS KMS ARN.
    TEST_ASSERT_SUCCESS(test_values.AddEdk("aws-kms", key1_not_arn));
    //= compliance/framework/aws-kms/aws-kms-mrk-aware-symmetric-region-discovery-keyring.txt#2.8
    //= type=test
    //# *  If a discovery filter is configured, its partition and the
    //# provider info partition MUST match.
    TEST_ASSERT_SUCCESS(test_values.AddEdk("aws-kms", key1_other_partition));
    //= compliance/framework/aws-kms/aws-kms-mrk-aware-symmetric-region-discovery-keyring.txt#2.8
    //= type=test
    //# *  If a discovery filter is configured, its set of accounts MUST
    //# contain the provider info account.
    TEST_ASSERT_SUCCESS(test_values.AddEdk("aws-kms", key1_other_account));
    //= compliance/framework/aws-kms/aws-kms-mrk-aware-symmetric-region-discovery-keyring.txt#2.8
    //= type=test
    //# *  If the provider info is not identified as a multi-Region key (aws-
    //# kms-key-arn.md#identifying-an-aws-kms-multi-region-key), then the
    //# provider info's Region MUST match the AWS KMS client region.
    TEST_ASSERT_SUCCESS(test_values.AddEdk("aws-kms", srk_outside_local_region));

    //= compliance/framework/aws-kms/aws-kms-mrk-aware-symmetric-region-discovery-keyring.txt#2.8
    //= type=test
    //# The set of encrypted data keys MUST first be filtered to match this
    //# keyring's configuration.
    //
    //= compliance/framework/aws-kms/aws-kms-mrk-aware-symmetric-region-discovery-keyring.txt#2.8
    //= type=test
    //# For each encrypted data key in the filtered set, one at a time, the
    //# OnDecrypt MUST attempt to decrypt the data key.
    //
    //= compliance/framework/aws-kms/aws-kms-mrk-aware-symmetric-region-discovery-keyring.txt#2.8
    //= type=test
    //# To attempt to decrypt a particular encrypted data key
    //# (structures.md#encrypted-data-key), OnDecrypt MUST call AWS KMS
    //# Decrypt (https://docs.aws.amazon.com/kms/latest/APIReference/
    //# API_Decrypt.html) with the configured AWS KMS client.
    //
    //= compliance/framework/aws-kms/aws-kms-mrk-aware-symmetric-region-discovery-keyring.txt#2.8
    //= type=test
    //# When calling AWS KMS Decrypt
    //# (https://docs.aws.amazon.com/kms/latest/APIReference/
    //# API_Decrypt.html), the keyring MUST call with a request constructed
    //# as follows:
    //
    //= compliance/framework/aws-kms/aws-kms-mrk-aware-symmetric-region-discovery-keyring.txt#2.8
    //= type=test
    //# *  "KeyId": If the provider info's resource type is "key" and its
    //# resource is a multi-Region key then a new ARN MUST be created
    //# where the region part MUST equal the AWS KMS client region and
    //# every other part MUST equal the provider info.
    kms_client_mock->ExpectDecryptAccumulator(test_values.GetDecryptRequest(key1), Aws::KMS::KMSError());
    //= compliance/framework/aws-kms/aws-kms-mrk-aware-symmetric-region-discovery-keyring.txt#2.8
    //= type=test
    //# Otherwise it MUST
    //# be the provider info.
    kms_client_mock->ExpectDecryptAccumulator(
        test_values.GetDecryptRequest(key2_in_local_region), test_values.GetDecryptSuccessResult(key2_in_local_region));

    kms_client_mock->ExpectGrantTokens(grant_tokens);

    TEST_ASSERT_SUCCESS(aws_cryptosdk_keyring_on_decrypt(
        keyring,
        test_values.request_alloc,
        &output_unencrypted_data_key,
        &test_values.keyring_trace,
        &test_values.edks,
        &test_values.enc_ctx,
        test_values.alg));

    //= compliance/framework/aws-kms/aws-kms-mrk-aware-symmetric-region-discovery-keyring.txt#2.8
    //= type=test
    //# Since the response does satisfies these requirements then OnDecrypt
    //# MUST do the following with the response:
    TEST_ASSERT(aws_byte_buf_eq(&output_unencrypted_data_key, &test_values.unencrypted_data_key));

    return 0;
}

int discovery_onDecrypt_materialsAlreadyContainsPlaintextDataKey() {
    std::shared_ptr<Aws::KMS::KMSClient> kms_client_mock(Aws::MakeShared<KmsClientMock>(CLASS_TAG));
    auto keyring = KmsMrkAwareSymmetricKeyring::Builder().WithKmsClient(kms_client_mock).BuildDiscovery("us-west-2");
    TEST_ASSERT_ADDR_NOT_NULL(keyring);

    //= compliance/framework/aws-kms/aws-kms-mrk-aware-symmetric-region-discovery-keyring.txt#2.8
    //= type=test
    //# OnDecrypt MUST take decryption materials (structures.md#decryption-
    //# materials) and a list of encrypted data keys
    //# (structures.md#encrypted-data-key) as input.
    //
    //= compliance/framework/aws-kms/aws-kms-mrk-aware-symmetric-region-discovery-keyring.txt#2.8
    //= type=test
    //# If the decryption materials (structures.md#decryption-materials)
    //# already contained a valid plaintext data key OnDecrypt MUST
    //# immediately return the unmodified decryption materials
    //# (structures.md#decryption-materials).
    struct TestValues test_values;
    struct aws_byte_buf unencrypted_data_key_copy;
    aws_byte_buf_init_copy(&unencrypted_data_key_copy, test_values.request_alloc, &test_values.unencrypted_data_key);
    TEST_ASSERT_ERROR(
        AWS_CRYPTOSDK_ERR_BAD_STATE,
        aws_cryptosdk_keyring_on_decrypt(
            keyring,
            test_values.request_alloc,
            &test_values.unencrypted_data_key,
            &test_values.keyring_trace,
            &test_values.edks,
            &test_values.enc_ctx,
            test_values.alg));
    TEST_ASSERT(aws_byte_buf_eq(&unencrypted_data_key_copy, &test_values.unencrypted_data_key));

    return 0;
}

int discovery_onDecrypt_decryptResponseIsInvalid() {
    std::shared_ptr<KmsClientMock> kms_client_mock(Aws::MakeShared<KmsClientMock>(CLASS_TAG));
    auto keyring = KmsMrkAwareSymmetricKeyring::Builder().WithKmsClient(kms_client_mock).BuildDiscovery("us-west-2");
    TEST_ASSERT_ADDR_NOT_NULL(keyring);

    struct TestValues test_values;
    struct aws_byte_buf output_unencrypted_data_key;
    aws_byte_buf_init(&output_unencrypted_data_key, test_values.request_alloc, 0);

    static const char *key1 = "arn:aws:kms:us-west-2:000011110000:key/mrk-foo";
    static const char *key2 = "arn:aws:kms:us-west-2:000011110000:key/mrk-bar";

    TEST_ASSERT_SUCCESS(test_values.AddEdk("aws-kms", key1));
    TEST_ASSERT_SUCCESS(test_values.AddEdk("aws-kms", key2));

    //= compliance/framework/aws-kms/aws-kms-mrk-aware-symmetric-region-discovery-keyring.txt#2.8
    //= type=test
    //# *  The "KeyId" field in the response MUST equal the requested "KeyId"
    kms_client_mock->ExpectDecryptAccumulator(
        test_values.GetDecryptRequest(key1), test_values.GetDecryptSuccessResult(key1).WithKeyId("wrong-key-id"));

    //= compliance/framework/aws-kms/aws-kms-mrk-aware-symmetric-region-discovery-keyring.txt#2.8
    //= type=test
    //# *  The length of the response's "Plaintext" MUST equal the key
    //# derivation input length (algorithm-suites.md#key-derivation-input-
    //# length) specified by the algorithm suite (algorithm-suites.md)
    //# included in the input decryption materials
    //# (structures.md#decryption-materials).
    kms_client_mock->ExpectDecryptAccumulator(
        test_values.GetDecryptRequest(key2),
        test_values.GetDecryptSuccessResult(key2).WithPlaintext(Aws::Utils::CryptoBuffer(1)));

    //= compliance/framework/aws-kms/aws-kms-mrk-aware-symmetric-region-discovery-keyring.txt#2.8
    //= type=test
    //# If the response does not satisfies these requirements then an error
    //# is collected and the next encrypted data key in the filtered set MUST
    //# be attempted.
    //
    //= compliance/framework/aws-kms/aws-kms-mrk-aware-symmetric-region-discovery-keyring.txt#2.8
    //= type=test
    //# If OnDecrypt fails to successfully decrypt any encrypted data key
    //# (structures.md#encrypted-data-key), then it MUST yield an error that
    //# includes all collected errors.
    TEST_ASSERT_ERROR(
        AWS_CRYPTOSDK_ERR_KMS_FAILURE,
        aws_cryptosdk_keyring_on_decrypt(
            keyring,
            test_values.request_alloc,
            &output_unencrypted_data_key,
            &test_values.keyring_trace,
            &test_values.edks,
            &test_values.enc_ctx,
            test_values.alg));

    TEST_ASSERT(output_unencrypted_data_key.len == 0);

    return 0;
}

int strict_multiKeyring_happyPath() {
    //= compliance/framework/aws-kms/aws-kms-mrk-aware-multi-keyrings.txt#2.6
    //= type=test
    //# The caller MUST provide:
    //
    //= compliance/framework/aws-kms/aws-kms-mrk-aware-multi-keyrings.txt#2.6
    //= type=test
    //# If any of the AWS KMS key identifiers is null or an empty string this
    //# function MUST fail.
    TEST_ASSERT_ADDR_NULL(KmsMrkAwareSymmetricKeyring::MultiKeyringBuilder().Build("key-1", { "extra-key-1", "" }));
    TEST_ASSERT_ADDR_NULL(
        KmsMrkAwareSymmetricKeyring::MultiKeyringBuilder().Build("", { "extra-key-1", "extra-key-2" }));

    //= compliance/framework/aws-kms/aws-kms-mrk-aware-multi-keyrings.txt#2.6
    //= type=test
    //# At least one non-null or non-empty string AWS
    //# KMS key identifiers exists in the input this function MUST fail.
    TEST_ASSERT_ADDR_NULL(KmsMrkAwareSymmetricKeyring::MultiKeyringBuilder().Build());

    //= compliance/framework/aws-kms/aws-kms-mrk-aware-multi-keyrings.txt#2.6
    //= type=test
    //# All
    //# AWS KMS identifiers are passed to Assert AWS KMS MRK are unique (aws-
    //# kms-mrk-are-unique.md#Implementation) and the function MUST return
    //# success otherwise this MUST fail.
    TEST_ASSERT_ADDR_NULL(KmsMrkAwareSymmetricKeyring::MultiKeyringBuilder().Build(
        "mrk-foobar", { "arn:aws:kms:us-west-2:000011110000:key/mrk-foobar" }));

    //= compliance/framework/aws-kms/aws-kms-mrk-aware-multi-keyrings.txt#2.6
    //= type=test
    //# If a regional client supplier is
    //# not passed, then a default MUST be created that takes a region string
    //# and generates a default AWS SDK client for the given region.
    TEST_ASSERT_ADDR_NOT_NULL(KmsMrkAwareSymmetricKeyring::MultiKeyringBuilder().Build("mrk-foobar"));

    //= compliance/framework/aws-kms/aws-kms-mrk-aware-multi-keyrings.txt#2.6
    //= type=test
    //# NOTE: The AWS Encryption SDK SHOULD NOT attempt to evaluate its own
    //# default region.
    // (implicit)

    //= compliance/framework/aws-kms/aws-kms-mrk-aware-multi-keyrings.txt#2.6
    //= type=test
    //# This Multi-
    //# Keyring MUST be this functions output.
    auto client_supplier_mock(Aws::MakeShared<KmsClientSupplierMock>(CLASS_TAG));
    const Aws::Vector<Aws::String> grant_tokens{ "grant-foo", "grant-bar" };
    struct aws_cryptosdk_keyring *keyring = KmsMrkAwareSymmetricKeyring::MultiKeyringBuilder()
                                                .WithClientSupplier(client_supplier_mock)
                                                .WithGrantTokens(grant_tokens)
                                                .Build(
                                                    "mrk-generator",
                                                    { "arn:aws:kms:us-west-2:000011110000:key/mrk-child-1",
                                                      "arn:aws:kms:eu-central-1:000011110000:key/mrk-child-2" });
    TEST_ASSERT_ADDR_NOT_NULL(keyring);

    //= compliance/framework/aws-kms/aws-kms-mrk-aware-multi-keyrings.txt#2.6
    //= type=test
    //# Then a Multi-Keyring (../multi-keyring.md#inputs) MUST be initialize
    //# by using this generator keyring as the generator keyring (../multi-
    //# keyring.md#generator-keyring) and this set of child keyrings as the
    //# child keyrings (../multi-keyring.md#child-keyrings).
    auto generator_keyring = (KmsMrkAwareSymmetricKeyringImpl *)((struct multi_keyring *)keyring)->generator;
    TEST_ASSERT_ADDR_NOT_NULL(generator_keyring);
    struct aws_array_list *child_keyrings = &((struct multi_keyring *)keyring)->children;
    KmsMrkAwareSymmetricKeyringImpl *child_keyring_us;
    KmsMrkAwareSymmetricKeyringImpl *child_keyring_eu;
    TEST_ASSERT_SUCCESS(aws_array_list_get_at(child_keyrings, (void *)&child_keyring_us, 0));
    TEST_ASSERT_SUCCESS(aws_array_list_get_at(child_keyrings, (void *)&child_keyring_eu, 1));
    TEST_ASSERT_ADDR_NOT_NULL(child_keyring_us);
    TEST_ASSERT_ADDR_NOT_NULL(child_keyring_eu);

    //= compliance/framework/aws-kms/aws-kms-mrk-aware-multi-keyrings.txt#2.6
    //= type=test
    //# If there is a generator input then the generator keyring MUST be a
    //# AWS KMS MRK Aware Symmetric Keyring (aws-kms-mrk-aware-symmetric-
    //# keyring.md) initialized with
    TEST_ASSERT(generator_keyring->key_id == "mrk-generator");
    TEST_ASSERT(generator_keyring->grant_tokens == grant_tokens);
    //= compliance/framework/aws-kms/aws-kms-mrk-aware-multi-keyrings.txt#2.6
    //= type=test
    //# *  The AWS KMS client that MUST be created by the regional client
    //# supplier when called with the region part of the generator ARN or
    //# a signal for the AWS SDK to select the default region.
    TEST_ASSERT((bool)client_supplier_mock->GetClientMock(""));

    //= compliance/framework/aws-kms/aws-kms-mrk-aware-multi-keyrings.txt#2.6
    //= type=test
    //# If there is a set of child identifiers then a set of AWS KMS MRK
    //# Aware Symmetric Keyring (aws-kms-mrk-aware-symmetric-keyring.md) MUST
    //# be created for each AWS KMS key identifier by initialized each
    //# keyring with
    TEST_ASSERT(child_keyring_us->key_id == "arn:aws:kms:us-west-2:000011110000:key/mrk-child-1");
    TEST_ASSERT(child_keyring_us->grant_tokens == grant_tokens);
    TEST_ASSERT(child_keyring_eu->key_id == "arn:aws:kms:eu-central-1:000011110000:key/mrk-child-2");
    TEST_ASSERT(child_keyring_eu->grant_tokens == grant_tokens);
    //= compliance/framework/aws-kms/aws-kms-mrk-aware-multi-keyrings.txt#2.6
    //= type=test
    //# *  The AWS KMS client that MUST be created by the regional client
    //# supplier when called with the region part of the AWS KMS key
    //# identifier or a signal for the AWS SDK to select the default
    //# region.
    TEST_ASSERT((bool)client_supplier_mock->GetClientMock("us-west-2"));
    TEST_ASSERT((bool)client_supplier_mock->GetClientMock("eu-central-1"));

    return 0;
}

int discovery_multiKeyring_happyPath() {
    auto client_supplier_mock(Aws::MakeShared<KmsClientSupplierMock>(CLASS_TAG));

    //= compliance/framework/aws-kms/aws-kms-mrk-aware-multi-keyrings.txt#2.5
    //= type=test
    //# The caller MUST provide:
    //
    //= compliance/framework/aws-kms/aws-kms-mrk-aware-multi-keyrings.txt#2.5
    //= type=test
    //# If an empty set of Region is provided this function MUST fail.
    TEST_ASSERT_ADDR_NULL(
        KmsMrkAwareSymmetricKeyring::MultiKeyringBuilder().WithClientSupplier(client_supplier_mock).BuildDiscovery({}));

    //= compliance/framework/aws-kms/aws-kms-mrk-aware-multi-keyrings.txt#2.5
    //= type=test
    //# If
    //# any element of the set of regions is null or an empty string this
    //# function MUST fail.
    TEST_ASSERT_ADDR_NULL(KmsMrkAwareSymmetricKeyring::MultiKeyringBuilder()
                              .WithClientSupplier(client_supplier_mock)
                              .BuildDiscovery({ "us-west-2", "", "eu-central-1" }));

    //= compliance/framework/aws-kms/aws-kms-mrk-aware-multi-keyrings.txt#2.5
    //= type=test
    //# If a regional client supplier is not passed,
    //# then a default MUST be created that takes a region string and
    //# generates a default AWS SDK client for the given region.
    TEST_ASSERT_ADDR_NOT_NULL(
        KmsMrkAwareSymmetricKeyring::MultiKeyringBuilder().BuildDiscovery({ "us-west-2", "eu-central-1" }));

    const Aws::Vector<Aws::String> grant_tokens{ "grant-foo", "grant-bar" };
    const auto discovery_filter = Aws::Cryptosdk::KmsKeyring::DiscoveryFilterBuilder("aws")
                                      .WithAccounts({ "000011110000", "111122221111" })
                                      .Build();

    //= compliance/framework/aws-kms/aws-kms-mrk-aware-multi-keyrings.txt#2.5
    //= type=test
    //# This Multi-Keyring MUST be
    //# this functions output.
    struct aws_cryptosdk_keyring *keyring = KmsMrkAwareSymmetricKeyring::MultiKeyringBuilder()
                                                .WithClientSupplier(client_supplier_mock)
                                                .WithGrantTokens(grant_tokens)
                                                .BuildDiscovery({ "us-west-2", "eu-central-1" }, discovery_filter);
    TEST_ASSERT_ADDR_NOT_NULL(keyring);

    //= compliance/framework/aws-kms/aws-kms-mrk-aware-multi-keyrings.txt#2.5
    //= type=test
    //# A set of AWS KMS clients MUST be created by calling regional client
    //# supplier for each region in the input set of regions.
    TEST_ASSERT(client_supplier_mock->GetClientMocksMap().size() == 2);
    TEST_ASSERT((bool)client_supplier_mock->GetClientMock("us-west-2"));
    TEST_ASSERT((bool)client_supplier_mock->GetClientMock("eu-central-1"));

    //= compliance/framework/aws-kms/aws-kms-mrk-aware-multi-keyrings.txt#2.5
    //= type=test
    //# Then a set of AWS KMS MRK Aware Symmetric Region Discovery Keyring
    //# (aws-kms-mrk-aware-symmetric-region-discovery-keyring.md) MUST be
    //# created for each AWS KMS client by initializing each keyring with
    //
    //= compliance/framework/aws-kms/aws-kms-mrk-aware-multi-keyrings.txt#2.5
    //= type=test
    //# Then a Multi-Keyring (../multi-keyring.md#inputs) MUST be initialize
    //# by using this set of discovery keyrings as the child keyrings
    //# (../multi-keyring.md#child-keyrings).
    struct aws_array_list *child_keyrings = &((struct multi_keyring *)keyring)->children;
    TEST_ASSERT(aws_array_list_length(child_keyrings) == 2);
    KmsMrkAwareSymmetricKeyringImpl *child_keyring_us;
    KmsMrkAwareSymmetricKeyringImpl *child_keyring_eu;
    TEST_ASSERT_SUCCESS(aws_array_list_get_at(child_keyrings, (void *)&child_keyring_us, 0));
    TEST_ASSERT_SUCCESS(aws_array_list_get_at(child_keyrings, (void *)&child_keyring_eu, 1));
    if (child_keyring_us->region.compare("us-west-2") != 0) {
        std::swap(child_keyring_us, child_keyring_eu);
    }

    TEST_ASSERT(child_keyring_us->region.compare("us-west-2") == 0);
    TEST_ASSERT(child_keyring_us->discovery_filter == discovery_filter);
    TEST_ASSERT(child_keyring_us->grant_tokens == grant_tokens);
    TEST_ASSERT(child_keyring_eu->region.compare("eu-central-1") == 0);
    TEST_ASSERT(child_keyring_eu->discovery_filter == discovery_filter);
    TEST_ASSERT(child_keyring_eu->grant_tokens == grant_tokens);

    aws_cryptosdk_keyring_release(keyring);

    return 0;
}

int main() {
    Aws::SDKOptions *options = Aws::New<Aws::SDKOptions>(CLASS_TAG);
    Aws::InitAPI(*options);

    aws_cryptosdk_load_error_strings();

    RUN_TEST(strict_initialization_validInputs());
    RUN_TEST(strict_onEncrypt_generateDataKey_happyPath());
    RUN_TEST(strict_onEncrypt_generateDataKeyCallFails());
    RUN_TEST(strict_onEncrypt_generateDataKeyResponseHasInvalidPlaintextLength());
    RUN_TEST(strict_onEncrypt_generateDataKeyResponseHasInvalidKeyId());
    RUN_TEST(strict_onEncrypt_encrypt_happyPath());
    RUN_TEST(strict_onEncrypt_encryptCallFails());
    RUN_TEST(strict_onEncrypt_encryptResponseHasInvalidKeyId());
    RUN_TEST(strict_onDecrypt_happyPath());
    RUN_TEST(strict_onDecrypt_decryptResponseIsInvalid());

    RUN_TEST(discovery_initialization_validInputs());
    RUN_TEST(discovery_onEncrypt_happyPath());
    RUN_TEST(discovery_onDecrypt_happyPath());
    RUN_TEST(discovery_onDecrypt_materialsAlreadyContainsPlaintextDataKey());
    RUN_TEST(discovery_onDecrypt_decryptResponseIsInvalid());

    RUN_TEST(strict_multiKeyring_happyPath());
    RUN_TEST(discovery_multiKeyring_happyPath());

    Aws::ShutdownAPI(*options);
    Aws::Delete(options);
    return 0;
}
