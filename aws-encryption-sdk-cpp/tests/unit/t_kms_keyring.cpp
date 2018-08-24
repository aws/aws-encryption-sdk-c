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
#include <aws/cryptosdk/private/cpputils.h>

#include <aws/common/array_list.h>
#include <aws/core/utils/Outcome.h>
#include <aws/kms/KMSClient.h>

#include "kms_client_mock.h"
#include "testutil.h"
#include "edks_utils.h"

using namespace Aws::Cryptosdk;
using namespace Aws::Cryptosdk::Private;
using namespace Aws::Cryptosdk::Testing;

const char *CLASS_TAG = "KMS_MASTER_KEY_CTAG";

/**
 * Changes access control for some protected members from KmsCMasterKey for testing purposes
 */
struct KmsMasterKeyExposer : Aws::Cryptosdk::KmsKeyring {
    KmsMasterKeyExposer(struct aws_allocator *allocator,
                        std::shared_ptr<Aws::KMS::KMSClient> kms,
                        const Aws::String &key_id)
        : KmsKeyring(allocator, kms, key_id) {}
    using KmsKeyring::EncryptDataKey;
    using KmsKeyring::DecryptDataKey;
    using KmsKeyring::GenerateDataKey;
    using KmsKeyring::CreateEncryptRequest;
    using KmsKeyring::CreateDecryptRequest;
    using KmsKeyring::CreateGenerateDataKeyRequest;
};

/**
 * Values used in all tests
 */
struct TestValues {
    const char *pt = "Random plain text";
    const char *ct = "expected_ct";
    const char *key_id = "Key_id";
    const char *provider_id = "aws-kms";

    struct aws_allocator *allocator;
    std::shared_ptr<KmsClientMock> kms_client_mock;
    KmsMasterKeyExposer *kms_keyring;
    Aws::Utils::ByteBuffer pt_bb;
    Aws::Utils::ByteBuffer ct_bb;
    aws_byte_buf pt_aws_byte;
    // TODO add tests for encryption context
    struct aws_hash_table *encryption_context = NULL;
    // TODO add tests for grant_todens;
    Aws::Vector<Aws::String> grant_tokens;

    TestValues() : allocator(aws_default_allocator()),
                   kms_client_mock(Aws::MakeShared<KmsClientMock>(CLASS_TAG)),
                   kms_keyring(Aws::New<KmsMasterKeyExposer>(CLASS_TAG,
                                                             allocator,
                                                             std::shared_ptr<Aws::KMS::KMSClient>(kms_client_mock),
                                                             key_id)),
                   pt_bb((unsigned char *) pt, strlen(pt)),
                   ct_bb((unsigned char *) ct, strlen(ct)),
                   pt_aws_byte(aws_byte_buf_from_c_str(pt)) {}

    //TODO implement this
    Aws::Map<Aws::String, Aws::String> GetEncryptionContext() {
        return Aws::Map<Aws::String, Aws::String>();
    }

    ~TestValues() {
        Aws::Delete(kms_keyring);
    }
};

struct EncryptTestValues : public TestValues {
    Model::EncryptResult encrypt_result;
    struct aws_cryptosdk_encryption_materials *enc_mat;

    EncryptTestValues() :
        enc_mat(aws_cryptosdk_encryption_materials_new(allocator, AES_128_GCM_IV12_AUTH16_KDNONE_SIGNONE)) {
        enc_mat->enc_context = NULL;
        encrypt_result.SetKeyId(key_id);
        encrypt_result.SetCiphertextBlob(ct_bb);

        enc_mat->unencrypted_data_key = aws_byte_buf_from_c_str(pt);
    }

    Model::EncryptRequest GetRequest() {
        Model::EncryptRequest request;
        request.SetKeyId(key_id);
        request.SetPlaintext(pt_bb);
        return request;
    }

    ~EncryptTestValues() {
        enc_mat->unencrypted_data_key.len = 0;
        enc_mat->unencrypted_data_key.buffer = NULL;
        aws_cryptosdk_encryption_materials_destroy(enc_mat);
    }
};

struct GenerateDataKeyValues : public TestValues {
    int generate_expected_value = 16;
    Model::GenerateDataKeyResult generate_result;
    struct aws_cryptosdk_encryption_materials *enc_mat;

    GenerateDataKeyValues()
        : enc_mat(aws_cryptosdk_encryption_materials_new(allocator, AES_128_GCM_IV12_AUTH16_KDNONE_SIGNONE)) {
        enc_mat->enc_context = encryption_context;
        generate_result.SetPlaintext(pt_bb);
        generate_result.SetCiphertextBlob(ct_bb);
        generate_result.SetKeyId(key_id);
    };

    ~GenerateDataKeyValues() {
        aws_cryptosdk_encryption_materials_destroy(enc_mat);
    }

    Model::GenerateDataKeyRequest GetRequest() {
        Model::GenerateDataKeyRequest request;
        request.SetKeyId(key_id);
        request.SetNumberOfBytes(generate_expected_value);
        return request;
    }

};

Model::DecryptResult MakeDecryptResult(const char *key_id, const char *plaintext) {
    Model::DecryptResult dr;
    Aws::Utils::ByteBuffer pt((u_char *) plaintext, strlen(plaintext));

    dr.SetKeyId(key_id);
    dr.SetPlaintext(pt);
    return dr;
}

/**
 * Predefined values used in testing decryption
 */
class DecryptValues : public TestValues {
  public:
    struct aws_cryptosdk_decryption_materials *dec_mat;
    Model::DecryptResult decrypt_result;
    Edks edks;

    DecryptValues() :
        dec_mat(aws_cryptosdk_decryption_materials_new(allocator, AES_128_GCM_IV12_AUTH16_KDNONE_SIGNONE)),
        decrypt_result(MakeDecryptResult(key_id, pt)),
        edks(allocator) {
    };

    Model::DecryptRequest GetRequest() {
        Model::DecryptRequest request;
        request.SetCiphertextBlob(ct_bb);
        return request;
    }

    struct aws_cryptosdk_decryption_request &decryption_request() {
        cryptosdk_decryption_request.enc_context = encryption_context;
        cryptosdk_decryption_request.alloc = allocator;
        cryptosdk_decryption_request.encrypted_data_keys = edks.encrypted_data_keys;
        return cryptosdk_decryption_request;
    }

    ~DecryptValues() {
        aws_cryptosdk_decryption_materials_destroy(dec_mat);
    }

  private:
    aws_cryptosdk_decryption_request cryptosdk_decryption_request;
};

int encrypt_validInputs_returnSuccess() {
    EncryptTestValues ev;
    Model::EncryptOutcome return_encrypt(ev.encrypt_result);

    ev.kms_client_mock->ExpectEncrypt(ev.GetRequest(), return_encrypt);
    TEST_ASSERT_SUCCESS(ev.kms_keyring->EncryptDataKey(ev.kms_keyring, ev.enc_mat));

    TEST_ASSERT_SUCCESS(assert_edks_with_single_element_contains_expected_values(&ev.enc_mat->encrypted_data_keys,
                                                                                 ev.ct,
                                                                                 ev.key_id,
                                                                                 ev.provider_id,
                                                                                 ev.allocator));

    TEST_ASSERT(ev.kms_client_mock->ExpectingOtherCalls() == false);
    return 0;
}

int encrypt_kmsFails_returnError() {
    EncryptTestValues ev;
    Model::EncryptOutcome return_encrypt; // if no parameter is set the EncryptOutcome.IsSuccess is false

    ev.kms_client_mock->ExpectEncrypt(ev.GetRequest(), return_encrypt);
    TEST_ASSERT_ERROR(AWS_CRYPTOSDK_ERR_KMS_FAILURE, ev.kms_keyring->EncryptDataKey(ev.kms_keyring, ev.enc_mat));
    return 0;
}

int decrypt_validInputs_returnSuccess() {
    DecryptValues dv;
    Model::DecryptOutcome return_decrypt(dv.decrypt_result);

    TEST_ASSERT_SUCCESS(append_c_str_key_to_edks(dv.allocator,
                                                 &dv.edks.encrypted_data_keys,
                                                 &dv.ct_bb,
                                                 dv.key_id,
                                                 dv.provider_id));

    dv.kms_client_mock->ExpectDecrypt(dv.GetRequest(), return_decrypt);

    TEST_ASSERT_SUCCESS(dv.kms_keyring->DecryptDataKey(dv.kms_keyring, dv.dec_mat, &dv.decryption_request()));
    TEST_ASSERT(aws_byte_buf_eq(&dv.dec_mat->unencrypted_data_key, &dv.pt_aws_byte) == true);
    TEST_ASSERT(dv.kms_client_mock->ExpectingOtherCalls() == false);
    return 0;
}

int decrypt_validInputsButNoKeyMatched_returnSuccess() {
    DecryptValues dv;
    Model::DecryptOutcome return_decrypt(dv.decrypt_result);

    TEST_ASSERT_SUCCESS(append_c_str_key_to_edks(dv.allocator,
                                                 &dv.edks.encrypted_data_keys,
                                                 &dv.ct_bb,
                                                 dv.key_id,
                                                 "invalid provider id"));

    TEST_ASSERT_SUCCESS(dv.kms_keyring->DecryptDataKey(dv.kms_keyring, dv.dec_mat, &dv.decryption_request()));
    TEST_ASSERT_ADDR_EQ(0, dv.dec_mat->unencrypted_data_key.buffer);
    TEST_ASSERT(dv.kms_client_mock->ExpectingOtherCalls() == false);
    return 0;
}

int decrypt_NoKeys_returnSuccess() {
    DecryptValues dv;
    Model::DecryptOutcome return_decrypt(dv.decrypt_result);

    TEST_ASSERT_SUCCESS(dv.kms_keyring->DecryptDataKey(dv.kms_keyring, dv.dec_mat, &dv.decryption_request()));
    TEST_ASSERT_ADDR_EQ(0, dv.dec_mat->unencrypted_data_key.buffer);
    TEST_ASSERT(dv.kms_client_mock->ExpectingOtherCalls() == false);
    return 0;
}

int decrypt_validInputsWithMultipleEdks_returnSuccess() {
    DecryptValues dv;

    Model::DecryptOutcome return_decrypt1;
    dv.kms_client_mock->ExpectDecrypt(dv.GetRequest(), return_decrypt1);

    // decrypt fails (decrypt outcome is failing) kms returns error
    TEST_ASSERT_SUCCESS(append_c_str_key_to_edks(dv.allocator,
                                                 &dv.edks.encrypted_data_keys,
                                                 &dv.ct_bb,
                                                 dv.key_id,
                                                 dv.provider_id));

    // decrypt is not called with invalid key
    TEST_ASSERT_SUCCESS(append_c_str_key_to_edks(dv.allocator,
                                                 &dv.edks.encrypted_data_keys,
                                                 &dv.ct_bb,
                                                 "Invalid key id",
                                                 dv.provider_id));

    // decrypt is not called because the provider_id is invalid
    TEST_ASSERT_SUCCESS(append_c_str_key_to_edks(dv.allocator,
                                                 &dv.edks.encrypted_data_keys,
                                                 &dv.ct_bb,
                                                 dv.key_id,
                                                 "Invalid provider id"));

    // this should succeed
    TEST_ASSERT_SUCCESS(append_c_str_key_to_edks(dv.allocator,
                                                 &dv.edks.encrypted_data_keys,
                                                 &dv.ct_bb,
                                                 dv.key_id,
                                                 dv.provider_id));
    Model::DecryptOutcome return_decrypt3(dv.decrypt_result);
    dv.kms_client_mock->ExpectDecrypt(dv.GetRequest(), return_decrypt3);

    TEST_ASSERT_SUCCESS(dv.kms_keyring->DecryptDataKey(dv.kms_keyring, dv.dec_mat, &dv.decryption_request()));
    TEST_ASSERT(aws_byte_buf_eq(&dv.dec_mat->unencrypted_data_key, &dv.pt_aws_byte) == true);
    TEST_ASSERT(dv.kms_client_mock->ExpectingOtherCalls() == false);
    return 0;
}

int generateDataKey_validInputs_returnSuccess() {
    GenerateDataKeyValues gv;
    Model::GenerateDataKeyOutcome return_generate(gv.generate_result);

    gv.kms_client_mock->ExpectGenerateDataKey(gv.GetRequest(), return_generate);

    TEST_ASSERT_SUCCESS(gv.kms_keyring->GenerateDataKey(gv.kms_keyring, gv.enc_mat));

    TEST_ASSERT_SUCCESS(assert_edks_with_single_element_contains_expected_values(&gv.enc_mat->encrypted_data_keys,
                                                                                 gv.ct,
                                                                                 gv.key_id,
                                                                                 gv.provider_id,
                                                                                 gv.allocator));
    TEST_ASSERT(aws_byte_buf_eq(&gv.enc_mat->unencrypted_data_key, &gv.pt_aws_byte) == true);

    TEST_ASSERT(gv.kms_client_mock->ExpectingOtherCalls() == false);

    return 0;
}

int generateDataKey_kmsFails_returnFailure() {
    GenerateDataKeyValues gv;
    Model::GenerateDataKeyOutcome return_generate;  // if no parameter is set GenerateDataKeyValues.IsSuccess() is false

    gv.kms_client_mock->ExpectGenerateDataKey(gv.GetRequest(), return_generate);

    TEST_ASSERT_ERROR(AWS_CRYPTOSDK_ERR_KMS_FAILURE, gv.kms_keyring->GenerateDataKey(gv.kms_keyring, gv.enc_mat));

    TEST_ASSERT(gv.kms_client_mock->ExpectingOtherCalls() == false);

    return 0;
}

int decrypt_validInputes_returnSuccess() {

    DecryptValues dv;
    Model::DecryptRequest outcome_out = dv.kms_keyring->CreateDecryptRequest(dv.key_id,
                                                                             dv.grant_tokens,
                                                                             dv.ct_bb,
                                                                             dv.GetEncryptionContext());

    TEST_ASSERT(outcome_out.GetCiphertextBlob() == dv.ct_bb);
    return 0;
}

int generate_dk_validInputes_returnSuccess() {
    GenerateDataKeyValues gd;

    Model::GenerateDataKeyRequest outcome_out = gd.kms_keyring->CreateGenerateDataKeyRequest(gd.key_id,
                                                                                             gd.grant_tokens,
                                                                                             gd.generate_expected_value,
                                                                                             gd.GetEncryptionContext());

    TEST_ASSERT(outcome_out.GetKeyId() == gd.key_id);
    TEST_ASSERT(outcome_out.GetNumberOfBytes() == gd.generate_expected_value);

    return 0;
}

//TODO add tests for encryption context and for grant_tokensgrant_tokens


int main() {
    Aws::SDKOptions *options = Aws::New<Aws::SDKOptions>(CLASS_TAG);
    Aws::InitAPI(*options);

    RUN_TEST(encrypt_validInputs_returnSuccess());
    RUN_TEST(encrypt_kmsFails_returnError());
    RUN_TEST(decrypt_validInputs_returnSuccess());
    RUN_TEST(decrypt_validInputsButNoKeyMatched_returnSuccess());
    RUN_TEST(decrypt_NoKeys_returnSuccess());
    RUN_TEST(decrypt_validInputsWithMultipleEdks_returnSuccess());
    RUN_TEST(generateDataKey_validInputs_returnSuccess());
    RUN_TEST(generateDataKey_kmsFails_returnFailure());
    RUN_TEST(decrypt_validInputes_returnSuccess());
    RUN_TEST(generate_dk_validInputes_returnSuccess());

    Aws::ShutdownAPI(*options);
    Aws::Delete(options);
    return 0;
}
