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
#include <aws/cryptosdk/private/kms_shim.h>
#include <aws/cryptosdk/private/cpputils.h>

#include <aws/common/array_list.h>
#include <aws/core/utils/Outcome.h>
#include <aws/kms/KMSClient.h>

#include "kms_shim_mock.h"
#include "testutil.h"
#include "edks_utils.h"

using namespace Aws::Cryptosdk::Private;
using namespace Aws::Cryptosdk::Testing;

const char *CLASS_TAG = "KMS_MASTER_KEY_CTAG";

/**
 * Changes access control for some protected members from KmsCMasterKey for testing purposes
 */
struct KmsMasterKeyExposer : Aws::Cryptosdk::KmsCMasterKey {
    KmsMasterKeyExposer(std::shared_ptr<KmsShim> kms, struct aws_allocator *allocator)
        : KmsCMasterKey(kms, allocator) {}
    using KmsCMasterKey::EncryptDataKey;
    using KmsCMasterKey::DecryptDataKey;
    using KmsCMasterKey::GenerateDataKey;
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
    std::shared_ptr<KmsShimMock> kms_shim_mock;
    KmsMasterKeyExposer *kms_mk;
    Aws::Utils::ByteBuffer pt_bb;
    Aws::Utils::ByteBuffer ct_bb;
    aws_byte_buf pt_aws_byte;
    // TODO add tests for encryption context
    struct aws_hash_table *encryption_context = NULL;

    TestValues() : allocator(aws_default_allocator()),
                   kms_shim_mock(Aws::MakeShared<KmsShimMock>(CLASS_TAG)),
                   kms_mk(Aws::New<KmsMasterKeyExposer>(CLASS_TAG, std::shared_ptr<KmsShim>(kms_shim_mock), allocator)),
                   pt_bb((unsigned char *) pt, strlen(pt)),
                   ct_bb((unsigned char *) ct, strlen(ct)),
                   pt_aws_byte(aws_byte_buf_from_c_str(pt)) {}

    ~TestValues() {
        Aws::Delete(kms_mk);
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

    ev.kms_shim_mock->ExpectEncrypt(ev.pt_bb, return_encrypt);
    TEST_ASSERT_INT_EQ(0, ev.kms_mk->EncryptDataKey(ev.kms_mk, ev.enc_mat));

    TEST_ASSERT_SUCCESS(assert_edks_with_single_element_contains_expected_values(&ev.enc_mat->encrypted_data_keys,
                                                                                 ev.ct,
                                                                                 ev.key_id,
                                                                                 ev.provider_id,
                                                                                 ev.allocator));

    TEST_ASSERT(ev.kms_shim_mock->ExpectingOtherCalls() == false);
    return 0;
}

int encrypt_kmsFails_returnError() {
    EncryptTestValues ev;
    Model::EncryptOutcome return_encrypt; // if no parameter is set the EncryptOutcome.IsSuccess is false

    ev.kms_shim_mock->ExpectEncrypt(ev.pt_bb, return_encrypt);
    TEST_ASSERT_INT_NE(0, ev.kms_mk->EncryptDataKey(ev.kms_mk, ev.enc_mat));
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

    dv.kms_shim_mock->ExpectDecrypt(dv.ct_bb, return_decrypt);

    TEST_ASSERT_SUCCESS(dv.kms_mk->DecryptDataKey(dv.kms_mk, dv.dec_mat, &dv.decryption_request()));
    TEST_ASSERT(aws_byte_buf_eq(&dv.dec_mat->unencrypted_data_key, &dv.pt_aws_byte) == true);
    TEST_ASSERT(dv.kms_shim_mock->ExpectingOtherCalls() == false);
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

    TEST_ASSERT(dv.kms_mk->DecryptDataKey(dv.kms_mk, dv.dec_mat, &dv.decryption_request()) == AWS_OP_SUCCESS);
    TEST_ASSERT_ADDR_EQ(0, dv.dec_mat->unencrypted_data_key.buffer);
    TEST_ASSERT(dv.kms_shim_mock->ExpectingOtherCalls() == false);
    return 0;
}

int decrypt_NoKeys_returnSuccess() {
    DecryptValues dv;
    Model::DecryptOutcome return_decrypt(dv.decrypt_result);

    TEST_ASSERT(dv.kms_mk->DecryptDataKey(dv.kms_mk, dv.dec_mat, &dv.decryption_request()) == AWS_OP_SUCCESS);
    TEST_ASSERT_ADDR_EQ(0, dv.dec_mat->unencrypted_data_key.buffer);
    TEST_ASSERT(dv.kms_shim_mock->ExpectingOtherCalls() == false);
    return 0;
}

int decrypt_validInputsWithMultipleEdks_returnSuccess() {
    DecryptValues dv;


    // decrypt fails (decrypt outcome is failing) kms returns error
    TEST_ASSERT_SUCCESS(append_c_str_key_to_edks(dv.allocator,
                                                 &dv.edks.encrypted_data_keys,
                                                 &dv.ct_bb,
                                                 dv.key_id,
                                                 dv.provider_id));

    Model::DecryptOutcome return_decrypt1;
    dv.kms_shim_mock->ExpectDecrypt(dv.ct_bb, return_decrypt1);

    // decrypt succeeds but the key_id is not the one expected
    TEST_ASSERT_SUCCESS(append_c_str_key_to_edks(dv.allocator,
                                                 &dv.edks.encrypted_data_keys,
                                                 &dv.ct_bb,
                                                 "Invalid key id",
                                                 dv.provider_id));
    Model::DecryptOutcome return_decrypt2(MakeDecryptResult(dv.key_id, dv.pt));
    dv.kms_shim_mock->ExpectDecrypt(dv.ct_bb, return_decrypt2);

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
    dv.kms_shim_mock->ExpectDecrypt(dv.ct_bb, return_decrypt3);

    TEST_ASSERT_SUCCESS(dv.kms_mk->DecryptDataKey(dv.kms_mk, dv.dec_mat, &dv.decryption_request()));
    TEST_ASSERT(aws_byte_buf_eq(&dv.dec_mat->unencrypted_data_key, &dv.pt_aws_byte) == true);
    TEST_ASSERT(dv.kms_shim_mock->ExpectingOtherCalls() == false);
    return 0;
}

int generateDataKey_validInputs_returnSuccess() {
    GenerateDataKeyValues gv;
    Model::GenerateDataKeyOutcome return_generate(gv.generate_result);

    gv.kms_shim_mock->ExpectGenerate(gv.generate_expected_value, return_generate);

    TEST_ASSERT_INT_EQ(0, gv.kms_mk->GenerateDataKey(gv.kms_mk, gv.enc_mat));

    TEST_ASSERT_SUCCESS(assert_edks_with_single_element_contains_expected_values(&gv.enc_mat->encrypted_data_keys,
                                                                                 gv.ct,
                                                                                 gv.key_id,
                                                                                 gv.provider_id,
                                                                                 gv.allocator));
    TEST_ASSERT(aws_byte_buf_eq(&gv.enc_mat->unencrypted_data_key, &gv.pt_aws_byte) == true);

    TEST_ASSERT(gv.kms_shim_mock->ExpectingOtherCalls() == false);

    return 0;
}

int generateDataKey_kmsFails_returnFailure() {
    GenerateDataKeyValues gv;
    Model::GenerateDataKeyOutcome
        return_generate; // if no parameter is set the GenerateDataKeyValues.IsSuccess() is false

    gv.kms_shim_mock->ExpectGenerate(gv.generate_expected_value, return_generate);

    TEST_ASSERT_INT_NE(0, gv.kms_mk->GenerateDataKey(gv.kms_mk, gv.enc_mat));

    TEST_ASSERT(gv.kms_shim_mock->ExpectingOtherCalls() == false);

    return 0;
}


int main() {
    RUN_TEST(encrypt_validInputs_returnSuccess());
    RUN_TEST(encrypt_kmsFails_returnError());
    RUN_TEST(decrypt_validInputs_returnSuccess());
    RUN_TEST(decrypt_validInputsWithMultipleEdks_returnSuccess());
    RUN_TEST(decrypt_validInputsButNoKeyMatched_returnSuccess());
    RUN_TEST(decrypt_NoKeys_returnSuccess());
    RUN_TEST(generateDataKey_validInputs_returnSuccess());
    RUN_TEST(generateDataKey_kmsFails_returnFailure());
    return 0;
}
