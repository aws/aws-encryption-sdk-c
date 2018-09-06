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
  protected:
    KmsMasterKeyExposer(struct aws_allocator *allocator,
                        std::shared_ptr<Aws::KMS::KMSClient> kms,
                        const Aws::String &key_id)
        : KmsMasterKeyExposer(allocator, kms, Aws::List<Aws::String> { key_id }) {
    }
    KmsMasterKeyExposer(struct aws_allocator *allocator,
                        std::shared_ptr<Aws::KMS::KMSClient> kms,
                        const Aws::List<Aws::String> &key_ids)
        : KmsKeyring(allocator,
                     key_ids,
                     "default_region",
                     {},
                     Aws::MakeShared<SingleClientSupplier>("KMS_EXPOSER", kms),
                     {}) {
    }
  public:
    using KmsKeyring::EncryptDataKey;
    using KmsKeyring::DecryptDataKey;
    using KmsKeyring::GenerateDataKey;
    using KmsKeyring::CreateEncryptRequest;
    using KmsKeyring::CreateDecryptRequest;
    using KmsKeyring::CreateGenerateDataKeyRequest;

    template<typename T, typename ...ArgTypes>
    friend T *Aws::New(const char *allocationTag, ArgTypes &&... args);
};

Aws::Utils::ByteBuffer t_aws_utils_bb_from_char(const char *str) {
    return Aws::Utils::ByteBuffer((unsigned char *) str, strlen(str));
}

/**
 * Values used in all tests
 */
struct TestValues {
    const char *pt = "Random plain text";
    const char *ct = "expected_ct";
    const static char *key_id;
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

    TestValues() : TestValues({ key_id }) {
    };

    TestValues(const Aws::List<Aws::String> &key_ids) : allocator(aws_default_allocator()),
                   kms_client_mock(Aws::MakeShared<KmsClientMock>(CLASS_TAG)),
                   kms_keyring(Aws::New<KmsMasterKeyExposer>(CLASS_TAG,
                                                             allocator,
                                                             std::shared_ptr<Aws::KMS::KMSClient>(kms_client_mock),
                                                             key_ids)),
                   pt_bb((unsigned char *) pt, strlen(pt)),
                   ct_bb((unsigned char *) ct, strlen(ct)),
                   pt_aws_byte(aws_byte_buf_from_c_str(pt)) {
    }


    //TODO implement this
    Aws::Map<Aws::String, Aws::String> GetEncryptionContext() {
        return Aws::Map<Aws::String, Aws::String>();
    }

    ~TestValues() {
        Aws::Delete(kms_keyring);
    }
};

const char *TestValues::key_id = "Key_id";

struct EncryptTestValues : public TestValues {
    struct aws_cryptosdk_encryption_materials *enc_mat;

    EncryptTestValues() : EncryptTestValues( { key_id } ) {

    }
    EncryptTestValues(const Aws::List<Aws::String> &key_ids)
        : TestValues(key_ids),
          enc_mat(aws_cryptosdk_encryption_materials_new(allocator, AES_128_GCM_IV12_AUTH16_KDNONE_SIGNONE)) {
        enc_mat->enc_context = NULL;

        enc_mat->unencrypted_data_key = aws_byte_buf_from_c_str(pt);
    }

    Model::EncryptResult GetResult() {
        return GetResult(key_id);
    }

    Model::EncryptResult GetResult(const Aws::String &in_key_id) {
        return GetResult(in_key_id, ct_bb);
    }

    Model::EncryptResult GetResult(const Aws::String &in_key_id, const Aws::Utils::ByteBuffer &in_ct_bb) {
        Model::EncryptResult encrypt_result;
        encrypt_result.SetKeyId(in_key_id);
        encrypt_result.SetCiphertextBlob(in_ct_bb);
        return encrypt_result;
    }

    Model::EncryptRequest GetRequest() {
        return GetRequest(key_id, pt_bb);
    }

    Model::EncryptRequest GetRequest(const Aws::String &in_key_id, const Aws::Utils::ByteBuffer &in_pt_bb) {
        Model::EncryptRequest request;
        request.SetKeyId(in_key_id);
        request.SetPlaintext(in_pt_bb);
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

    DecryptValues(const Aws::List<Aws::String> &key_ids)
    : TestValues(key_ids),
      dec_mat(aws_cryptosdk_decryption_materials_new(allocator, AES_128_GCM_IV12_AUTH16_KDNONE_SIGNONE)),
      edks(allocator) {

    }

    Model::DecryptRequest GetRequest() {
        Model::DecryptRequest request;
        request.SetCiphertextBlob(ct_bb);
        return request;
    }

    Model::DecryptRequest GetRequest(const Aws::Utils::ByteBuffer &in_ct_bb) {
        Model::DecryptRequest request;
        request.SetCiphertextBlob(in_ct_bb);
        return request;
    }

    Model::DecryptResult GetResult(const Aws::String &key, const Aws::Utils::ByteBuffer &pt_bb) {
        Model::DecryptResult rv;
        rv.SetKeyId(key);
        rv.SetPlaintext(pt_bb);
        return rv;
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

    ev.kms_client_mock->ExpectEncryptAccumulator(ev.GetRequest(), ev.GetResult());
    TEST_ASSERT_SUCCESS(ev.kms_keyring->EncryptDataKey(ev.kms_keyring, ev.enc_mat));

    TEST_ASSERT_SUCCESS(t_assert_edks_with_single_element_contains_expected_values(&ev.enc_mat->encrypted_data_keys,
                                                                                   ev.ct,
                                                                                   ev.key_id,
                                                                                   ev.provider_id,
                                                                                   ev.allocator));

    TEST_ASSERT(ev.kms_client_mock->ExpectingOtherCalls() == false);
    return 0;
}

/**
 * Sets kms_client_mock to expect an encrypt call with \param key and plaintext as \param in_pt and
 * to return \param expected_ct. Also in expected_edks will append the key, ev.provider_id, expected_ct as it would
 * have the encrypt operation (for comparison purposes).
 * purposes
 */
int expect_encrypt(struct aws_array_list &expected_edks,
                   EncryptTestValues &ev,
                   const char *key,
                   const char *in_pt,
                   const char *expected_ct) {
    Aws::Utils::ByteBuffer pt = t_aws_utils_bb_from_char(in_pt);
    Aws::Utils::ByteBuffer ct = t_aws_utils_bb_from_char(expected_ct);
    ev.kms_client_mock->ExpectEncryptAccumulator(ev.GetRequest(key, pt), ev.GetResult(key, ct));
    TEST_ASSERT_SUCCESS(t_append_c_str_key_to_edks(ev.allocator, &expected_edks, &ct, key, ev.provider_id));
    return AWS_OP_SUCCESS;
}

int encrypt_validInputsMultipleKeys_returnSuccess() {
    EncryptTestValues ev({"key1", "key2", "key3"});
    struct aws_array_list expected_edks;
    TEST_ASSERT_SUCCESS(aws_array_list_init_dynamic(&expected_edks, ev.allocator, 3, sizeof(struct aws_cryptosdk_edk)));

    TEST_ASSERT_SUCCESS(expect_encrypt(expected_edks, ev, "key1", ev.pt, "ct1"));
    TEST_ASSERT_SUCCESS(expect_encrypt(expected_edks, ev, "key2", ev.pt, "ct2"));
    TEST_ASSERT_SUCCESS(expect_encrypt(expected_edks, ev, "key3", ev.pt, "ct3"));

    TEST_ASSERT_SUCCESS(ev.kms_keyring->EncryptDataKey(ev.kms_keyring, ev.enc_mat));
    TEST_ASSERT_SUCCESS(t_assert_edks_equals(&ev.enc_mat->encrypted_data_keys, &expected_edks));
    TEST_ASSERT(ev.kms_client_mock->ExpectingOtherCalls() == false);

    aws_cryptosdk_edk_list_clean_up(&expected_edks);

    return 0;
}

int encrypt_emptyRegionNameInKeys_returnSuccess() {
    Aws::List<Aws::String> key = {"arn:aws:kms::123456789010:whatever"};
    EncryptTestValues ev(key);

    auto kms_client_mock = Aws::MakeShared<KmsClientMock>(CLASS_TAG);
    auto kms_keyring = Aws::New<KmsMasterKeyExposer>(CLASS_TAG,
                                                     ev.allocator,
                                                     kms_client_mock,
                                                     key
    );

    kms_client_mock->ExpectEncryptAccumulator(ev.GetRequest(key.front().c_str(), ev.pt_bb),
                                              ev.GetResult(key.front().c_str()));
    TEST_ASSERT_SUCCESS(kms_keyring->EncryptDataKey(kms_keyring, ev.enc_mat));

    TEST_ASSERT_SUCCESS(t_assert_edks_with_single_element_contains_expected_values(&ev.enc_mat->encrypted_data_keys,
                                                                                   ev.ct,
                                                                                   key.front().c_str(),
                                                                                   ev.provider_id,
                                                                                   ev.allocator));

    TEST_ASSERT(ev.kms_client_mock->ExpectingOtherCalls() == false);

    Aws::Delete(kms_keyring);

    return 0;
}

int encrypt_multipleKeysOneFails_returnFail() {
    EncryptTestValues ev({"key1", "key2", "key3"});
    Aws::Utils::ByteBuffer ct = t_aws_utils_bb_from_char("expected_ct");
    Model::EncryptOutcome error_return; // this will set IsSuccess to false

    ev.kms_client_mock->ExpectEncryptAccumulator(ev.GetRequest("key1", ev.pt_bb), ev.GetResult("key1", ct));
    ev.kms_client_mock->ExpectEncryptAccumulator(ev.GetRequest("key2", ev.pt_bb), error_return);

    TEST_ASSERT_ERROR(AWS_CRYPTOSDK_ERR_KMS_FAILURE, ev.kms_keyring->EncryptDataKey(ev.kms_keyring, ev.enc_mat));

    TEST_ASSERT_INT_EQ(0, aws_array_list_length(&ev.enc_mat->encrypted_data_keys));
    TEST_ASSERT(ev.kms_client_mock->ExpectingOtherCalls() == false);
    return 0;
}

// assuming that enc_mat->encrypted_data_keys had already some elements before the EncryptDataKey call and we are not
// able to encrypt, we should't modify anything
int encrypt_multipleKeysOneFails_initialEdksAreNotAffected() {
    EncryptTestValues ev({"key1", "key2", "key3"});
    Model::EncryptOutcome error_return; // this will set IsSuccess to false
    const char *initial_ct = "initial_ct";
    auto initial_ct_bb = t_aws_utils_bb_from_char(initial_ct);
    const char *initial_key = "initial_key";

    // artificially add a new edk
    TEST_ASSERT_SUCCESS(t_append_c_str_key_to_edks(ev.allocator,
                                                   &ev.enc_mat->encrypted_data_keys,
                                                   &initial_ct_bb,
                                                   initial_key,
                                                   ev.provider_id));


    // first request works
    ev.kms_client_mock->ExpectEncryptAccumulator(ev.GetRequest("key1", ev.pt_bb), ev.GetResult("key1", ev.ct_bb));
    // second request will fail
    ev.kms_client_mock->ExpectEncryptAccumulator(ev.GetRequest("key2", ev.pt_bb), error_return);

    TEST_ASSERT_ERROR(AWS_CRYPTOSDK_ERR_KMS_FAILURE, ev.kms_keyring->EncryptDataKey(ev.kms_keyring, ev.enc_mat));

    // we should have the initial edk
    TEST_ASSERT_SUCCESS(t_assert_edks_with_single_element_contains_expected_values(&ev.enc_mat->encrypted_data_keys,
                                                                                   initial_ct,
                                                                                   initial_key,
                                                                                   ev.provider_id,
                                                                                   ev.allocator));

    TEST_ASSERT(ev.kms_client_mock->ExpectingOtherCalls() == false);
    return 0;
}


int encrypt_kmsFails_returnError() {
    EncryptTestValues ev;
    Model::EncryptOutcome return_encrypt; // if no parameter is set the EncryptOutcome.IsSuccess is false

    ev.kms_client_mock->ExpectEncryptAccumulator(ev.GetRequest(), return_encrypt);
    TEST_ASSERT_ERROR(AWS_CRYPTOSDK_ERR_KMS_FAILURE, ev.kms_keyring->EncryptDataKey(ev.kms_keyring, ev.enc_mat));
    return 0;
}

int decrypt_validInputs_returnSuccess() {
    DecryptValues dv;
    Model::DecryptOutcome return_decrypt(dv.decrypt_result);

    TEST_ASSERT_SUCCESS(t_append_c_str_key_to_edks(dv.allocator,
                                                   &dv.edks.encrypted_data_keys,
                                                   &dv.ct_bb,
                                                   dv.key_id,
                                                   dv.provider_id));

    dv.kms_client_mock->ExpectDecryptAccumulator(dv.GetRequest(), return_decrypt);

    TEST_ASSERT_SUCCESS(dv.kms_keyring->DecryptDataKey(dv.kms_keyring, dv.dec_mat, &dv.decryption_request()));
    TEST_ASSERT(aws_byte_buf_eq(&dv.dec_mat->unencrypted_data_key, &dv.pt_aws_byte) == true);
    TEST_ASSERT(dv.kms_client_mock->ExpectingOtherCalls() == false);
    return 0;
}

int decrypt_emptyRegionNameInKeys_returnSuccess() {
    Aws::String key = {"arn:aws:kms::123456789010:whatever"};
    DecryptValues dv( { key } );

    auto kms_client_mock = Aws::MakeShared<KmsClientMock>(CLASS_TAG);
    auto kms_keyring = Aws::New<KmsMasterKeyExposer>(CLASS_TAG,
                                                     dv.allocator,
                                                     kms_client_mock,
                                                     key
    );
    TEST_ASSERT_SUCCESS(t_append_c_str_key_to_edks(dv.allocator,
                                                   &dv.edks.encrypted_data_keys,
                                                   &dv.ct_bb,
                                                   key.c_str(),
                                                   dv.provider_id));


    kms_client_mock->ExpectDecryptAccumulator(dv.GetRequest(), dv.GetResult(key, dv.pt_bb));

    TEST_ASSERT_SUCCESS(kms_keyring->DecryptDataKey(kms_keyring, dv.dec_mat, &dv.decryption_request()));
    TEST_ASSERT(aws_byte_buf_eq(&dv.dec_mat->unencrypted_data_key, &dv.pt_aws_byte) == true);
    TEST_ASSERT(dv.kms_client_mock->ExpectingOtherCalls() == false);

    Aws::Delete(kms_keyring);

    return 0;
}

int decrypt_validInputsButNoKeyMatched_returnSuccess() {
    DecryptValues dv;
    Model::DecryptOutcome return_decrypt(dv.decrypt_result);

    TEST_ASSERT_SUCCESS(t_append_c_str_key_to_edks(dv.allocator,
                                                   &dv.edks.encrypted_data_keys,
                                                   &dv.ct_bb,
                                                   dv.key_id,
                                                   "invalid provider id"));

    TEST_ASSERT_SUCCESS(dv.kms_keyring->DecryptDataKey(dv.kms_keyring, dv.dec_mat, &dv.decryption_request()));
    TEST_ASSERT_ADDR_EQ(0, dv.dec_mat->unencrypted_data_key.buffer);
    TEST_ASSERT(dv.kms_client_mock->ExpectingOtherCalls() == false);
    return 0;
}

int decrypt_noKeys_returnSuccess() {
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
    dv.kms_client_mock->ExpectDecryptAccumulator(dv.GetRequest(), return_decrypt1);

    // decrypt fails (decrypt outcome is failing) kms returns error
    TEST_ASSERT_SUCCESS(t_append_c_str_key_to_edks(dv.allocator,
                                                   &dv.edks.encrypted_data_keys,
                                                   &dv.ct_bb,
                                                   dv.key_id,
                                                   dv.provider_id));

    // decrypt is not called with invalid key
    TEST_ASSERT_SUCCESS(t_append_c_str_key_to_edks(dv.allocator,
                                                   &dv.edks.encrypted_data_keys,
                                                   &dv.ct_bb,
                                                   "Invalid key id",
                                                   dv.provider_id));

    // decrypt is not called because the provider_id is invalid
    TEST_ASSERT_SUCCESS(t_append_c_str_key_to_edks(dv.allocator,
                                                   &dv.edks.encrypted_data_keys,
                                                   &dv.ct_bb,
                                                   dv.key_id,
                                                   "Invalid provider id"));

    // this should succeed
    TEST_ASSERT_SUCCESS(t_append_c_str_key_to_edks(dv.allocator,
                                                   &dv.edks.encrypted_data_keys,
                                                   &dv.ct_bb,
                                                   dv.key_id,
                                                   dv.provider_id));
    Model::DecryptOutcome return_decrypt3(dv.decrypt_result);
    dv.kms_client_mock->ExpectDecryptAccumulator(dv.GetRequest(), return_decrypt3);

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

    TEST_ASSERT_SUCCESS(t_assert_edks_with_single_element_contains_expected_values(&gv.enc_mat->encrypted_data_keys,
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

int createDecryptRequest_validInputes_returnRequest() {

    DecryptValues dv;
    Model::DecryptRequest outcome_out = dv.kms_keyring->CreateDecryptRequest(dv.key_id,
                                                                             dv.grant_tokens,
                                                                             dv.ct_bb,
                                                                             dv.GetEncryptionContext());

    TEST_ASSERT(outcome_out.GetCiphertextBlob() == dv.ct_bb);
    return 0;
}

int createGenerateDataKeyRequest_validInputes_returnRequest() {
    GenerateDataKeyValues gd;

    Model::GenerateDataKeyRequest outcome_out = gd.kms_keyring->CreateGenerateDataKeyRequest(gd.key_id,
                                                                                             gd.grant_tokens,
                                                                                             gd.generate_expected_value,
                                                                                             gd.GetEncryptionContext());

    TEST_ASSERT(outcome_out.GetKeyId() == gd.key_id);
    TEST_ASSERT(outcome_out.GetNumberOfBytes() == gd.generate_expected_value);

    return 0;
}

int createEncryptRequest_validInputes_returnRequest() {
    EncryptTestValues ev;

    Model::EncryptRequest outcome_out = ev.kms_keyring->CreateEncryptRequest(ev.key_id,
                                                                             ev.grant_tokens,
                                                                             ev.pt_bb,
                                                                             ev.GetEncryptionContext());

    TEST_ASSERT(outcome_out.GetKeyId() == ev.key_id);
    TEST_ASSERT(outcome_out.GetPlaintext() == ev.pt_bb);
    TEST_ASSERT(outcome_out.GetGrantTokens() == ev.grant_tokens);
    TEST_ASSERT(outcome_out.GetEncryptionContext() == ev.GetEncryptionContext());

    return 0;
}

// exposes protected members
struct KmsKeyringBuilderExposer : KmsKeyring::Builder {
  public:
    using KmsKeyring::Builder::BuildDefaultRegion;
    using KmsKeyring::Builder::BuildClientSupplier;
    using KmsKeyring::Builder::ValidParameters;
    using KmsKeyring::Builder::BuildAllocator;
};

int testBuilder_buildDefaultRegion_buildsRegion() {
    const static char *default_region = "test";
    KmsKeyringBuilderExposer a;
    a.SetDefaultRegion(default_region);
    TEST_ASSERT(a.BuildDefaultRegion() == default_region);

    a.SetDefaultRegion("");
    a.SetKeyId("arn:aws:kms:region_extracted_from_key:");
    TEST_ASSERT(a.BuildDefaultRegion() == "region_extracted_from_key");

    // no default region is set if there are two keys
    a.AppendKeyId("key2");
    TEST_ASSERT(a.BuildDefaultRegion() == "");

    TestValues tv;
    a.SetKmsClient(tv.kms_client_mock);
    TEST_ASSERT(a.BuildDefaultRegion() == "default_region");

    return 0;
}


int testBuilder_buildClientSupplier_buildsClient() {
    KmsKeyringBuilderExposer a;
    TEST_ASSERT(dynamic_cast<KmsKeyring::DefaultRegionalClientSupplier*>(a.BuildClientSupplier().get()) != NULL);

    TestValues tv;
    a.SetKmsClient(tv.kms_client_mock);
    TEST_ASSERT(dynamic_cast<KmsKeyring::SingleClientSupplier*>(a.BuildClientSupplier().get()) != NULL);

    return 0;
}

int testBuilder_invalidInputs_isValidReturnFalse() {
    KmsKeyringBuilderExposer a;

    // no keys
    TEST_ASSERT(a.ValidParameters() == false);

    // no keys
    a.SetAllocator(aws_default_allocator());
    TEST_ASSERT(a.ValidParameters() == false);

    // minimum valid parameters are met
    a.SetKeyId("arn:aws:kms:region_extracted_from_key:");
    TEST_ASSERT(a.ValidParameters() == true);

    // no keys that contain region
    a.SetAllocator(aws_default_allocator());
    a.SetKeyId("arn:aws:kms:");
    TEST_ASSERT(a.ValidParameters() == false);

    a.SetDefaultRegion("default_region_set");
    TEST_ASSERT(a.ValidParameters() == true);

    // empty key is not allowed
    a.AppendKeyId("");
    TEST_ASSERT(a.ValidParameters() == false);

    return 0;
}

int testBuilder_allocator_returnAlloc() {
    KmsKeyringBuilderExposer a;
    struct aws_allocator test_alloc;

    TEST_ASSERT_ADDR_NE(NULL, a.BuildAllocator());
    a.SetAllocator(&test_alloc);

    TEST_ASSERT_ADDR_EQ(&test_alloc, a.BuildAllocator());

    return 0;
}

//TODO add tests for encryption context and for grant_tokensgrant_tokens
//TODO add test for multiple keys decryption

int main() {
    Aws::SDKOptions *options = Aws::New<Aws::SDKOptions>(CLASS_TAG);
    Aws::InitAPI(*options);

    RUN_TEST(encrypt_validInputs_returnSuccess());
    RUN_TEST(encrypt_kmsFails_returnError());
    RUN_TEST(encrypt_validInputsMultipleKeys_returnSuccess());
    RUN_TEST(encrypt_emptyRegionNameInKeys_returnSuccess());
    RUN_TEST(encrypt_multipleKeysOneFails_returnFail());
    RUN_TEST(encrypt_multipleKeysOneFails_initialEdksAreNotAffected());
    RUN_TEST(decrypt_validInputs_returnSuccess());
    RUN_TEST(decrypt_emptyRegionNameInKeys_returnSuccess());
    RUN_TEST(decrypt_validInputsButNoKeyMatched_returnSuccess());
    RUN_TEST(decrypt_noKeys_returnSuccess());
    RUN_TEST(decrypt_validInputsWithMultipleEdks_returnSuccess());
    RUN_TEST(generateDataKey_validInputs_returnSuccess());
    RUN_TEST(generateDataKey_kmsFails_returnFailure());
    RUN_TEST(createDecryptRequest_validInputes_returnRequest());
    RUN_TEST(createGenerateDataKeyRequest_validInputes_returnRequest());
    RUN_TEST(createEncryptRequest_validInputes_returnRequest());
    RUN_TEST(testBuilder_buildDefaultRegion_buildsRegion());
    RUN_TEST(testBuilder_buildClientSupplier_buildsClient());
    RUN_TEST(testBuilder_invalidInputs_isValidReturnFalse());
    RUN_TEST(testBuilder_allocator_returnAlloc());

    Aws::ShutdownAPI(*options);
    Aws::Delete(options);
    return 0;
}
