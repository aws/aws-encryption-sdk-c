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
#include <aws/common/string.h>
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
                        const Aws::List<Aws::String> &key_ids,
                        const Aws::Vector<Aws::String> &grant_tokens = { },
                        std::shared_ptr<KmsClientCache> kms_client_cache = NULL
                        )
        : KmsKeyring(allocator,
                     key_ids,
                     "default_region",
                     grant_tokens,
                     Aws::MakeShared<SingleClientSupplier>("KMS_EXPOSER", kms),
                     kms_client_cache) {
    }
  public:
    using KmsKeyring::OnEncrypt;
    using KmsKeyring::OnDecrypt;
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
    struct aws_hash_table encryption_context;
    Aws::Vector<Aws::String> grant_tokens;

    TestValues() : TestValues({ key_id }) {
    };

    TestValues(const Aws::List<Aws::String> &key_ids, const Aws::Vector<Aws::String> &grant_tokens = { })
                 : allocator(aws_default_allocator()),
                   kms_client_mock(Aws::MakeShared<KmsClientMock>(CLASS_TAG)),
                   kms_keyring(Aws::New<KmsMasterKeyExposer>(CLASS_TAG,
                                                             allocator,
                                                             std::shared_ptr<Aws::KMS::KMSClient>(kms_client_mock),
                                                             key_ids,
                                                             grant_tokens)),
                   pt_bb((unsigned char *) pt, strlen(pt)),
                   ct_bb((unsigned char *) ct, strlen(ct)),
                   pt_aws_byte(aws_byte_buf_from_c_str(pt)),
                   grant_tokens(grant_tokens) {
        aws_hash_table_init(&encryption_context, allocator, 100,
                                                aws_hash_string, aws_string_eq, aws_string_destroy, aws_string_destroy);


    }

    /**
     * Inserts inside the encryption_context member values from in_encryption_context
     */
    int SetEncryptionContext(Aws::Map<Aws::String, Aws::String> in_encryption_context) {
        struct aws_hash_element *p_elem;
        int was_created;

        for (auto entry : in_encryption_context) {
            const struct aws_string *key = aws_string_new_from_c_str(allocator, entry.first.c_str());
            const struct aws_string *value = aws_string_new_from_c_str(allocator, entry.second.c_str());

            TEST_ASSERT_SUCCESS(aws_hash_table_create(&encryption_context, (void *) key, &p_elem, &was_created));
            p_elem->value = (void *) value;
        }

        return AWS_OP_SUCCESS;
    }

    Aws::Map<Aws::String, Aws::String> GetEncryptionContext() const {
        return aws_map_from_c_aws_hash_table(&encryption_context);
    }

    ~TestValues() {
        Aws::Delete(kms_keyring);
        aws_hash_table_clean_up(&encryption_context);
    }
};

const char *TestValues::key_id = "Key_id";

struct EncryptTestValues : public TestValues {
    enum aws_cryptosdk_alg_id alg;
    struct aws_byte_buf unencrypted_data_key;
    struct aws_array_list edks;

    EncryptTestValues() : EncryptTestValues( { key_id } ) {

    }
    EncryptTestValues(const Aws::List<Aws::String> &key_ids, const Aws::Vector<Aws::String> &grant_tokens = { })
        : TestValues(key_ids, grant_tokens),
          alg(AES_128_GCM_IV12_AUTH16_KDNONE_SIGNONE),
          unencrypted_data_key(aws_byte_buf_from_c_str(pt)) {
        if (aws_cryptosdk_edk_list_init(allocator, &edks)) abort();
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
        return GetRequest(key_id, pt_bb, grant_tokens, GetEncryptionContext());
    }

    Model::EncryptRequest GetRequest(const Aws::String &in_key_id,
                                     const Aws::Utils::ByteBuffer &in_pt_bb,
                                     const Aws::Vector<Aws::String> &grant_tokens = { },
                                     const Aws::Map<Aws::String, Aws::String> in_encryption_context = { }) {
        Model::EncryptRequest request;
        request.SetKeyId(in_key_id);
        request.SetPlaintext(in_pt_bb);
        request.SetGrantTokens(grant_tokens);
        request.SetEncryptionContext(in_encryption_context);
        return request;
    }

    ~EncryptTestValues() {
        aws_byte_buf_clean_up(&unencrypted_data_key);
        aws_cryptosdk_edk_list_clean_up(&edks);
    }
};

struct GenerateDataKeyValues : public TestValues {
    int generate_expected_value = 16;
    Model::GenerateDataKeyResult generate_result;
    enum aws_cryptosdk_alg_id alg;
    struct aws_byte_buf unencrypted_data_key;
    struct aws_array_list edks;

    GenerateDataKeyValues(const Aws::Vector<Aws::String> &grant_tokens = { })
        : TestValues({ key_id }, grant_tokens),
          alg(AES_128_GCM_IV12_AUTH16_KDNONE_SIGNONE),
          unencrypted_data_key({0}) {
        if (aws_cryptosdk_edk_list_init(allocator, &edks)) abort();
        generate_result.SetPlaintext(pt_bb);
        generate_result.SetCiphertextBlob(ct_bb);
        generate_result.SetKeyId(key_id);
    };

    ~GenerateDataKeyValues() {
        aws_byte_buf_clean_up(&unencrypted_data_key);
        aws_cryptosdk_edk_list_clean_up(&edks);
    }

    static Model::GenerateDataKeyRequest GetRequest(const Aws::String &key_id,
                                                    int generate_expected_value,
                                                    const Aws::Vector<Aws::String> &grant_tokens = {},
                                                    const Aws::Map<Aws::String, Aws::String> in_encryption_context = { }
                                                    ) {
        Model::GenerateDataKeyRequest request;
        request.SetKeyId(key_id);
        request.SetNumberOfBytes(generate_expected_value);
        request.SetGrantTokens(grant_tokens);
        request.SetEncryptionContext(in_encryption_context);
        return request;
    }

    Model::GenerateDataKeyRequest GetRequest() {
        return GetRequest(key_id, generate_expected_value, grant_tokens, GetEncryptionContext());
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
    Model::DecryptResult decrypt_result;
    Edks edks;
    enum aws_cryptosdk_alg_id alg;
    struct aws_byte_buf unencrypted_data_key;

    DecryptValues() :
        decrypt_result(MakeDecryptResult(key_id, pt)),
        edks(allocator),
        alg(AES_128_GCM_IV12_AUTH16_KDNONE_SIGNONE),
        unencrypted_data_key({0}) {
    }

    DecryptValues(const Aws::List<Aws::String> &key_ids, const Aws::Vector<Aws::String> &grant_tokens = { })
    : TestValues(key_ids, grant_tokens),
      edks(allocator),
      alg(AES_128_GCM_IV12_AUTH16_KDNONE_SIGNONE),
      unencrypted_data_key({0}) {
    }

    Model::DecryptRequest GetRequest() {
        return GetRequest(ct_bb, grant_tokens, GetEncryptionContext());
    }

    static Model::DecryptRequest GetRequest(const Aws::Utils::ByteBuffer &in_ct_bb,
                                            const Aws::Vector<Aws::String> &in_grant_tokens = { },
                                            const Aws::Map<Aws::String, Aws::String> in_encryption_context = { }) {
        Model::DecryptRequest request;
        request.SetCiphertextBlob(in_ct_bb);
        request.SetGrantTokens(in_grant_tokens);
        request.SetEncryptionContext(in_encryption_context);
        return request;
    }

    static Model::DecryptResult GetResult(const Aws::String &key, const Aws::Utils::ByteBuffer &pt_bb) {
        Model::DecryptResult rv;
        rv.SetKeyId(key);
        rv.SetPlaintext(pt_bb);
        return rv;
    }

    ~DecryptValues() {
        aws_byte_buf_clean_up(&unencrypted_data_key);
    }

};

int encrypt_validInputs_returnSuccess() {
    EncryptTestValues ev;

    ev.kms_client_mock->ExpectEncryptAccumulator(ev.GetRequest(), ev.GetResult());
    TEST_ASSERT_SUCCESS(ev.kms_keyring->OnEncrypt(ev.kms_keyring,
                                                  ev.allocator,
                                                  &ev.unencrypted_data_key,
                                                  &ev.edks,
                                                  &ev.encryption_context,
                                                  ev.alg));

    TEST_ASSERT_SUCCESS(t_assert_edks_with_single_element_contains_expected_values(&ev.edks,
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
    ev.kms_client_mock->ExpectEncryptAccumulator(ev.GetRequest(key, pt, {}, ev.GetEncryptionContext()), ev.GetResult(key, ct));
    TEST_ASSERT_SUCCESS(t_append_c_str_key_to_edks(ev.allocator, &expected_edks, &ct, key, ev.provider_id));
    return AWS_OP_SUCCESS;
}

int encrypt_validInputsMultipleKeys_returnSuccess() {
    EncryptTestValues ev({"key1", "key2", "key3"});
    struct aws_array_list expected_edks;
    TEST_ASSERT_SUCCESS(aws_cryptosdk_edk_list_init(ev.allocator, &expected_edks));

    TEST_ASSERT_SUCCESS(expect_encrypt(expected_edks, ev, "key1", ev.pt, "ct1"));
    TEST_ASSERT_SUCCESS(expect_encrypt(expected_edks, ev, "key2", ev.pt, "ct2"));
    TEST_ASSERT_SUCCESS(expect_encrypt(expected_edks, ev, "key3", ev.pt, "ct3"));

    TEST_ASSERT_SUCCESS(ev.kms_keyring->OnEncrypt(ev.kms_keyring,
                                                  ev.allocator,
                                                  &ev.unencrypted_data_key,
                                                  &ev.edks,
                                                  &ev.encryption_context,
                                                  ev.alg));
    TEST_ASSERT_SUCCESS(t_assert_edks_equals(&ev.edks, &expected_edks));
    TEST_ASSERT(ev.kms_client_mock->ExpectingOtherCalls() == false);

    aws_cryptosdk_edk_list_clean_up(&expected_edks);

    return 0;
}

int encrypt_validInputsMultipleKeysWithGrantTokensAndEncContext_returnSuccess() {
    Aws::List<Aws::String> keys = {"key1", "key2", "key3"};
    Aws::Map <Aws::String, Aws::String> enc_context = { {"k1", "v1"}, {"k2", "v2"} };
    Aws::Vector<Aws::String> grant_tokens = { "gt1", "gt2" };

    EncryptTestValues ev(keys, grant_tokens);
    ev.SetEncryptionContext(enc_context);


    struct aws_array_list expected_edks;
    TEST_ASSERT_SUCCESS(aws_cryptosdk_edk_list_init(ev.allocator, &expected_edks));

    TEST_ASSERT_SUCCESS(expect_encrypt(expected_edks, ev, "key1", ev.pt, "ct1"));
    TEST_ASSERT_SUCCESS(expect_encrypt(expected_edks, ev, "key2", ev.pt, "ct2"));
    TEST_ASSERT_SUCCESS(expect_encrypt(expected_edks, ev, "key3", ev.pt, "ct3"));
    ev.kms_client_mock->ExpectGrantTokens(grant_tokens);


    TEST_ASSERT_SUCCESS(ev.kms_keyring->OnEncrypt(ev.kms_keyring,
                                                  ev.allocator,
                                                  &ev.unencrypted_data_key,
                                                  &ev.edks,
                                                  &ev.encryption_context,
                                                  ev.alg));
    TEST_ASSERT_SUCCESS(t_assert_edks_equals(&ev.edks, &expected_edks));
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
    TEST_ASSERT_SUCCESS(kms_keyring->OnEncrypt(kms_keyring,
                                               ev.allocator,
                                               &ev.unencrypted_data_key,
                                               &ev.edks,
                                               &ev.encryption_context,
                                               ev.alg));

    TEST_ASSERT_SUCCESS(t_assert_edks_with_single_element_contains_expected_values(&ev.edks,
                                                                                   ev.ct,
                                                                                   key.front().c_str(),
                                                                                   ev.provider_id,
                                                                                   ev.allocator));

    TEST_ASSERT(kms_client_mock->ExpectingOtherCalls() == false);

    Aws::Delete(kms_keyring);

    return 0;
}

int encrypt_multipleKeysOneFails_returnFail() {
    EncryptTestValues ev({"key1", "key2", "key3"});
    Aws::Utils::ByteBuffer ct = t_aws_utils_bb_from_char("expected_ct");
    Model::EncryptOutcome error_return; // this will set IsSuccess to false

    ev.kms_client_mock->ExpectEncryptAccumulator(ev.GetRequest("key1", ev.pt_bb), ev.GetResult("key1", ct));
    ev.kms_client_mock->ExpectEncryptAccumulator(ev.GetRequest("key2", ev.pt_bb), error_return);

    TEST_ASSERT_ERROR(AWS_CRYPTOSDK_ERR_KMS_FAILURE, ev.kms_keyring->OnEncrypt(ev.kms_keyring,
                                                                               ev.allocator,
                                                                               &ev.unencrypted_data_key,
                                                                               &ev.edks,
                                                                               &ev.encryption_context,
                                                                               ev.alg));

    TEST_ASSERT_INT_EQ(0, aws_array_list_length(&ev.edks));
    TEST_ASSERT(ev.kms_client_mock->ExpectingOtherCalls() == false);
    return 0;
}

// assuming that edks had already some elements before the EncryptDataKey call and we are not
// able to encrypt, we should't modify anything
int encrypt_multipleKeysOneFails_initialEdksAreNotAffected() {
    EncryptTestValues ev({"key1", "key2", "key3"});
    Model::EncryptOutcome error_return; // this will set IsSuccess to false
    const char *initial_ct = "initial_ct";
    auto initial_ct_bb = t_aws_utils_bb_from_char(initial_ct);
    const char *initial_key = "initial_key";

    // artificially add a new edk
    TEST_ASSERT_SUCCESS(t_append_c_str_key_to_edks(ev.allocator,
                                                   &ev.edks,
                                                   &initial_ct_bb,
                                                   initial_key,
                                                   ev.provider_id));


    // first request works
    ev.kms_client_mock->ExpectEncryptAccumulator(ev.GetRequest("key1", ev.pt_bb), ev.GetResult("key1", ev.ct_bb));
    // second request will fail
    ev.kms_client_mock->ExpectEncryptAccumulator(ev.GetRequest("key2", ev.pt_bb), error_return);

    TEST_ASSERT_ERROR(AWS_CRYPTOSDK_ERR_KMS_FAILURE, ev.kms_keyring->OnEncrypt(ev.kms_keyring,
                                                                               ev.allocator,
                                                                               &ev.unencrypted_data_key,
                                                                               &ev.edks,
                                                                               &ev.encryption_context,
                                                                               ev.alg));

    // we should have the initial edk
    TEST_ASSERT_SUCCESS(t_assert_edks_with_single_element_contains_expected_values(&ev.edks,
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
    TEST_ASSERT_ERROR(AWS_CRYPTOSDK_ERR_KMS_FAILURE, ev.kms_keyring->OnEncrypt(ev.kms_keyring,
                                                                               ev.allocator,
                                                                               &ev.unencrypted_data_key,
                                                                               &ev.edks,
                                                                               &ev.encryption_context,
                                                                               ev.alg));
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

    TEST_ASSERT_SUCCESS(dv.kms_keyring->OnDecrypt(dv.kms_keyring,
                                                  dv.allocator,
                                                  &dv.unencrypted_data_key,
                                                  &dv.edks.encrypted_data_keys,
                                                  &dv.encryption_context,
                                                  dv.alg));
    TEST_ASSERT(aws_byte_buf_eq(&dv.unencrypted_data_key, &dv.pt_aws_byte) == true);
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

    TEST_ASSERT_SUCCESS(kms_keyring->OnDecrypt(kms_keyring,
                                               dv.allocator,
                                               &dv.unencrypted_data_key,
                                               &dv.edks.encrypted_data_keys,
                                               &dv.encryption_context,
                                               dv.alg));
    TEST_ASSERT(aws_byte_buf_eq(&dv.unencrypted_data_key, &dv.pt_aws_byte) == true);
    TEST_ASSERT(kms_client_mock->ExpectingOtherCalls() == false);

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

    TEST_ASSERT_SUCCESS(dv.kms_keyring->OnDecrypt(dv.kms_keyring,
                                                  dv.allocator,
                                                  &dv.unencrypted_data_key,
                                                  &dv.edks.encrypted_data_keys,
                                                  &dv.encryption_context,
                                                  dv.alg));
    TEST_ASSERT_ADDR_EQ(0, dv.unencrypted_data_key.buffer);
    TEST_ASSERT(dv.kms_client_mock->ExpectingOtherCalls() == false);
    return 0;
}

int decrypt_noKeys_returnSuccess() {
    DecryptValues dv;
    Model::DecryptOutcome return_decrypt(dv.decrypt_result);

    TEST_ASSERT_SUCCESS(dv.kms_keyring->OnDecrypt(dv.kms_keyring,
                                                  dv.allocator,
                                                  &dv.unencrypted_data_key,
                                                  &dv.edks.encrypted_data_keys,
                                                  &dv.encryption_context,
                                                  dv.alg));
    TEST_ASSERT_ADDR_EQ(0, dv.unencrypted_data_key.buffer);
    TEST_ASSERT(dv.kms_client_mock->ExpectingOtherCalls() == false);
    return 0;
}

/**
 * Creates three edks and sets the corresponding expect calls for KMS client mock.
 * First two edks will be invalid, first one returns an error, second one has a key that has not been configured in
 * KmsKeyring and the third one will have the correct key id/provider
 */
int build_multiple_edks(DecryptValues &dv) {
    dv.kms_client_mock->ExpectGrantTokens(dv.grant_tokens);

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
    Model::DecryptOutcome return_decrypt3(MakeDecryptResult(dv.key_id, dv.pt));
    dv.kms_client_mock->ExpectDecryptAccumulator(dv.GetRequest(), return_decrypt3);

    return AWS_OP_SUCCESS;
}

int decrypt_validInputsWithMultipleEdks_returnSuccess() {
    DecryptValues dv;

    build_multiple_edks(dv);

    TEST_ASSERT_SUCCESS(dv.kms_keyring->OnDecrypt(dv.kms_keyring,
                                                  dv.allocator,
                                                  &dv.unencrypted_data_key,
                                                  &dv.edks.encrypted_data_keys,
                                                  &dv.encryption_context,
                                                  dv.alg));
    TEST_ASSERT(aws_byte_buf_eq(&dv.unencrypted_data_key, &dv.pt_aws_byte) == true);
    TEST_ASSERT(dv.kms_client_mock->ExpectingOtherCalls() == false);
    return 0;
}

int decrypt_validInputsWithMultipleEdksWithGrantTokensAndEncContext_returnSuccess() {
    Aws::Vector<Aws::String> grant_tokens = { "gt1", "gt2" };
    DecryptValues dv({ TestValues::key_id }, grant_tokens);

    Aws::Map <Aws::String, Aws::String> enc_context = { {"k1", "v1"}, {"k2", "v2"} };
    dv.SetEncryptionContext(enc_context);

    build_multiple_edks(dv);

    TEST_ASSERT_SUCCESS(dv.kms_keyring->OnDecrypt(dv.kms_keyring,
                                                  dv.allocator,
                                                  &dv.unencrypted_data_key,
                                                  &dv.edks.encrypted_data_keys,
                                                  &dv.encryption_context,
                                                  dv.alg));
    TEST_ASSERT(aws_byte_buf_eq(&dv.unencrypted_data_key, &dv.pt_aws_byte) == true);
    TEST_ASSERT(dv.kms_client_mock->ExpectingOtherCalls() == false);
    return 0;
}

int generateDataKey_validInputs_returnSuccess() {
    GenerateDataKeyValues gv;
    Model::GenerateDataKeyOutcome return_generate(gv.generate_result);

    gv.kms_client_mock->ExpectGenerateDataKey(gv.GetRequest(), return_generate);

    TEST_ASSERT_SUCCESS(gv.kms_keyring->OnEncrypt(gv.kms_keyring,
                                                  gv.allocator,
                                                  &gv.unencrypted_data_key,
                                                  &gv.edks,
                                                  &gv.encryption_context,
                                                  gv.alg));

    TEST_ASSERT_SUCCESS(t_assert_edks_with_single_element_contains_expected_values(&gv.edks,
                                                                                   gv.ct,
                                                                                   gv.key_id,
                                                                                   gv.provider_id,
                                                                                   gv.allocator));
    TEST_ASSERT(aws_byte_buf_eq(&gv.unencrypted_data_key, &gv.pt_aws_byte) == true);

    TEST_ASSERT(gv.kms_client_mock->ExpectingOtherCalls() == false);

    return 0;
}

int generateDataKey_validInputsWithGrantTokensAndEncContext_returnSuccess() {
    Aws::Vector<Aws::String> grant_tokens = { "gt1", "gt2" };
    GenerateDataKeyValues gv(grant_tokens);
    Model::GenerateDataKeyOutcome return_generate(gv.generate_result);

    Aws::Map <Aws::String, Aws::String> enc_context = { {"k1", "v1"}, {"k2", "v2"} };
    gv.SetEncryptionContext(enc_context);

    gv.kms_client_mock->ExpectGenerateDataKey(gv.GetRequest(), return_generate);
    gv.kms_client_mock->ExpectGrantTokens(grant_tokens);

    TEST_ASSERT_SUCCESS(gv.kms_keyring->OnEncrypt(gv.kms_keyring,
                                                  gv.allocator,
                                                  &gv.unencrypted_data_key,
                                                  &gv.edks,
                                                  &gv.encryption_context,
                                                  gv.alg));

    TEST_ASSERT_SUCCESS(t_assert_edks_with_single_element_contains_expected_values(&gv.edks,
                                                                                   gv.ct,
                                                                                   gv.key_id,
                                                                                   gv.provider_id,
                                                                                   gv.allocator));
    TEST_ASSERT(aws_byte_buf_eq(&gv.unencrypted_data_key, &gv.pt_aws_byte) == true);

    TEST_ASSERT(gv.kms_client_mock->ExpectingOtherCalls() == false);

    return 0;
}

int generateDataKey_kmsFails_returnFailure() {
    GenerateDataKeyValues gv;
    Model::GenerateDataKeyOutcome return_generate;  // if no parameter is set GenerateDataKeyValues.IsSuccess() is false

    gv.kms_client_mock->ExpectGenerateDataKey(gv.GetRequest(), return_generate);

    TEST_ASSERT_ERROR(AWS_CRYPTOSDK_ERR_KMS_FAILURE, gv.kms_keyring->OnEncrypt(gv.kms_keyring,
                                                                               gv.allocator,
                                                                               &gv.unencrypted_data_key,
                                                                               &gv.edks,
                                                                               &gv.encryption_context,
                                                                               gv.alg));

    TEST_ASSERT(gv.kms_client_mock->ExpectingOtherCalls() == false);

    return 0;
}

int createDecryptRequest_validInputes_returnRequest() {

    DecryptValues dv;
    dv.grant_tokens = {"gt1", "gt2"};
    Model::DecryptRequest outcome_out = dv.kms_keyring->CreateDecryptRequest(dv.key_id,
                                                                             dv.grant_tokens,
                                                                             dv.ct_bb,
                                                                             dv.GetEncryptionContext());

    TEST_ASSERT(outcome_out.GetCiphertextBlob() == dv.ct_bb);
    TEST_ASSERT(outcome_out.GetGrantTokens() == dv.grant_tokens);
    return 0;
}

int createGenerateDataKeyRequest_validInputes_returnRequest() {
    GenerateDataKeyValues gd;
    gd.grant_tokens = {"gt1", "gt2"};

    Model::GenerateDataKeyRequest outcome_out = gd.kms_keyring->CreateGenerateDataKeyRequest(gd.key_id,
                                                                                             gd.grant_tokens,
                                                                                             gd.generate_expected_value,
                                                                                             gd.GetEncryptionContext());

    TEST_ASSERT(outcome_out.GetKeyId() == gd.key_id);
    TEST_ASSERT(outcome_out.GetNumberOfBytes() == gd.generate_expected_value);
    TEST_ASSERT(outcome_out.GetGrantTokens() == gd.grant_tokens);

    return 0;
}

int createEncryptRequest_validInputes_returnRequest() {
    EncryptTestValues ev;
    ev.grant_tokens = {"gt1", "gt2"};

    Model::EncryptRequest outcome_out = ev.kms_keyring->CreateEncryptRequest(ev.key_id,
                                                                             ev.grant_tokens,
                                                                             ev.pt_bb,
                                                                             ev.GetEncryptionContext());

    TEST_ASSERT(outcome_out.GetKeyId() == ev.key_id);
    TEST_ASSERT(outcome_out.GetPlaintext() == ev.pt_bb);
    TEST_ASSERT(outcome_out.GetGrantTokens() == ev.grant_tokens);
    TEST_ASSERT(outcome_out.GetEncryptionContext() == ev.GetEncryptionContext());
    TEST_ASSERT(outcome_out.GetGrantTokens() == ev.grant_tokens);

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

int testBuilder_invalidInputs_returnFalse() {
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

int t_assert_encrypt_with_default_values(KmsMasterKeyExposer *kms_keyring, EncryptTestValues &ev) {
    TEST_ASSERT(kms_keyring != NULL);
    TEST_ASSERT_SUCCESS(kms_keyring->OnEncrypt(kms_keyring,
                                               ev.allocator,
                                               &ev.unencrypted_data_key,
                                               &ev.edks,
                                               &ev.encryption_context,
                                               ev.alg));
    TEST_ASSERT_SUCCESS(t_assert_edks_with_single_element_contains_expected_values(&ev.edks,
                                                                                   ev.ct,
                                                                                   ev.key_id,
                                                                                   ev.provider_id,
                                                                                   ev.allocator));
    return 0;
}

int testKmsClientCache_cacheAlreadyContainValues_sameInitializedClientIsUsed() {
    EncryptTestValues ev1;
    EncryptTestValues ev2;
    std::shared_ptr<KmsKeyring::KmsClientCache> client_cache = Aws::MakeShared<KmsKeyring::KmsClientCache>("test");
    auto kms_cached_client_mock(Aws::MakeShared<KmsClientMock>(CLASS_TAG));
    client_cache->SaveInCache("default_region", kms_cached_client_mock);

    KmsMasterKeyExposer *kms_keyring1 = Aws::New<KmsMasterKeyExposer>("TEST_CTOR",
                                                                      aws_default_allocator(),
                                                                      ev1.kms_client_mock,
                                                                      Aws::List<Aws::String>{ev1.key_id},
                                                                      Aws::Vector<Aws::String>{},
                                                                      client_cache);
    KmsMasterKeyExposer *kms_keyring2 = Aws::New<KmsMasterKeyExposer>("TEST_CTOR",
                                                                      aws_default_allocator(),
                                                                      ev2.kms_client_mock,
                                                                      Aws::List<Aws::String>{ev2.key_id},
                                                                      Aws::Vector<Aws::String>{},
                                                                      client_cache);

    // Kms_keyring should use kms_cached_client_mock because is already in cache and should not try to use the
    // ev1.kms_client_mock or ev2.kms_client_mock
    kms_cached_client_mock->ExpectEncryptAccumulator(ev1.GetRequest(), ev1.GetResult());
    kms_cached_client_mock->ExpectEncryptAccumulator(ev2.GetRequest(), ev2.GetResult());

    TEST_ASSERT_SUCCESS(t_assert_encrypt_with_default_values(kms_keyring1, ev1));
    TEST_ASSERT_SUCCESS(t_assert_encrypt_with_default_values(kms_keyring2, ev2));
    Aws::Delete(kms_keyring1);
    Aws::Delete(kms_keyring2);

    return 0;
}

int testKmsClientCache_cacheDoesNotContainValues_cacheWillBePopulatedWithValues() {
    EncryptTestValues ev1;
    EncryptTestValues ev2;

    std::shared_ptr<KmsKeyring::KmsClientCache> client_cache = Aws::MakeShared<KmsKeyring::KmsClientCache>("test");
    auto kms_cached_client_mock(Aws::MakeShared<KmsClientMock>(CLASS_TAG));

    KmsMasterKeyExposer *kms_keyring1 = Aws::New<KmsMasterKeyExposer>("TEST_CTOR",
                                                                      aws_default_allocator(),
                                                                      ev1.kms_client_mock,
                                                                      Aws::List<Aws::String>{ev1.key_id},
                                                                      Aws::Vector<Aws::String>{},
                                                                      client_cache);
    KmsMasterKeyExposer *kms_keyring2 = Aws::New<KmsMasterKeyExposer>("TEST_CTOR",
                                                                      aws_default_allocator(),
                                                                      ev2.kms_client_mock,
                                                                      Aws::List<Aws::String>{ev2.key_id},
                                                                      Aws::Vector<Aws::String>{},
                                                                      client_cache);

    // Kms_keyring1 should use ev1.kms_client_mock and then to store it in client_cache. The call of kms_keyring2
    // should pick kms_client from the cache (ev1.kms_client_mock) instead of using its own
    ev1.kms_client_mock->ExpectEncryptAccumulator(ev1.GetRequest(), ev1.GetResult());
    ev1.kms_client_mock->ExpectEncryptAccumulator(ev2.GetRequest(), ev2.GetResult());

    TEST_ASSERT_SUCCESS(t_assert_encrypt_with_default_values(kms_keyring1, ev1));
    TEST_ASSERT_SUCCESS(t_assert_encrypt_with_default_values(kms_keyring2, ev2));

    Aws::Delete(kms_keyring1);
    Aws::Delete(kms_keyring2);

    return 0;
}

int main() {
    Aws::SDKOptions *options = Aws::New<Aws::SDKOptions>(CLASS_TAG);
    Aws::InitAPI(*options);

    aws_load_error_strings();
    aws_cryptosdk_err_init_strings();

    RUN_TEST(encrypt_validInputs_returnSuccess());
    RUN_TEST(encrypt_kmsFails_returnError());
    RUN_TEST(encrypt_validInputsMultipleKeys_returnSuccess());
    RUN_TEST(encrypt_validInputsMultipleKeysWithGrantTokensAndEncContext_returnSuccess());
    RUN_TEST(encrypt_emptyRegionNameInKeys_returnSuccess());
    RUN_TEST(encrypt_multipleKeysOneFails_returnFail());
    RUN_TEST(encrypt_multipleKeysOneFails_initialEdksAreNotAffected());
    RUN_TEST(decrypt_validInputs_returnSuccess());
    RUN_TEST(decrypt_emptyRegionNameInKeys_returnSuccess());
    RUN_TEST(decrypt_validInputsButNoKeyMatched_returnSuccess());
    RUN_TEST(decrypt_noKeys_returnSuccess());
    RUN_TEST(decrypt_validInputsWithMultipleEdks_returnSuccess());
    RUN_TEST(decrypt_validInputsWithMultipleEdksWithGrantTokensAndEncContext_returnSuccess());
    RUN_TEST(generateDataKey_validInputs_returnSuccess());
    RUN_TEST(generateDataKey_validInputsWithGrantTokensAndEncContext_returnSuccess());
    RUN_TEST(generateDataKey_kmsFails_returnFailure());
    RUN_TEST(createDecryptRequest_validInputes_returnRequest());
    RUN_TEST(createGenerateDataKeyRequest_validInputes_returnRequest());
    RUN_TEST(createEncryptRequest_validInputes_returnRequest());
    RUN_TEST(testBuilder_buildDefaultRegion_buildsRegion());
    RUN_TEST(testBuilder_buildClientSupplier_buildsClient());
    RUN_TEST(testBuilder_invalidInputs_returnFalse());
    RUN_TEST(testBuilder_allocator_returnAlloc());
    RUN_TEST(testKmsClientCache_cacheAlreadyContainValues_sameInitializedClientIsUsed());
    RUN_TEST(testKmsClientCache_cacheDoesNotContainValues_cacheWillBePopulatedWithValues());

    Aws::ShutdownAPI(*options);
    Aws::Delete(options);
    return 0;
}
