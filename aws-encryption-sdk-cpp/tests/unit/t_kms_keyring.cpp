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

#include <aws/cryptosdk/enc_context.h>
#include <aws/cryptosdk/private/kms_keyring.h>
#include <aws/cryptosdk/private/cpputils.h>

#include "kms_client_mock.h"
#include "testutil.h"
#include "edks_utils.h"

using namespace Aws::Cryptosdk;
using namespace Aws::Cryptosdk::Private;
using namespace Aws::Cryptosdk::Testing;

const char *CLASS_TAG = "KMS_UNIT_TESTS_CTAG";

struct aws_cryptosdk_keyring *CreateTestingKeyring(std::shared_ptr<Aws::KMS::KMSClient> kms,
                                                   const Aws::Vector<Aws::String> &key_ids,
                                                   const Aws::Vector<Aws::String> &grant_tokens = { }) {
    Aws::Cryptosdk::KmsKeyring::Builder builder;
    return builder.WithKmsClient(kms).WithGrantTokens(grant_tokens).Build(key_ids);
}

struct aws_cryptosdk_keyring *CreateTestingKeyring(std::shared_ptr<Aws::KMS::KMSClient> kms,
                                                   const Aws::String &key_id) {
    Aws::Cryptosdk::KmsKeyring::Builder builder;
    return builder.WithKmsClient(kms).Build({key_id});
}

Aws::Utils::ByteBuffer t_aws_utils_bb_from_char(const char *str) {
    return Aws::Utils::ByteBuffer((unsigned char *) str, strlen(str));
}

/**
 * Values used in all tests
 */
struct TestValues {
    const char *pt = "Random plain txt"; // 16 bytes = AES-128 data key
    const char *ct = "expected_ct";
    const static char *key_id;
    const char *provider_id = "aws-kms";

    struct aws_allocator *allocator;
    std::shared_ptr<KmsClientMock> kms_client_mock;
    struct aws_cryptosdk_keyring *kms_keyring;
    Aws::Utils::ByteBuffer pt_bb;
    Aws::Utils::ByteBuffer ct_bb;
    aws_byte_buf pt_aws_byte;
    struct aws_hash_table encryption_context;
    struct aws_array_list edks; // used in encrypt and generate, not decrypt
    struct aws_array_list keyring_trace;
    Aws::Vector<Aws::String> grant_tokens;

    TestValues() : TestValues({ key_id }) {
    };

    TestValues(const Aws::Vector<Aws::String> &key_ids, const Aws::Vector<Aws::String> &grant_tokens = { })
                 : allocator(aws_default_allocator()),
                   kms_client_mock(Aws::MakeShared<KmsClientMock>(CLASS_TAG)),
                   kms_keyring(CreateTestingKeyring(std::shared_ptr<Aws::KMS::KMSClient>(kms_client_mock),
                                                    key_ids,
                                                    grant_tokens)),
                   pt_bb((unsigned char *) pt, strlen(pt)),
                   ct_bb((unsigned char *) ct, strlen(ct)),
                   pt_aws_byte(aws_byte_buf_from_c_str(pt)),
                   grant_tokens(grant_tokens) {
        aws_cryptosdk_enc_context_init(allocator, &encryption_context);
        aws_cryptosdk_keyring_trace_init(allocator, &keyring_trace);
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
        aws_cryptosdk_keyring_release(kms_keyring);
        aws_cryptosdk_enc_context_clean_up(&encryption_context);
        aws_cryptosdk_keyring_trace_clean_up(&keyring_trace);
    }
};

const char *TestValues::key_id = "arn:aws:kms:us-west-2:658956600833:key/01234567-89ab-cdef-fedc-ba9876543210";

struct EncryptTestValues : public TestValues {
    enum aws_cryptosdk_alg_id alg;
    struct aws_byte_buf unencrypted_data_key;

    EncryptTestValues() : EncryptTestValues( { key_id } ) {

    }
    EncryptTestValues(const Aws::Vector<Aws::String> &key_ids, const Aws::Vector<Aws::String> &grant_tokens = { })
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
    Aws::Utils::ByteBuffer pt((uint8_t *) plaintext, strlen(plaintext));

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

    DecryptValues(const Aws::Vector<Aws::String> &key_ids, const Aws::Vector<Aws::String> &grant_tokens = { })
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


static int t_encrypt_with_single_key_success(TestValues &tv, bool generated) {
    TEST_ASSERT_SUCCESS(t_assert_edks_with_single_element_contains_expected_values(
                            &tv.edks,
                            tv.ct,
                            tv.key_id,
                            tv.provider_id,
                            tv.allocator));
    TEST_ASSERT_INT_EQ(aws_array_list_length(&tv.keyring_trace), 1);

    uint32_t flags = AWS_CRYPTOSDK_WRAPPING_KEY_ENCRYPTED_DATA_KEY |
        AWS_CRYPTOSDK_WRAPPING_KEY_SIGNED_ENC_CTX;
    if (generated) flags |= AWS_CRYPTOSDK_WRAPPING_KEY_GENERATED_DATA_KEY;

    return assert_keyring_trace_record(&tv.keyring_trace, 0, flags, tv.provider_id, tv.key_id);
}


int encrypt_validInputs_returnSuccess() {
    EncryptTestValues ev;

    ev.kms_client_mock->ExpectEncryptAccumulator(ev.GetRequest(), ev.GetResult());
    TEST_ASSERT_SUCCESS(aws_cryptosdk_keyring_on_encrypt(ev.kms_keyring,
                                                         ev.allocator,
                                                         &ev.unencrypted_data_key,
                                                         &ev.keyring_trace,
                                                         &ev.edks,
                                                         &ev.encryption_context,
                                                         ev.alg));

    TEST_ASSERT_SUCCESS(t_encrypt_with_single_key_success(ev, false));

    TEST_ASSERT(!ev.kms_client_mock->ExpectingOtherCalls());
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

const Aws::Vector<Aws::String> fake_arns = {"arn:aws:kms:us-fake-1:999999999999:key/1",
                                            "arn:aws:kms:us-fake-1:999999999999:key/2",
                                            "arn:aws:kms:us-fake-1:999999999999:key/3"};

static int t_encrypt_multiple_keys_trace_success(struct aws_array_list *keyring_trace) {
    uint32_t flags = AWS_CRYPTOSDK_WRAPPING_KEY_ENCRYPTED_DATA_KEY |
        AWS_CRYPTOSDK_WRAPPING_KEY_SIGNED_ENC_CTX;
    for (unsigned int i = 0; i < fake_arns.size(); i++)	{
        TEST_ASSERT_SUCCESS(assert_keyring_trace_record(keyring_trace, i, flags, "aws-kms",
                                                      fake_arns[i].c_str()));
    }
}

int encrypt_validInputsMultipleKeys_returnSuccess() {
    EncryptTestValues ev(fake_arns);
    struct aws_array_list expected_edks;
    TEST_ASSERT_SUCCESS(aws_cryptosdk_edk_list_init(ev.allocator, &expected_edks));

    TEST_ASSERT_SUCCESS(expect_encrypt(expected_edks, ev, fake_arns[0].c_str(), ev.pt, "ct1"));
    TEST_ASSERT_SUCCESS(expect_encrypt(expected_edks, ev, fake_arns[1].c_str(), ev.pt, "ct2"));
    TEST_ASSERT_SUCCESS(expect_encrypt(expected_edks, ev, fake_arns[2].c_str(), ev.pt, "ct3"));

    TEST_ASSERT_SUCCESS(aws_cryptosdk_keyring_on_encrypt(ev.kms_keyring,
                                                         ev.allocator,
                                                         &ev.unencrypted_data_key,
                                                         &ev.keyring_trace,
                                                         &ev.edks,
                                                         &ev.encryption_context,
                                                         ev.alg));
    TEST_ASSERT_SUCCESS(t_assert_edks_equals(&ev.edks, &expected_edks));
    TEST_ASSERT_SUCCESS(t_encrypt_multiple_keys_trace_success(&ev.keyring_trace));

    TEST_ASSERT(!ev.kms_client_mock->ExpectingOtherCalls());

    aws_cryptosdk_edk_list_clean_up(&expected_edks);

    return 0;
}

int encrypt_validInputsMultipleKeysWithGrantTokensAndEncContext_returnSuccess() {
    Aws::Map <Aws::String, Aws::String> enc_context = { {"k1", "v1"}, {"k2", "v2"} };
    Aws::Vector<Aws::String> grant_tokens = { "gt1", "gt2" };

    EncryptTestValues ev(fake_arns, grant_tokens);
    ev.SetEncryptionContext(enc_context);


    struct aws_array_list expected_edks;
    TEST_ASSERT_SUCCESS(aws_cryptosdk_edk_list_init(ev.allocator, &expected_edks));

    TEST_ASSERT_SUCCESS(expect_encrypt(expected_edks, ev, fake_arns[0].c_str(), ev.pt, "ct1"));
    TEST_ASSERT_SUCCESS(expect_encrypt(expected_edks, ev, fake_arns[1].c_str(), ev.pt, "ct2"));
    TEST_ASSERT_SUCCESS(expect_encrypt(expected_edks, ev, fake_arns[2].c_str(), ev.pt, "ct3"));
    ev.kms_client_mock->ExpectGrantTokens(grant_tokens);


    TEST_ASSERT_SUCCESS(aws_cryptosdk_keyring_on_encrypt(ev.kms_keyring,
                                                         ev.allocator,
                                                         &ev.unencrypted_data_key,
                                                         &ev.keyring_trace,
                                                         &ev.edks,
                                                         &ev.encryption_context,
                                                         ev.alg));
    TEST_ASSERT_SUCCESS(t_assert_edks_equals(&ev.edks, &expected_edks));
    TEST_ASSERT_SUCCESS(t_encrypt_multiple_keys_trace_success(&ev.keyring_trace));

    TEST_ASSERT(!ev.kms_client_mock->ExpectingOtherCalls());

    aws_cryptosdk_edk_list_clean_up(&expected_edks);

    return 0;
}

int encrypt_multipleKeysOneFails_returnFail() {
    EncryptTestValues ev(fake_arns);
    Aws::Utils::ByteBuffer ct = t_aws_utils_bb_from_char("expected_ct");
    Model::EncryptOutcome error_return; // this will set IsSuccess to false

    ev.kms_client_mock->ExpectEncryptAccumulator(ev.GetRequest(fake_arns[0], ev.pt_bb), ev.GetResult(fake_arns[0], ct));
    ev.kms_client_mock->ExpectEncryptAccumulator(ev.GetRequest(fake_arns[1], ev.pt_bb), error_return);

    TEST_ASSERT_ERROR(AWS_CRYPTOSDK_ERR_KMS_FAILURE, aws_cryptosdk_keyring_on_encrypt(ev.kms_keyring,
                                                                                      ev.allocator,
                                                                                      &ev.unencrypted_data_key,
                                                                                      &ev.keyring_trace,
                                                                                      &ev.edks,
                                                                                      &ev.encryption_context,
                                                                                      ev.alg));

    TEST_ASSERT_INT_EQ(0, aws_array_list_length(&ev.edks));
    TEST_ASSERT(!ev.kms_client_mock->ExpectingOtherCalls());
    return 0;
}

// assuming that edks had already some elements before the EncryptDataKey call and we are not
// able to encrypt, we should't modify anything
int encrypt_multipleKeysOneFails_initialEdksAreNotAffected() {
    EncryptTestValues ev(fake_arns);
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
    ev.kms_client_mock->ExpectEncryptAccumulator(ev.GetRequest(fake_arns[0], ev.pt_bb), ev.GetResult(fake_arns[0], ev.ct_bb));
    // second request will fail
    ev.kms_client_mock->ExpectEncryptAccumulator(ev.GetRequest(fake_arns[1], ev.pt_bb), error_return);

    TEST_ASSERT_ERROR(AWS_CRYPTOSDK_ERR_KMS_FAILURE, aws_cryptosdk_keyring_on_encrypt(ev.kms_keyring,
                                                                                      ev.allocator,
                                                                                      &ev.unencrypted_data_key,
                                                                                      &ev.keyring_trace,
                                                                                      &ev.edks,
                                                                                      &ev.encryption_context,
                                                                                      ev.alg));

    // we should have the initial edk
    TEST_ASSERT_SUCCESS(t_assert_edks_with_single_element_contains_expected_values(&ev.edks,
                                                                                   initial_ct,
                                                                                   initial_key,
                                                                                   ev.provider_id,
                                                                                   ev.allocator));

    TEST_ASSERT(!ev.kms_client_mock->ExpectingOtherCalls());
    return 0;
}


int encrypt_kmsFails_returnError() {
    EncryptTestValues ev;
    Model::EncryptOutcome return_encrypt; // if no parameter is set the EncryptOutcome.IsSuccess is false

    ev.kms_client_mock->ExpectEncryptAccumulator(ev.GetRequest(), return_encrypt);
    TEST_ASSERT_ERROR(AWS_CRYPTOSDK_ERR_KMS_FAILURE, aws_cryptosdk_keyring_on_encrypt(ev.kms_keyring,
                                                                                      ev.allocator,
                                                                                      &ev.unencrypted_data_key,
                                                                                      &ev.keyring_trace,
                                                                                      &ev.edks,
                                                                                      &ev.encryption_context,
                                                                                      ev.alg));
    return 0;
}

static int t_decrypt_success(DecryptValues &dv) {
    TEST_ASSERT(aws_byte_buf_eq(&dv.unencrypted_data_key, &dv.pt_aws_byte));
    return assert_keyring_trace_record(&dv.keyring_trace,
                                     aws_array_list_length(&dv.keyring_trace) - 1,
                                     AWS_CRYPTOSDK_WRAPPING_KEY_DECRYPTED_DATA_KEY |
                                     AWS_CRYPTOSDK_WRAPPING_KEY_VERIFIED_ENC_CTX,
                                     "aws-kms",
                                     dv.key_id);
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

    TEST_ASSERT_SUCCESS(aws_cryptosdk_keyring_on_decrypt(dv.kms_keyring,
                                                         dv.allocator,
                                                         &dv.unencrypted_data_key,
                                                         &dv.keyring_trace,
                                                         &dv.edks.encrypted_data_keys,
                                                         &dv.encryption_context,
                                                         dv.alg));
    TEST_ASSERT_SUCCESS(t_decrypt_success(dv));
    TEST_ASSERT(!dv.kms_client_mock->ExpectingOtherCalls());
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

    TEST_ASSERT_SUCCESS(aws_cryptosdk_keyring_on_decrypt(dv.kms_keyring,
                                                         dv.allocator,
                                                         &dv.unencrypted_data_key,
                                                         &dv.keyring_trace,
                                                         &dv.edks.encrypted_data_keys,
                                                         &dv.encryption_context,
                                                         dv.alg));
    TEST_ASSERT(!aws_array_list_length(&dv.keyring_trace));
    TEST_ASSERT_ADDR_EQ(0, dv.unencrypted_data_key.buffer);
    TEST_ASSERT(!dv.kms_client_mock->ExpectingOtherCalls());
    return 0;
}

int decrypt_noKeys_returnSuccess() {
    DecryptValues dv;
    Model::DecryptOutcome return_decrypt(dv.decrypt_result);

    TEST_ASSERT_SUCCESS(aws_cryptosdk_keyring_on_decrypt(dv.kms_keyring,
                                                         dv.allocator,
                                                         &dv.unencrypted_data_key,
                                                         &dv.keyring_trace,
                                                         &dv.edks.encrypted_data_keys,
                                                         &dv.encryption_context,
                                                         dv.alg));
    TEST_ASSERT(!aws_array_list_length(&dv.keyring_trace));
    TEST_ASSERT_ADDR_EQ(0, dv.unencrypted_data_key.buffer);
    TEST_ASSERT(!dv.kms_client_mock->ExpectingOtherCalls());
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

    TEST_ASSERT_SUCCESS(aws_cryptosdk_keyring_on_decrypt(dv.kms_keyring,
                                                         dv.allocator,
                                                         &dv.unencrypted_data_key,
                                                         &dv.keyring_trace,
                                                         &dv.edks.encrypted_data_keys,
                                                         &dv.encryption_context,
                                                         dv.alg));
    TEST_ASSERT_SUCCESS(t_decrypt_success(dv));
    TEST_ASSERT(!dv.kms_client_mock->ExpectingOtherCalls());
    return 0;
}

int decrypt_validInputsWithMultipleEdksWithGrantTokensAndEncContext_returnSuccess() {
    Aws::Vector<Aws::String> grant_tokens = { "gt1", "gt2" };
    DecryptValues dv({ TestValues::key_id }, grant_tokens);

    Aws::Map <Aws::String, Aws::String> enc_context = { {"k1", "v1"}, {"k2", "v2"} };
    dv.SetEncryptionContext(enc_context);

    build_multiple_edks(dv);

    TEST_ASSERT_SUCCESS(aws_cryptosdk_keyring_on_decrypt(dv.kms_keyring,
                                                         dv.allocator,
                                                         &dv.unencrypted_data_key,
                                                         &dv.keyring_trace,
                                                         &dv.edks.encrypted_data_keys,
                                                         &dv.encryption_context,
                                                         dv.alg));
    TEST_ASSERT_SUCCESS(t_decrypt_success(dv));
    TEST_ASSERT(!dv.kms_client_mock->ExpectingOtherCalls());
    return 0;
}

int generateDataKey_validInputs_returnSuccess() {
    GenerateDataKeyValues gv;
    Model::GenerateDataKeyOutcome return_generate(gv.generate_result);

    gv.kms_client_mock->ExpectGenerateDataKey(gv.GetRequest(), return_generate);

    TEST_ASSERT_SUCCESS(aws_cryptosdk_keyring_on_encrypt(gv.kms_keyring,
                                                         gv.allocator,
                                                         &gv.unencrypted_data_key,
                                                         &gv.keyring_trace,
                                                         &gv.edks,
                                                         &gv.encryption_context,
                                                         gv.alg));

    TEST_ASSERT_SUCCESS(t_encrypt_with_single_key_success(gv, true));
    TEST_ASSERT(aws_byte_buf_eq(&gv.unencrypted_data_key, &gv.pt_aws_byte));

    TEST_ASSERT(!gv.kms_client_mock->ExpectingOtherCalls());

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

    TEST_ASSERT_SUCCESS(aws_cryptosdk_keyring_on_encrypt(gv.kms_keyring,
                                                         gv.allocator,
                                                         &gv.unencrypted_data_key,
                                                         &gv.keyring_trace,
                                                         &gv.edks,
                                                         &gv.encryption_context,
                                                         gv.alg));

    TEST_ASSERT_SUCCESS(t_encrypt_with_single_key_success(gv, true));
    TEST_ASSERT(aws_byte_buf_eq(&gv.unencrypted_data_key, &gv.pt_aws_byte));

    TEST_ASSERT(!gv.kms_client_mock->ExpectingOtherCalls());

    return 0;
}

int generateDataKey_kmsFails_returnFailure() {
    GenerateDataKeyValues gv;
    Model::GenerateDataKeyOutcome return_generate;  // if no parameter is set GenerateDataKeyValues.IsSuccess() is false

    gv.kms_client_mock->ExpectGenerateDataKey(gv.GetRequest(), return_generate);

    TEST_ASSERT_ERROR(AWS_CRYPTOSDK_ERR_KMS_FAILURE, aws_cryptosdk_keyring_on_encrypt(gv.kms_keyring,
                                                                                      gv.allocator,
                                                                                      &gv.unencrypted_data_key,
                                                                                      &gv.keyring_trace,
                                                                                      &gv.edks,
                                                                                      &gv.encryption_context,
                                                                                      gv.alg));
    TEST_ASSERT(!aws_array_list_length(&gv.edks));
    TEST_ASSERT(!aws_array_list_length(&gv.keyring_trace));
    TEST_ASSERT(!gv.kms_client_mock->ExpectingOtherCalls());

    return 0;
}

// exposes protected members
struct KmsKeyringBuilderExposer : KmsKeyring::Builder {
  public:
    using KmsKeyring::Builder::BuildClientSupplier;
    using KmsKeyring::Builder::ValidParameters;
};

int testBuilder_buildClientSupplier_buildsClient() {
    KmsKeyringBuilderExposer a;
    TEST_ASSERT(dynamic_cast<KmsKeyring::CachingClientSupplier*>(
                    a.BuildClientSupplier({"arn:aws:kms:region1:", "arn:aws:kms:region2:"}).get()) != NULL);

    TestValues tv;
    a.WithKmsClient(tv.kms_client_mock);
    TEST_ASSERT(dynamic_cast<KmsKeyring::SingleClientSupplier*>(
                    a.BuildClientSupplier({"arn:aws:kms:region:"}).get()) != NULL);

    return 0;
}

int testBuilder_noKeys_invalid() {
    KmsKeyringBuilderExposer a;
    // no keys
    Aws::Vector<Aws::String> empty_key_id_list;
    TEST_ASSERT(!a.Build(empty_key_id_list));
    return 0;
}

int testBuilder_keyWithRegion_valid() {
    KmsKeyringBuilderExposer a;
    aws_cryptosdk_keyring *k = a.Build({"arn:aws:kms:region_extracted_from_key:"});
    TEST_ASSERT_ADDR_NOT_NULL(k);
    aws_cryptosdk_keyring_release(k);
    return 0;
}

int testBuilder_keyWithoutRegion_invalid() {
    KmsKeyringBuilderExposer a;
    TEST_ASSERT_ADDR_NULL(a.Build({"alias/foobar"}));
    return 0;
}

int testBuilder_emptyKey_invalid() {
    KmsKeyringBuilderExposer a;
    TEST_ASSERT_ADDR_NULL(a.Build({""}));
    return 0;
}

int t_assert_encrypt_with_default_values(aws_cryptosdk_keyring *kms_keyring, EncryptTestValues &ev) {
    TEST_ASSERT(kms_keyring != NULL);
    TEST_ASSERT_SUCCESS(aws_cryptosdk_keyring_on_encrypt(kms_keyring,
                                                         ev.allocator,
                                                         &ev.unencrypted_data_key,
                                                         &ev.keyring_trace,
                                                         &ev.edks,
                                                         &ev.encryption_context,
                                                         ev.alg));

    TEST_ASSERT_SUCCESS(t_encrypt_with_single_key_success(ev, false));
    return 0;
}

int main() {
    Aws::SDKOptions *options = Aws::New<Aws::SDKOptions>(CLASS_TAG);
    Aws::InitAPI(*options);

    aws_cryptosdk_load_error_strings();

    RUN_TEST(encrypt_validInputs_returnSuccess());
    RUN_TEST(encrypt_kmsFails_returnError());
    RUN_TEST(encrypt_validInputsMultipleKeys_returnSuccess());
    RUN_TEST(encrypt_validInputsMultipleKeysWithGrantTokensAndEncContext_returnSuccess());
    RUN_TEST(encrypt_multipleKeysOneFails_returnFail());
    RUN_TEST(encrypt_multipleKeysOneFails_initialEdksAreNotAffected());
    RUN_TEST(decrypt_validInputs_returnSuccess());
    RUN_TEST(decrypt_validInputsButNoKeyMatched_returnSuccess());
    RUN_TEST(decrypt_noKeys_returnSuccess());
    RUN_TEST(decrypt_validInputsWithMultipleEdks_returnSuccess());
    RUN_TEST(decrypt_validInputsWithMultipleEdksWithGrantTokensAndEncContext_returnSuccess());
    RUN_TEST(generateDataKey_validInputs_returnSuccess());
    RUN_TEST(generateDataKey_validInputsWithGrantTokensAndEncContext_returnSuccess());
    RUN_TEST(generateDataKey_kmsFails_returnFailure());
    RUN_TEST(testBuilder_buildClientSupplier_buildsClient());
    RUN_TEST(testBuilder_noKeys_invalid());
    RUN_TEST(testBuilder_keyWithRegion_valid());
    RUN_TEST(testBuilder_keyWithoutRegion_invalid());
    RUN_TEST(testBuilder_emptyKey_invalid());

    Aws::ShutdownAPI(*options);
    Aws::Delete(options);
    return 0;
}
