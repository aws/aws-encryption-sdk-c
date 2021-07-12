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

#include "edks_utils.h"
#include "kms_client_mock.h"
#include "testutil.h"

using namespace Aws::Cryptosdk;
using namespace Aws::Cryptosdk::Private;
using namespace Aws::Cryptosdk::Testing;

const char *CLASS_TAG = "KMS_UNIT_TESTS_CTAG";

struct aws_cryptosdk_keyring *CreateTestingKeyring(
    std::shared_ptr<Aws::KMS::KMSClient> kms,
    const Aws::Vector<Aws::String> &key_ids,
    const Aws::Vector<Aws::String> &grant_tokens = {}) {
    Aws::Vector<Aws::String> additional_key_ids;
    for (auto it = ++key_ids.begin(); it != key_ids.end(); ++it) {
        additional_key_ids.push_back(*it);
    }

    Aws::Cryptosdk::KmsKeyring::Builder builder;
    return builder.WithKmsClient(kms).WithGrantTokens(grant_tokens).Build(key_ids[0], additional_key_ids);
}

struct aws_cryptosdk_keyring *CreateTestingKeyring(
    std::shared_ptr<Aws::KMS::KMSClient> kms, const Aws::String &key_id) {
    Aws::Cryptosdk::KmsKeyring::Builder builder;
    return builder.WithKmsClient(kms).Build(key_id);
}

Aws::Utils::ByteBuffer t_aws_utils_bb_from_char(const char *str) {
    return Aws::Utils::ByteBuffer((unsigned char *)str, strlen(str));
}

/**
 * Values used in all tests
 */
struct TestValues {
    const char *pt = "Random plain txt";  // 16 bytes = AES-128 data key
    const char *ct = "expected_ct";
    const static char *key_id;
    const static char *key_region;
    const char *provider_id = "aws-kms";

    struct aws_allocator *allocator;
    std::shared_ptr<KmsClientMock> kms_client_mock;
    struct aws_cryptosdk_keyring *kms_keyring;
    Aws::Utils::ByteBuffer pt_bb;
    Aws::Utils::ByteBuffer ct_bb;
    aws_byte_buf pt_aws_byte;
    struct aws_hash_table encryption_context;
    struct aws_array_list edks;  // used in encrypt, generate, and decrypt
    struct aws_array_list keyring_trace;
    Aws::Vector<Aws::String> grant_tokens;

    TestValues() : TestValues({ key_id }){};

    TestValues(const Aws::Vector<Aws::String> &key_ids, const Aws::Vector<Aws::String> &grant_tokens = {})
        : allocator(aws_default_allocator()),
          kms_client_mock(Aws::MakeShared<KmsClientMock>(CLASS_TAG)),
          kms_keyring(
              CreateTestingKeyring(std::shared_ptr<Aws::KMS::KMSClient>(kms_client_mock), key_ids, grant_tokens)),
          pt_bb((unsigned char *)pt, strlen(pt)),
          ct_bb((unsigned char *)ct, strlen(ct)),
          pt_aws_byte(aws_byte_buf_from_c_str(pt)),
          grant_tokens(grant_tokens) {
        if (aws_cryptosdk_enc_ctx_init(allocator, &encryption_context)) abort();
        if (aws_cryptosdk_keyring_trace_init(allocator, &keyring_trace)) abort();
        if (aws_cryptosdk_edk_list_init(allocator, &edks)) abort();
    }

    /**
     * Inserts inside the encryption_context member values from in_encryption_context
     */
    int SetEncryptionContext(Aws::Map<Aws::String, Aws::String> in_encryption_context) {
        struct aws_hash_element *p_elem;
        int was_created;

        for (auto entry : in_encryption_context) {
            const struct aws_string *key   = aws_string_new_from_c_str(allocator, entry.first.c_str());
            const struct aws_string *value = aws_string_new_from_c_str(allocator, entry.second.c_str());

            TEST_ASSERT_SUCCESS(aws_hash_table_create(&encryption_context, (void *)key, &p_elem, &was_created));
            p_elem->value = (void *)value;
        }

        return AWS_OP_SUCCESS;
    }

    Aws::Map<Aws::String, Aws::String> GetEncryptionContext() const {
        return aws_map_from_c_aws_hash_table(&encryption_context);
    }

    ~TestValues() {
        aws_cryptosdk_keyring_release(kms_keyring);
        aws_cryptosdk_enc_ctx_clean_up(&encryption_context);
        aws_cryptosdk_keyring_trace_clean_up(&keyring_trace);
        aws_cryptosdk_edk_list_clean_up(&edks);
    }
};

const char *TestValues::key_id     = "arn:aws:kms:us-west-2:658956600833:key/01234567-89ab-cdef-fedc-ba9876543210";
const char *TestValues::key_region = "us-west-2";

struct EncryptTestValues : public TestValues {
    enum aws_cryptosdk_alg_id alg;
    struct aws_byte_buf unencrypted_data_key;

    EncryptTestValues() : EncryptTestValues({ key_id }) {}
    EncryptTestValues(const Aws::Vector<Aws::String> &key_ids, const Aws::Vector<Aws::String> &grant_tokens = {})
        : TestValues(key_ids, grant_tokens),
          alg(ALG_AES128_GCM_IV12_TAG16_NO_KDF),
          unencrypted_data_key(aws_byte_buf_from_c_str(pt)) {}

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

    Model::EncryptRequest GetRequest(
        const Aws::String &in_key_id,
        const Aws::Utils::ByteBuffer &in_pt_bb,
        const Aws::Vector<Aws::String> &grant_tokens                   = {},
        const Aws::Map<Aws::String, Aws::String> in_encryption_context = {}) {
        Model::EncryptRequest request;
        request.SetKeyId(in_key_id);
        request.SetPlaintext(in_pt_bb);
        request.SetGrantTokens(grant_tokens);
        request.SetEncryptionContext(in_encryption_context);
        return request;
    }

    ~EncryptTestValues() {
        aws_byte_buf_clean_up(&unencrypted_data_key);
    }
};

struct GenerateDataKeyValues : public TestValues {
    int generate_expected_value = 16;
    Model::GenerateDataKeyResult generate_result;
    enum aws_cryptosdk_alg_id alg;
    struct aws_byte_buf unencrypted_data_key;

    GenerateDataKeyValues(const Aws::Vector<Aws::String> &grant_tokens = {})
        : TestValues({ key_id }, grant_tokens), alg(ALG_AES128_GCM_IV12_TAG16_NO_KDF), unencrypted_data_key({ 0 }) {
        generate_result.SetPlaintext(pt_bb);
        generate_result.SetCiphertextBlob(ct_bb);
        generate_result.SetKeyId(key_id);
    };

    ~GenerateDataKeyValues() {
        aws_byte_buf_clean_up(&unencrypted_data_key);
    }

    static Model::GenerateDataKeyRequest GetRequest(
        const Aws::String &key_id,
        int generate_expected_value,
        const Aws::Vector<Aws::String> &grant_tokens                   = {},
        const Aws::Map<Aws::String, Aws::String> in_encryption_context = {}) {
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
    Aws::Utils::ByteBuffer pt((uint8_t *)plaintext, strlen(plaintext));

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

    DecryptValues()
        : decrypt_result(MakeDecryptResult(key_id, pt)),
          edks(allocator),
          alg(ALG_AES128_GCM_IV12_TAG16_NO_KDF),
          unencrypted_data_key({ 0 }) {}

    DecryptValues(const Aws::Vector<Aws::String> &key_ids, const Aws::Vector<Aws::String> &grant_tokens = {})
        : TestValues(key_ids, grant_tokens),
          edks(allocator),
          alg(ALG_AES128_GCM_IV12_TAG16_NO_KDF),
          unencrypted_data_key({ 0 }) {}

    Model::DecryptRequest GetRequest() {
        return GetRequest(ct_bb, grant_tokens, GetEncryptionContext());
    }

    static Model::DecryptRequest GetRequest(
        const Aws::Utils::ByteBuffer &in_ct_bb,
        const Aws::Vector<Aws::String> &in_grant_tokens                = {},
        const Aws::Map<Aws::String, Aws::String> in_encryption_context = {}) {
        Model::DecryptRequest request;
        request.SetCiphertextBlob(in_ct_bb);
        request.SetGrantTokens(in_grant_tokens);
        request.SetEncryptionContext(in_encryption_context);
        request.SetKeyId(key_id);
        return request;
    }

    Model::DecryptResult GetResult() {
        return GetResult(key_id, pt_bb);
    }

    static Model::DecryptResult GetResult(const Aws::String &key, const Aws::Utils::ByteBuffer &pt_bb) {
        Model::DecryptResult rv;
        rv.SetKeyId(key);
        rv.SetPlaintext(pt_bb);
        return rv;
    }

    static Model::DecryptOutcome GetErrorOutcome(const Aws::String &message) {
        Aws::Client::AWSError<Aws::KMS::KMSErrors> aws_error(Aws::KMS::KMSErrors::INTERNAL_FAILURE, false);
        Aws::KMS::KMSError error(aws_error);
        error.SetMessage(message);
        return Model::DecryptOutcome(error);
    }

    int AppendKeyToEdks(const Aws::String &key_id) {
        return t_append_c_str_key_to_edks(allocator, &edks.encrypted_data_keys, &ct_bb, key_id.c_str(), provider_id);
    }

    ~DecryptValues() {
        aws_byte_buf_clean_up(&unencrypted_data_key);
    }
};

const Aws::String TEST_ACCOUNT_ID_0 = "000011110000";
const Aws::String TEST_ACCOUNT_ID_1 = "111122221111";
const Aws::String TEST_ACCOUNT_ID_2 = "222233332222";

const Aws::Vector<Aws::String> TEST_ACCOUNT0_KEY_ARNS = {
    "arn:aws:kms:us-fake-1:000011110000:key/a",
    "arn:aws:kms:us-fake-1:000011110000:key/b",
    "arn:aws:kms:us-fake-1:000011110000:key/c",
};

const Aws::Vector<Aws::String> TEST_ACCOUNT1_KEY_ARNS = {
    "arn:aws:kms:us-fake-1:111122221111:key/a",
    "arn:aws:kms:us-fake-1:111122221111:key/b",
    "arn:aws:kms:us-fake-1:111122221111:key/c",
};

static int t_encrypt_with_single_key_success(TestValues &tv, bool generated) {
    TEST_ASSERT_SUCCESS(t_assert_edks_with_single_element_contains_expected_values(
        &tv.edks, tv.ct, tv.key_id, tv.provider_id, tv.allocator));
    TEST_ASSERT_INT_EQ(aws_array_list_length(&tv.keyring_trace), 1);

    uint32_t flags = AWS_CRYPTOSDK_WRAPPING_KEY_ENCRYPTED_DATA_KEY | AWS_CRYPTOSDK_WRAPPING_KEY_SIGNED_ENC_CTX;
    if (generated) flags |= AWS_CRYPTOSDK_WRAPPING_KEY_GENERATED_DATA_KEY;

    return assert_keyring_trace_record(&tv.keyring_trace, 0, tv.provider_id, tv.key_id, flags);
}

int encrypt_validInputs_returnSuccess() {
    EncryptTestValues ev;

    ev.kms_client_mock->ExpectEncryptAccumulator(ev.GetRequest(), ev.GetResult());
    TEST_ASSERT_SUCCESS(aws_cryptosdk_keyring_on_encrypt(
        ev.kms_keyring,
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
int expect_encrypt(
    struct aws_array_list &expected_edks,
    EncryptTestValues &ev,
    const char *key,
    const char *in_pt,
    const char *expected_ct) {
    Aws::Utils::ByteBuffer pt = t_aws_utils_bb_from_char(in_pt);
    Aws::Utils::ByteBuffer ct = t_aws_utils_bb_from_char(expected_ct);
    ev.kms_client_mock->ExpectEncryptAccumulator(
        ev.GetRequest(key, pt, {}, ev.GetEncryptionContext()), ev.GetResult(key, ct));
    TEST_ASSERT_SUCCESS(t_append_c_str_key_to_edks(ev.allocator, &expected_edks, &ct, key, ev.provider_id));
    return AWS_OP_SUCCESS;
}

const Aws::Vector<Aws::String> fake_arns = { "arn:aws:kms:us-fake-1:999999999999:key/1",
                                             "arn:aws:kms:us-fake-1:999999999999:key/2",
                                             "arn:aws:kms:us-fake-1:999999999999:key/3" };

static int t_encrypt_multiple_keys_trace_success(struct aws_array_list *keyring_trace) {
    uint32_t flags = AWS_CRYPTOSDK_WRAPPING_KEY_ENCRYPTED_DATA_KEY | AWS_CRYPTOSDK_WRAPPING_KEY_SIGNED_ENC_CTX;
    for (unsigned int i = 0; i < fake_arns.size(); i++) {
        TEST_ASSERT_SUCCESS(assert_keyring_trace_record(keyring_trace, i, "aws-kms", fake_arns[i].c_str(), flags));
    }
    return 0;
}

int encrypt_validInputsMultipleKeys_returnSuccess() {
    EncryptTestValues ev(fake_arns);
    struct aws_array_list expected_edks;
    TEST_ASSERT_SUCCESS(aws_cryptosdk_edk_list_init(ev.allocator, &expected_edks));

    TEST_ASSERT_SUCCESS(expect_encrypt(expected_edks, ev, fake_arns[0].c_str(), ev.pt, "ct1"));
    TEST_ASSERT_SUCCESS(expect_encrypt(expected_edks, ev, fake_arns[1].c_str(), ev.pt, "ct2"));
    TEST_ASSERT_SUCCESS(expect_encrypt(expected_edks, ev, fake_arns[2].c_str(), ev.pt, "ct3"));

    TEST_ASSERT_SUCCESS(aws_cryptosdk_keyring_on_encrypt(
        ev.kms_keyring,
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
    Aws::Map<Aws::String, Aws::String> enc_ctx = { { "k1", "v1" }, { "k2", "v2" } };
    Aws::Vector<Aws::String> grant_tokens      = { "gt1", "gt2" };

    EncryptTestValues ev(fake_arns, grant_tokens);
    ev.SetEncryptionContext(enc_ctx);

    struct aws_array_list expected_edks;
    TEST_ASSERT_SUCCESS(aws_cryptosdk_edk_list_init(ev.allocator, &expected_edks));

    TEST_ASSERT_SUCCESS(expect_encrypt(expected_edks, ev, fake_arns[0].c_str(), ev.pt, "ct1"));
    TEST_ASSERT_SUCCESS(expect_encrypt(expected_edks, ev, fake_arns[1].c_str(), ev.pt, "ct2"));
    TEST_ASSERT_SUCCESS(expect_encrypt(expected_edks, ev, fake_arns[2].c_str(), ev.pt, "ct3"));
    ev.kms_client_mock->ExpectGrantTokens(grant_tokens);

    TEST_ASSERT_SUCCESS(aws_cryptosdk_keyring_on_encrypt(
        ev.kms_keyring,
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
    Model::EncryptOutcome error_return;  // this will set IsSuccess to false

    ev.kms_client_mock->ExpectEncryptAccumulator(ev.GetRequest(fake_arns[0], ev.pt_bb), ev.GetResult(fake_arns[0], ct));
    ev.kms_client_mock->ExpectEncryptAccumulator(ev.GetRequest(fake_arns[1], ev.pt_bb), error_return);

    TEST_ASSERT_ERROR(
        AWS_CRYPTOSDK_ERR_KMS_FAILURE,
        aws_cryptosdk_keyring_on_encrypt(
            ev.kms_keyring,
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
    Model::EncryptOutcome error_return;  // this will set IsSuccess to false
    const char *initial_ct  = "initial_ct";
    auto initial_ct_bb      = t_aws_utils_bb_from_char(initial_ct);
    const char *initial_key = "initial_key";

    // artificially add a new edk
    TEST_ASSERT_SUCCESS(
        t_append_c_str_key_to_edks(ev.allocator, &ev.edks, &initial_ct_bb, initial_key, ev.provider_id));

    // first request works
    ev.kms_client_mock->ExpectEncryptAccumulator(
        ev.GetRequest(fake_arns[0], ev.pt_bb), ev.GetResult(fake_arns[0], ev.ct_bb));
    // second request will fail
    ev.kms_client_mock->ExpectEncryptAccumulator(ev.GetRequest(fake_arns[1], ev.pt_bb), error_return);

    TEST_ASSERT_ERROR(
        AWS_CRYPTOSDK_ERR_KMS_FAILURE,
        aws_cryptosdk_keyring_on_encrypt(
            ev.kms_keyring,
            ev.allocator,
            &ev.unencrypted_data_key,
            &ev.keyring_trace,
            &ev.edks,
            &ev.encryption_context,
            ev.alg));

    // we should have the initial edk
    TEST_ASSERT_SUCCESS(t_assert_edks_with_single_element_contains_expected_values(
        &ev.edks, initial_ct, initial_key, ev.provider_id, ev.allocator));

    TEST_ASSERT(!ev.kms_client_mock->ExpectingOtherCalls());
    return 0;
}

int encrypt_kmsFails_returnError() {
    EncryptTestValues ev;
    Model::EncryptOutcome return_encrypt;  // if no parameter is set the EncryptOutcome.IsSuccess is false

    ev.kms_client_mock->ExpectEncryptAccumulator(ev.GetRequest(), return_encrypt);
    TEST_ASSERT_ERROR(
        AWS_CRYPTOSDK_ERR_KMS_FAILURE,
        aws_cryptosdk_keyring_on_encrypt(
            ev.kms_keyring,
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
    return assert_keyring_trace_record(
        &dv.keyring_trace,
        aws_array_list_length(&dv.keyring_trace) - 1,
        "aws-kms",
        dv.key_id,
        AWS_CRYPTOSDK_WRAPPING_KEY_DECRYPTED_DATA_KEY | AWS_CRYPTOSDK_WRAPPING_KEY_VERIFIED_ENC_CTX);
}

int decrypt_validInputs_returnSuccess() {
    DecryptValues dv;
    Model::DecryptOutcome return_decrypt(dv.decrypt_result);

    TEST_ASSERT_SUCCESS(
        t_append_c_str_key_to_edks(dv.allocator, &dv.edks.encrypted_data_keys, &dv.ct_bb, dv.key_id, dv.provider_id));

    dv.kms_client_mock->ExpectDecryptAccumulator(dv.GetRequest(), return_decrypt);

    TEST_ASSERT_SUCCESS(aws_cryptosdk_keyring_on_decrypt(
        dv.kms_keyring,
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

    TEST_ASSERT_SUCCESS(t_append_c_str_key_to_edks(
        dv.allocator, &dv.edks.encrypted_data_keys, &dv.ct_bb, dv.key_id, "invalid provider id"));

    TEST_ASSERT_SUCCESS(aws_cryptosdk_keyring_on_decrypt(
        dv.kms_keyring,
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

    TEST_ASSERT_SUCCESS(aws_cryptosdk_keyring_on_decrypt(
        dv.kms_keyring,
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
    TEST_ASSERT_SUCCESS(
        t_append_c_str_key_to_edks(dv.allocator, &dv.edks.encrypted_data_keys, &dv.ct_bb, dv.key_id, dv.provider_id));

    // decrypt is not called with invalid key
    TEST_ASSERT_SUCCESS(t_append_c_str_key_to_edks(
        dv.allocator, &dv.edks.encrypted_data_keys, &dv.ct_bb, "Invalid key id", dv.provider_id));

    // decrypt is not called because the provider_id is invalid
    TEST_ASSERT_SUCCESS(t_append_c_str_key_to_edks(
        dv.allocator, &dv.edks.encrypted_data_keys, &dv.ct_bb, dv.key_id, "Invalid provider id"));

    // this should succeed
    TEST_ASSERT_SUCCESS(
        t_append_c_str_key_to_edks(dv.allocator, &dv.edks.encrypted_data_keys, &dv.ct_bb, dv.key_id, dv.provider_id));
    Model::DecryptOutcome return_decrypt3(MakeDecryptResult(dv.key_id, dv.pt));
    dv.kms_client_mock->ExpectDecryptAccumulator(dv.GetRequest(), return_decrypt3);

    return AWS_OP_SUCCESS;
}

int decrypt_validInputsWithMultipleEdks_returnSuccess() {
    DecryptValues dv;

    build_multiple_edks(dv);

    TEST_ASSERT_SUCCESS(aws_cryptosdk_keyring_on_decrypt(
        dv.kms_keyring,
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

    Aws::Map<Aws::String, Aws::String> enc_ctx = { { "k1", "v1" }, { "k2", "v2" } };
    dv.SetEncryptionContext(enc_ctx);

    build_multiple_edks(dv);

    TEST_ASSERT_SUCCESS(aws_cryptosdk_keyring_on_decrypt(
        dv.kms_keyring,
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

    TEST_ASSERT_SUCCESS(aws_cryptosdk_keyring_on_encrypt(
        gv.kms_keyring,
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

    Aws::Map<Aws::String, Aws::String> enc_ctx = { { "k1", "v1" }, { "k2", "v2" } };
    gv.SetEncryptionContext(enc_ctx);

    gv.kms_client_mock->ExpectGenerateDataKey(gv.GetRequest(), return_generate);
    gv.kms_client_mock->ExpectGrantTokens(grant_tokens);

    TEST_ASSERT_SUCCESS(aws_cryptosdk_keyring_on_encrypt(
        gv.kms_keyring,
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

    TEST_ASSERT_ERROR(
        AWS_CRYPTOSDK_ERR_KMS_FAILURE,
        aws_cryptosdk_keyring_on_encrypt(
            gv.kms_keyring,
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

int testBuilder_keyWithRegion_valid() {
    KmsKeyring::Builder a;
    aws_cryptosdk_keyring *k = a.Build("arn:aws:kms:region_extracted_from_key:");
    TEST_ASSERT_ADDR_NOT_NULL(k);
    aws_cryptosdk_keyring_release(k);
    return 0;
}

int testBuilder_keyWithoutRegion_invalid() {
    KmsKeyring::Builder a;
    TEST_ASSERT_ADDR_NULL(a.Build("alias/foobar"));
    return 0;
}

int testBuilder_emptyKey_invalid() {
    KmsKeyring::Builder a;
    TEST_ASSERT_ADDR_NULL(a.Build(""));
    return 0;
}

int testBuilder_emptyAdditionalKey_invalid() {
    KmsKeyring::Builder a;
    TEST_ASSERT_ADDR_NULL(a.Build("alias/key0", { "alias/key1", "", "alias/key2" }));
    return 0;
}

int t_assert_encrypt_with_default_values(aws_cryptosdk_keyring *kms_keyring, EncryptTestValues &ev) {
    TEST_ASSERT(kms_keyring != NULL);
    TEST_ASSERT_SUCCESS(aws_cryptosdk_keyring_on_encrypt(
        kms_keyring,
        ev.allocator,
        &ev.unencrypted_data_key,
        &ev.keyring_trace,
        &ev.edks,
        &ev.encryption_context,
        ev.alg));

    TEST_ASSERT_SUCCESS(t_encrypt_with_single_key_success(ev, false));
    return 0;
}

/**
 * Whenever the ESDK calls the KMS Decrypt API in order to unwrap an EDK, it
 * MUST provide the Key Provider Information value in the EDK as the KeyID
 * parameter.
 */
int decrypt_validEdk_providesKeyProviderInfoAsKeyId() {
    Aws::String key_id = TEST_ACCOUNT0_KEY_ARNS[0];
    DecryptValues dv({ key_id });

    // Expect Key Id to be passed in request...
    Model::DecryptRequest request = dv.GetRequest();
    request.SetKeyId(key_id);
    dv.kms_client_mock->ExpectDecryptAccumulator(request, dv.GetResult(key_id, dv.pt_bb));

    // ...from EDK's Key Provider Info
    TEST_ASSERT_SUCCESS(dv.AppendKeyToEdks(key_id));

    TEST_ASSERT_SUCCESS(aws_cryptosdk_keyring_on_decrypt(
        dv.kms_keyring,
        dv.allocator,
        &dv.unencrypted_data_key,
        &dv.keyring_trace,
        &dv.edks.encrypted_data_keys,
        &dv.encryption_context,
        dv.alg));
    TEST_ASSERT_ADDR_NOT_NULL(dv.unencrypted_data_key.buffer);
    TEST_ASSERT(!dv.kms_client_mock->ExpectingOtherCalls());

    return 0;
}

/**
 * Whenever the ESDK calls the KMS Decrypt API in order to unwrap an EDK, it
 * MUST provide the Key Provider Information value in the EDK as the KeyID
 * parameter. This MUST also hold for KMS Decrypt calls for distinct Key
 * Provider Info values.
 */
int decrypt_distinctEdkKeyProviderInfos_callsKmsWithRespectiveKeyIds() {
    Aws::String key_id_a = TEST_ACCOUNT0_KEY_ARNS[0];
    Aws::String key_id_b = TEST_ACCOUNT0_KEY_ARNS[1];
    DecryptValues dv({ key_id_a, key_id_b });

    Model::DecryptRequest request_a = dv.GetRequest();
    Model::DecryptRequest request_b = dv.GetRequest();
    request_a.SetKeyId(key_id_a);
    request_b.SetKeyId(key_id_b);
    dv.kms_client_mock->ExpectDecryptAccumulator(request_a, dv.GetErrorOutcome("test error for key_id_a"));
    dv.kms_client_mock->ExpectDecryptAccumulator(request_b, dv.GetResult(key_id_b, dv.pt_bb));

    t_append_c_str_key_to_edks(dv.allocator, &dv.edks.encrypted_data_keys, &dv.ct_bb, key_id_a.c_str(), dv.provider_id);
    t_append_c_str_key_to_edks(dv.allocator, &dv.edks.encrypted_data_keys, &dv.ct_bb, key_id_b.c_str(), dv.provider_id);

    TEST_ASSERT_SUCCESS(aws_cryptosdk_keyring_on_decrypt(
        dv.kms_keyring,
        dv.allocator,
        &dv.unencrypted_data_key,
        &dv.keyring_trace,
        &dv.edks.encrypted_data_keys,
        &dv.encryption_context,
        dv.alg));
    TEST_ASSERT_ADDR_NOT_NULL(dv.unencrypted_data_key.buffer);
    TEST_ASSERT(!dv.kms_client_mock->ExpectingOtherCalls());

    return 0;
}

/**
 * The implementation MUST return failure if the KeyId value in the KMS Decrypt
 * response does not match the Key Provider Info value in the EDK.
 *
 * It is unnecessary to check that the KeyId value is present in the
 * response, since such a state is not representable by
 * Model::DecryptResult.
 */
int decrypt_kmsResponseKeyIdDiffersFromKeyProviderInfo_returnsFailure() {
    DecryptValues dv;
    Model::DecryptResult result = dv.GetResult(dv.key_id, dv.pt_bb);
    result.SetKeyId("");
    dv.kms_client_mock->ExpectDecryptAccumulator(dv.GetRequest(), result);

    TEST_ASSERT_SUCCESS(dv.AppendKeyToEdks(dv.key_id));

    TEST_ASSERT_ERROR(
        AWS_ERROR_INVALID_STATE,
        aws_cryptosdk_keyring_on_decrypt(
            dv.kms_keyring,
            dv.allocator,
            &dv.unencrypted_data_key,
            &dv.keyring_trace,
            &dv.edks.encrypted_data_keys,
            &dv.encryption_context,
            dv.alg));
    TEST_ASSERT(!dv.kms_client_mock->ExpectingOtherCalls());

    return 0;
}

/**
 * The implementation MUST return success if the KeyId value in the KMS Decrypt
 * response matches the Key Provider Info value in the EDK.
 */
int decrypt_kmsResponseKeyIdMatchesKeyProviderInfo_returnsSuccess() {
    DecryptValues dv;
    Model::DecryptResult result = dv.GetResult(dv.key_id, dv.pt_bb);
    dv.kms_client_mock->ExpectDecryptAccumulator(dv.GetRequest(), result);

    TEST_ASSERT_SUCCESS(dv.AppendKeyToEdks(dv.key_id));

    TEST_ASSERT_SUCCESS(aws_cryptosdk_keyring_on_decrypt(
        dv.kms_keyring,
        dv.allocator,
        &dv.unencrypted_data_key,
        &dv.keyring_trace,
        &dv.edks.encrypted_data_keys,
        &dv.encryption_context,
        dv.alg));
    TEST_ASSERT_ADDR_NOT_NULL(dv.unencrypted_data_key.buffer);
    TEST_ASSERT(!dv.kms_client_mock->ExpectingOtherCalls());

    return 0;
}

/**
 * The non-discovery mode constructor MUST succeed.
 */
int decrypt_publicConstructorForNonDiscoveryMode_returnsSuccess() {
    std::shared_ptr<Aws::KMS::KMSClient> kms;
    DecryptValues dv;
    Aws::Vector<Aws::String> additional_key_ids;

    Aws::Cryptosdk::KmsKeyring::Builder builder;
    aws_cryptosdk_keyring *keyring = builder.WithKmsClient(kms).Build(dv.key_id, additional_key_ids);
    TEST_ASSERT((bool)keyring);

    return 0;
}

/**
 * If a non-discovery keyring is configured with a single key name, and its
 * Decrypt method is called with a single EDK whose Key Provider Information
 * field matches the key name, then the method must succeed.
 */
int nonDiscoverySingleKeyName_singleEdkMatchingKeyName_returnsSuccess() {
    DecryptValues dv;
    dv.kms_client_mock->ExpectDecryptAccumulator(dv.GetRequest(), dv.GetResult());
    TEST_ASSERT_SUCCESS(dv.AppendKeyToEdks(dv.key_id));
    TEST_ASSERT_SUCCESS(aws_cryptosdk_keyring_on_decrypt(
        dv.kms_keyring,
        dv.allocator,
        &dv.unencrypted_data_key,
        &dv.keyring_trace,
        &dv.edks.encrypted_data_keys,
        &dv.encryption_context,
        dv.alg));
    TEST_ASSERT_ADDR_NOT_NULL(dv.unencrypted_data_key.buffer);
    TEST_ASSERT(!dv.kms_client_mock->ExpectingOtherCalls());

    return 0;
}

/**
 * If a non-discovery keyring is configured with a single key name, and its
 * Decrypt method is called with a single EDK whose Key Provider Information
 * field does not match the key name, then the method must fail to decrypt the
 * EDK, and must not make a KMS call.
 */
int nonDiscoverySingleKeyName_singleEdkWithMismatchedKeyName_doesNotDecryptOrCallKms() {
    DecryptValues dv;
    TEST_ASSERT_SUCCESS(dv.AppendKeyToEdks("arn:aws:kms:us-west-2:000011110000:key/bad"));
    TEST_ASSERT_SUCCESS(aws_cryptosdk_keyring_on_decrypt(
        dv.kms_keyring,
        dv.allocator,
        &dv.unencrypted_data_key,
        &dv.keyring_trace,
        &dv.edks.encrypted_data_keys,
        &dv.encryption_context,
        dv.alg));
    TEST_ASSERT_ADDR_NULL(dv.unencrypted_data_key.buffer);
    TEST_ASSERT(!dv.kms_client_mock->ExpectingOtherCalls());

    return 0;
}

/**
 * If a non-discovery keyring is configured with a single key name, and its
 * Decrypt method is called with a list of EDKs in which no Key Provider
 * Information field matches the key name, then the method must fail without
 * attempting a KMS call.
 */
int nonDiscoverySingleKeyName_edksWithoutMatchingKeyName_returnsFailureWithoutKmsCall() {
    DecryptValues dv;
    TEST_ASSERT_SUCCESS(dv.AppendKeyToEdks("arn:aws:kms:us-west-2:000011110000:key/bad0"));
    TEST_ASSERT_SUCCESS(dv.AppendKeyToEdks("arn:aws:kms:us-west-2:000011110000:key/bad1"));
    TEST_ASSERT_SUCCESS(dv.AppendKeyToEdks("arn:aws:kms:us-west-2:000011110000:key/bad2"));
    TEST_ASSERT_SUCCESS(aws_cryptosdk_keyring_on_decrypt(
        dv.kms_keyring,
        dv.allocator,
        &dv.unencrypted_data_key,
        &dv.keyring_trace,
        &dv.edks.encrypted_data_keys,
        &dv.encryption_context,
        dv.alg));
    TEST_ASSERT_ADDR_NULL(dv.unencrypted_data_key.buffer);
    TEST_ASSERT(!dv.kms_client_mock->ExpectingOtherCalls());

    return 0;
}

/**
 * If a non-discovery keyring is configured with a single key name, and its
 * Decrypt method is called with a list of EDKs in which each Key Provider
 * Information field matches the key name, then the method must decrypt the
 * first EDK.
 */
int nonDiscoverySingleKeyName_edksAllMatchingKeyName_decryptsFirstEdk() {
    DecryptValues dv;
    Aws::Vector<Aws::String> key_cts({ "ct0", "ct1", "ct2" });

    for (const Aws::String &key_ct : key_cts) {
        Aws::Utils::ByteBuffer key_ct_bb = t_aws_utils_bb_from_char(key_ct.c_str());
        TEST_ASSERT_SUCCESS(t_append_c_str_key_to_edks(
            dv.allocator, &dv.edks.encrypted_data_keys, &key_ct_bb, dv.key_id, dv.provider_id));
    }

    Model::DecryptRequest request;
    request.SetKeyId(dv.key_id);
    // Request must be for the first EDK's ciphertext
    request.SetCiphertextBlob(t_aws_utils_bb_from_char(key_cts[0].c_str()));

    Model::DecryptResult result = dv.GetResult(dv.key_id, dv.pt_bb);
    dv.kms_client_mock->ExpectDecryptAccumulator(request, result);

    TEST_ASSERT_SUCCESS(aws_cryptosdk_keyring_on_decrypt(
        dv.kms_keyring,
        dv.allocator,
        &dv.unencrypted_data_key,
        &dv.keyring_trace,
        &dv.edks.encrypted_data_keys,
        &dv.encryption_context,
        dv.alg));
    TEST_ASSERT_ADDR_NOT_NULL(dv.unencrypted_data_key.buffer);
    TEST_ASSERT(!dv.kms_client_mock->ExpectingOtherCalls());

    return 0;
}

/**
 * If a non-discovery keyring is configured with a single key name, and its
 * Decrypt method is called with a list of EDKs in which each Key Provider
 * Information field matches the key name, and the first EDK fails decryption,
 * then the method must decrypt the second EDK.
 */
int nonDiscoverySingleKeyName_edksAllMatchingKeyNameButFirstEdkFails_decryptsSecondEdk() {
    DecryptValues dv;
    Aws::Vector<Aws::String> key_cts({ "ct0", "ct1", "ct2" });

    for (const Aws::String &key_ct : key_cts) {
        Aws::Utils::ByteBuffer key_ct_bb = t_aws_utils_bb_from_char(key_ct.c_str());
        TEST_ASSERT_SUCCESS(t_append_c_str_key_to_edks(
            dv.allocator, &dv.edks.encrypted_data_keys, &key_ct_bb, dv.key_id, dv.provider_id));
    }

    Model::DecryptRequest request0, request1;
    request0.SetKeyId(dv.key_id);
    request1.SetKeyId(dv.key_id);
    request0.SetCiphertextBlob(t_aws_utils_bb_from_char(key_cts[0].c_str()));
    request1.SetCiphertextBlob(t_aws_utils_bb_from_char(key_cts[1].c_str()));

    Model::DecryptOutcome outcome0 = dv.GetErrorOutcome("test-error");
    dv.kms_client_mock->ExpectDecryptAccumulator(request0, outcome0);

    Model::DecryptOutcome outcome1(dv.GetResult(dv.key_id, dv.pt_bb));
    dv.kms_client_mock->ExpectDecryptAccumulator(request1, outcome1);

    TEST_ASSERT_SUCCESS(aws_cryptosdk_keyring_on_decrypt(
        dv.kms_keyring,
        dv.allocator,
        &dv.unencrypted_data_key,
        &dv.keyring_trace,
        &dv.edks.encrypted_data_keys,
        &dv.encryption_context,
        dv.alg));
    TEST_ASSERT_ADDR_NOT_NULL(dv.unencrypted_data_key.buffer);
    TEST_ASSERT(!dv.kms_client_mock->ExpectingOtherCalls());

    return 0;
}

/**
 * If a non-discovery keyring is configured with a single key name, and its
 * Decrypt method is called with a list of EDKs in which a single Key Provider
 * Information field matches the key name (other than the first EDK), then the
 * method must decrypt the matching EDK and no others.
 */
int nonDiscoverySingleKeyName_edksWithOneMatchingKeyProviderInfo_decryptsOnlyMatchingEdk() {
    DecryptValues dv;
    Aws::Vector<Aws::String> key_cts({ "ct0", "ct1", "ct2" });
    for (const Aws::String &key_ct : key_cts) {
        Aws::Utils::ByteBuffer key_ct_bb = t_aws_utils_bb_from_char(key_ct.c_str());
        TEST_ASSERT_SUCCESS(t_append_c_str_key_to_edks(
            dv.allocator,
            &dv.edks.encrypted_data_keys,
            &key_ct_bb,
            key_ct == key_cts[1] ? dv.key_id : "arn:aws:kms:us-fake-1:000011110000:key/bad",
            dv.provider_id));
    }

    Model::DecryptRequest request;
    request.SetKeyId(dv.key_id);
    request.SetCiphertextBlob(t_aws_utils_bb_from_char(key_cts[1].c_str()));
    Model::DecryptOutcome outcome(dv.GetResult(dv.key_id, dv.pt_bb));
    dv.kms_client_mock->ExpectDecryptAccumulator(request, outcome);

    TEST_ASSERT_SUCCESS(aws_cryptosdk_keyring_on_decrypt(
        dv.kms_keyring,
        dv.allocator,
        &dv.unencrypted_data_key,
        &dv.keyring_trace,
        &dv.edks.encrypted_data_keys,
        &dv.encryption_context,
        dv.alg));
    TEST_ASSERT_ADDR_NOT_NULL(dv.unencrypted_data_key.buffer);
    TEST_ASSERT(!dv.kms_client_mock->ExpectingOtherCalls());

    return 0;
}

/**
 * If a non-discovery keyring is configured with a list of key names, and its
 * Decrypt method is called with a single EDK whose Key Provider Information
 * field matches one of the configured key names, then the method must succeed.
 */
int nonDiscoveryKeyNames_singleEdkMatchingName_returnsSuccess() {
    Aws::Vector<Aws::String> key_ids = {
        "arn:aws:kms:us-west-2:000011110000:key/a",
        "arn:aws:kms:us-west-2:000011110000:key/b",
        "arn:aws:kms:us-west-2:000011110000:key/c",
    };

    DecryptValues dv(key_ids);
    Model::DecryptRequest request = dv.GetRequest().WithKeyId(key_ids[1]);
    Model::DecryptResult result   = dv.GetResult().WithKeyId(key_ids[1]);
    dv.kms_client_mock->ExpectDecryptAccumulator(request, result);
    TEST_ASSERT_SUCCESS(dv.AppendKeyToEdks(key_ids[1]));
    TEST_ASSERT_SUCCESS(aws_cryptosdk_keyring_on_decrypt(
        dv.kms_keyring,
        dv.allocator,
        &dv.unencrypted_data_key,
        &dv.keyring_trace,
        &dv.edks.encrypted_data_keys,
        &dv.encryption_context,
        dv.alg));
    TEST_ASSERT_ADDR_NOT_NULL(dv.unencrypted_data_key.buffer);
    TEST_ASSERT(!dv.kms_client_mock->ExpectingOtherCalls());

    return 0;
}

/**
 * If a non-discovery keyring is configured with a list of key names, and its
 * Decrypt method is called with a single EDK whose Key Provider Information
 * field does not match any of the configured key names, then the method must
 * fail to decrypt the EDK, and must not make a KMS call.
 */
int nonDiscoveryKeyNames_singleEdkWithMismatchedName_doesNotDecryptOrCallKms() {
    Aws::Vector<Aws::String> key_ids = {
        "arn:aws:kms:us-west-2:000011110000:key/a",
        "arn:aws:kms:us-west-2:000011110000:key/b",
        "arn:aws:kms:us-west-2:000011110000:key/c",
    };

    DecryptValues dv(key_ids);
    TEST_ASSERT_SUCCESS(dv.AppendKeyToEdks("arn:aws:kms:us-west-2:000011110000:key/bad"));
    TEST_ASSERT_SUCCESS(aws_cryptosdk_keyring_on_decrypt(
        dv.kms_keyring,
        dv.allocator,
        &dv.unencrypted_data_key,
        &dv.keyring_trace,
        &dv.edks.encrypted_data_keys,
        &dv.encryption_context,
        dv.alg));
    TEST_ASSERT_ADDR_NULL(dv.unencrypted_data_key.buffer);
    TEST_ASSERT(!dv.kms_client_mock->ExpectingOtherCalls());

    return 0;
}

/**
 * If a non-discovery keyring is configured with a list of key names, and its
 * Decrypt method is called with a list of EDKs in which no Key Provider
 * Information field matches any of the configured key names, then the method
 * must fail without attempting a KMS call.
 */
int nonDiscoveryKeyNames_edksWithoutMatchingKeyName_returnsFailureWithoutKmsCall() {
    Aws::Vector<Aws::String> key_ids = {
        "arn:aws:kms:us-west-2:000011110000:key/a",
        "arn:aws:kms:us-west-2:000011110000:key/b",
        "arn:aws:kms:us-west-2:000011110000:key/c",
    };
    DecryptValues dv(key_ids);

    TEST_ASSERT_SUCCESS(dv.AppendKeyToEdks("arn:aws:kms:us-west-2:000011110000:key/bad0"));
    TEST_ASSERT_SUCCESS(dv.AppendKeyToEdks("arn:aws:kms:us-west-2:000011110000:key/bad1"));
    TEST_ASSERT_SUCCESS(dv.AppendKeyToEdks("arn:aws:kms:us-west-2:000011110000:key/bad2"));
    TEST_ASSERT_SUCCESS(aws_cryptosdk_keyring_on_decrypt(
        dv.kms_keyring,
        dv.allocator,
        &dv.unencrypted_data_key,
        &dv.keyring_trace,
        &dv.edks.encrypted_data_keys,
        &dv.encryption_context,
        dv.alg));
    TEST_ASSERT_ADDR_NULL(dv.unencrypted_data_key.buffer);
    TEST_ASSERT(!dv.kms_client_mock->ExpectingOtherCalls());

    return 0;
}

/**
 * If a non-discovery keyring is configured with a list of key names, and its
 * Decrypt method is called with a list of EDKs in which each Key Provider
 * Information field matches a configured key name, then the method must
 * decrypt the first EDK.
 */
int nonDiscoveryKeyNames_edksAllMatchingKeyName_decryptsFirstEdk() {
    Aws::Vector<Aws::String> key_ids = {
        "arn:aws:kms:us-west-2:000011110000:key/a",
        "arn:aws:kms:us-west-2:000011110000:key/b",
        "arn:aws:kms:us-west-2:000011110000:key/c",
    };
    DecryptValues dv(key_ids);

    Aws::Vector<Aws::String> key_cts({ "ct0", "ct1", "ct2" });
    for (int i = 0; i < key_ids.size(); ++i) {
        Aws::Utils::ByteBuffer key_ct_bb = t_aws_utils_bb_from_char(key_cts[i].c_str());
        TEST_ASSERT_SUCCESS(t_append_c_str_key_to_edks(
            dv.allocator, &dv.edks.encrypted_data_keys, &key_ct_bb, key_ids[i].c_str(), dv.provider_id));
    }

    Model::DecryptRequest request;
    request.SetKeyId(key_ids[0]);
    // Request must be for the first EDK's ciphertext
    request.SetCiphertextBlob(t_aws_utils_bb_from_char(key_cts[0].c_str()));

    Model::DecryptResult result = dv.GetResult(key_ids[0], dv.pt_bb);
    dv.kms_client_mock->ExpectDecryptAccumulator(request, result);

    TEST_ASSERT_SUCCESS(aws_cryptosdk_keyring_on_decrypt(
        dv.kms_keyring,
        dv.allocator,
        &dv.unencrypted_data_key,
        &dv.keyring_trace,
        &dv.edks.encrypted_data_keys,
        &dv.encryption_context,
        dv.alg));
    TEST_ASSERT_ADDR_NOT_NULL(dv.unencrypted_data_key.buffer);
    TEST_ASSERT(!dv.kms_client_mock->ExpectingOtherCalls());

    return 0;
}

/**
 * If a non-discovery keyring is configured with a list of key names, and its
 * Decrypt method is called with a list of EDKs in which each Key Provider
 * Information field matches a configured key name, and the first EDK fails
 * decryption, then the method must decrypt the second EDK.
 */
int nonDiscoveryKeyNames_edksAllMatchingKeyNameButFirstEdkFails_decryptsSecondEdk() {
    Aws::Vector<Aws::String> key_ids = {
        "arn:aws:kms:us-west-2:000011110000:key/a",
        "arn:aws:kms:us-west-2:000011110000:key/b",
        "arn:aws:kms:us-west-2:000011110000:key/c",
    };
    DecryptValues dv(key_ids);

    Aws::Vector<Aws::String> key_cts({ "ct0", "ct1", "ct2" });
    for (int i = 0; i < key_ids.size(); ++i) {
        Aws::Utils::ByteBuffer key_ct_bb = t_aws_utils_bb_from_char(key_cts[i].c_str());
        TEST_ASSERT_SUCCESS(t_append_c_str_key_to_edks(
            dv.allocator, &dv.edks.encrypted_data_keys, &key_ct_bb, key_ids[i].c_str(), dv.provider_id));
    }

    Model::DecryptRequest request0, request1;
    request0.SetKeyId(key_ids[0]);
    request1.SetKeyId(key_ids[1]);
    request0.SetCiphertextBlob(t_aws_utils_bb_from_char(key_cts[0].c_str()));
    request1.SetCiphertextBlob(t_aws_utils_bb_from_char(key_cts[1].c_str()));

    Model::DecryptOutcome outcome0 = dv.GetErrorOutcome("test-error");
    dv.kms_client_mock->ExpectDecryptAccumulator(request0, outcome0);

    Model::DecryptOutcome outcome1(dv.GetResult(key_ids[1], dv.pt_bb));
    dv.kms_client_mock->ExpectDecryptAccumulator(request1, outcome1);

    TEST_ASSERT_SUCCESS(aws_cryptosdk_keyring_on_decrypt(
        dv.kms_keyring,
        dv.allocator,
        &dv.unencrypted_data_key,
        &dv.keyring_trace,
        &dv.edks.encrypted_data_keys,
        &dv.encryption_context,
        dv.alg));
    TEST_ASSERT_ADDR_NOT_NULL(dv.unencrypted_data_key.buffer);
    TEST_ASSERT(!dv.kms_client_mock->ExpectingOtherCalls());

    return 0;
}

/**
 * If a non-discovery keyring is configured with a list of key names, and its
 * Decrypt method is called with a list of EDKs in which a single Key Provider
 * Information field matches a configured key name (other than the first EDK),
 * then the method must decrypt the matching EDK and no others.
 */
int nonDiscoveryKeyNames_edksWithOneMatchingKeyProviderInfo_decryptsOnlyMatchingEdk() {
    Aws::Vector<Aws::String> key_ids = {
        "arn:aws:kms:us-west-2:000011110000:key/a",
        "arn:aws:kms:us-west-2:000011110000:key/b",
        "arn:aws:kms:us-west-2:000011110000:key/c",
    };
    DecryptValues dv(key_ids);
    Aws::Vector<Aws::String> key_cts({ "ct0", "ct1", "ct2" });
    for (const Aws::String &key_ct : key_cts) {
        Aws::Utils::ByteBuffer key_ct_bb = t_aws_utils_bb_from_char(key_ct.c_str());
        TEST_ASSERT_SUCCESS(t_append_c_str_key_to_edks(
            dv.allocator,
            &dv.edks.encrypted_data_keys,
            &key_ct_bb,
            key_ct == key_cts[1] ? key_ids[1].c_str() : "arn:aws:kms:us-west-2:000011110000:key/bad",
            dv.provider_id));
    }

    Model::DecryptRequest request;
    request.SetKeyId(key_ids[1]);
    request.SetCiphertextBlob(t_aws_utils_bb_from_char(key_cts[1].c_str()));
    Model::DecryptOutcome outcome(dv.GetResult(key_ids[1], dv.pt_bb));
    dv.kms_client_mock->ExpectDecryptAccumulator(request, outcome);

    TEST_ASSERT_SUCCESS(aws_cryptosdk_keyring_on_decrypt(
        dv.kms_keyring,
        dv.allocator,
        &dv.unencrypted_data_key,
        &dv.keyring_trace,
        &dv.edks.encrypted_data_keys,
        &dv.encryption_context,
        dv.alg));
    TEST_ASSERT_ADDR_NOT_NULL(dv.unencrypted_data_key.buffer);
    TEST_ASSERT(!dv.kms_client_mock->ExpectingOtherCalls());

    return 0;
}

/**
 * The discovery mode constructor MUST succeed.
 */
int decrypt_publicConstructorForDiscoveryMode_returnsSuccess() {
    std::shared_ptr<Aws::KMS::KMSClient> kms;
    Aws::Cryptosdk::KmsKeyring::Builder builder;
    aws_cryptosdk_keyring *keyring = builder.WithKmsClient(kms).BuildDiscovery();
    TEST_ASSERT((bool)keyring);
    return 0;
}

/**
 * A discovery keyring must succeed in decrypting an EDK if the KMS client can
 * decrypt the EDK's ciphertext.
 */
int discoveryNoKeyNames_callWithDecryptableEdk_decryptsEdk() {
    std::shared_ptr<KmsClientMock> kms_client_mock(Aws::MakeShared<KmsClientMock>(CLASS_TAG));
    std::shared_ptr<Aws::KMS::KMSClient> kms(kms_client_mock);
    Aws::Cryptosdk::KmsKeyring::Builder builder;
    aws_cryptosdk_keyring *keyring = builder.WithKmsClient(kms).BuildDiscovery();
    TEST_ASSERT((bool)keyring);

    DecryptValues dv;
    kms_client_mock->ExpectDecryptAccumulator(dv.GetRequest(), dv.GetResult());
    TEST_ASSERT_SUCCESS(dv.AppendKeyToEdks(dv.key_id));
    TEST_ASSERT_SUCCESS(aws_cryptosdk_keyring_on_decrypt(
        keyring,
        dv.allocator,
        &dv.unencrypted_data_key,
        &dv.keyring_trace,
        &dv.edks.encrypted_data_keys,
        &dv.encryption_context,
        dv.alg));
    TEST_ASSERT_ADDR_NOT_NULL(dv.unencrypted_data_key.buffer);
    TEST_ASSERT(!kms_client_mock->ExpectingOtherCalls());

    return 0;
}

/**
 * A discovery keyring must fail to decrypt an EDK if the KMS client cannot
 * decrypt the EDK's ciphertext.
 */
int discoveryNoKeyNames_callWithUndecryptableEdk_failsToDecryptEdk() {
    std::shared_ptr<KmsClientMock> kms_client_mock(Aws::MakeShared<KmsClientMock>(CLASS_TAG));
    std::shared_ptr<Aws::KMS::KMSClient> kms(kms_client_mock);
    Aws::Cryptosdk::KmsKeyring::Builder builder;
    aws_cryptosdk_keyring *keyring = builder.WithKmsClient(kms).BuildDiscovery();
    TEST_ASSERT((bool)keyring);

    DecryptValues dv;
    kms_client_mock->ExpectDecryptAccumulator(dv.GetRequest(), dv.GetErrorOutcome("test error"));
    TEST_ASSERT_SUCCESS(dv.AppendKeyToEdks(dv.key_id));
    TEST_ASSERT_SUCCESS(aws_cryptosdk_keyring_on_decrypt(
        keyring,
        dv.allocator,
        &dv.unencrypted_data_key,
        &dv.keyring_trace,
        &dv.edks.encrypted_data_keys,
        &dv.encryption_context,
        dv.alg));
    TEST_ASSERT_ADDR_NULL(dv.unencrypted_data_key.buffer);
    TEST_ASSERT(!kms_client_mock->ExpectingOtherCalls());

    return 0;
}

int buildDiscovery_validFilter_returnsSuccess() {
    std::shared_ptr<KmsKeyring::DiscoveryFilter> discovery_filter(
        KmsKeyring::DiscoveryFilter::Builder("aws").WithAccounts({ TEST_ACCOUNT_ID_0 }).Build());
    KmsKeyring::Builder builder;
    aws_cryptosdk_keyring *keyring = builder.BuildDiscovery(discovery_filter);
    TEST_ASSERT_ADDR_NOT_NULL(keyring);
    return 0;
}

/**
 * Building a discovery-mode keyring with a DiscoveryFilter that has a
 * non-empty set of nonsense AWS account IDs and a non-empty nonsense
 * partition, must succeed.
 */
int buildDiscovery_nonsenseFilter_returnsSuccess() {
    std::shared_ptr<KmsKeyring::DiscoveryFilter> discovery_filter(
        KmsKeyring::DiscoveryFilter::Builder("nonsense-partition")
            .WithAccounts({ "nonsense", "account", "IDs" })
            .Build());
    KmsKeyring::Builder builder;
    aws_cryptosdk_keyring *keyring = builder.BuildDiscovery(discovery_filter);
    TEST_ASSERT_ADDR_NOT_NULL(keyring);
    return 0;
}

/**
 * Building a discovery-mode keyring with a null DiscoveryFilter pointer must
 * fail (return nullptr).
 */
int buildDiscovery_nullFilter_returnsNull() {
    std::shared_ptr<KmsKeyring::DiscoveryFilter> null_filter;
    KmsKeyring::Builder builder;
    aws_cryptosdk_keyring *keyring = builder.BuildDiscovery(null_filter);
    TEST_ASSERT_ADDR_NULL(keyring);
    return 0;
}

/**
 * If a DiscoveryFilterBuilder's partition is the empty string, it must fail to build.
 */
int discoveryFilterBuild_blankPartition_returnsFailure() {
    TEST_ASSERT_ADDR_NULL(KmsKeyring::DiscoveryFilter::Builder("").WithAccounts({ TEST_ACCOUNT_ID_0 }).Build().get());
    return 0;
}

/**
 * If a DiscoveryFilterBuilder has no account IDs, then it must fail to build.
 */
int discoveryFilterBuild_noAccountIds_returnsFailure() {
    TEST_ASSERT_ADDR_NULL(KmsKeyring::DiscoveryFilter::Builder("aws").WithAccounts({}).Build().get());
    return 0;
}

/**
 * If a DiscoveryFilterBuilder has any empty account IDs, then it must fail to build.
 */
int discoveryFilterBuild_invalidAccountIds_returnsFailure() {
    TEST_ASSERT_ADDR_NULL(KmsKeyring::DiscoveryFilter::Builder("aws")
                              .WithAccounts({ TEST_ACCOUNT_ID_0, "", TEST_ACCOUNT_ID_1 })
                              .Build()
                              .get());
    return 0;
}

struct aws_cryptosdk_keyring *t_create_discovery_keyring(
    std::shared_ptr<Aws::KMS::KMSClient> kms_client, const Aws::Vector<Aws::String> &account_ids) {
    std::shared_ptr<KmsKeyring::DiscoveryFilter> discovery_filter(
        KmsKeyring::DiscoveryFilter::Builder("aws").WithAccounts(account_ids).Build());
    KmsKeyring::Builder builder;
    return builder.WithKmsClient(kms_client).BuildDiscovery(discovery_filter);
}

/**
 * If a discovery-mode keyring has one account ID in its discovery filter, and
 * decrypt is called with a single EDK without provider info, then the keyring
 * must fail without making a KMS call.
 */
int decrypt1AccountDiscoveryFilter_edkWithoutProviderInfo_returnsFailureWithoutKmsCall() {
    DecryptValues dv;
    struct aws_cryptosdk_keyring *keyring = t_create_discovery_keyring(dv.kms_client_mock, { TEST_ACCOUNT_ID_0 });
    t_append_c_str_key_to_edks(dv.allocator, &dv.edks.encrypted_data_keys, &dv.ct_bb, "", dv.provider_id);
    TEST_ASSERT_SUCCESS(aws_cryptosdk_keyring_on_decrypt(
        keyring,
        dv.allocator,
        &dv.unencrypted_data_key,
        &dv.keyring_trace,
        &dv.edks.encrypted_data_keys,
        &dv.encryption_context,
        dv.alg));
    TEST_ASSERT_ADDR_NULL(dv.unencrypted_data_key.buffer);
    TEST_ASSERT(!dv.kms_client_mock->ExpectingOtherCalls());

    return 0;
}

/**
 * If a discovery-mode keyring has one account ID in its discovery filter, and
 * decrypt is called with a single EDK without provider info, then the keyring
 * must fail without making a KMS call.
 */
int decrypt1AccountDiscoveryFilter_edkNonArnProviderInfo_returnsFailureWithoutKmsCall() {
    DecryptValues dv;
    struct aws_cryptosdk_keyring *keyring = t_create_discovery_keyring(dv.kms_client_mock, { TEST_ACCOUNT_ID_0 });
    t_append_c_str_key_to_edks(dv.allocator, &dv.edks.encrypted_data_keys, &dv.ct_bb, "nonsense", dv.provider_id);
    TEST_ASSERT_SUCCESS(aws_cryptosdk_keyring_on_decrypt(
        keyring,
        dv.allocator,
        &dv.unencrypted_data_key,
        &dv.keyring_trace,
        &dv.edks.encrypted_data_keys,
        &dv.encryption_context,
        dv.alg));
    TEST_ASSERT_ADDR_NULL(dv.unencrypted_data_key.buffer);
    TEST_ASSERT(!dv.kms_client_mock->ExpectingOtherCalls());

    return 0;
}

/**
 * If a discovery-mode keyring has one account ID in its discovery filter, and
 * OnDecrypt is called with a single EDK authorized by the discovery filter,
 * then the keyring must succeed.
 */
int decrypt1AccountDiscoveryFilter_authorizedProviderInfoArn_returnsSuccess() {
    DecryptValues dv;
    struct aws_cryptosdk_keyring *keyring = t_create_discovery_keyring(dv.kms_client_mock, { TEST_ACCOUNT_ID_0 });
    Aws::String key_id                    = TEST_ACCOUNT0_KEY_ARNS[0];
    t_append_c_str_key_to_edks(dv.allocator, &dv.edks.encrypted_data_keys, &dv.ct_bb, key_id.c_str(), dv.provider_id);
    dv.kms_client_mock->ExpectDecryptAccumulator(dv.GetRequest().WithKeyId(key_id), dv.GetResult().WithKeyId(key_id));
    TEST_ASSERT_SUCCESS(aws_cryptosdk_keyring_on_decrypt(
        keyring,
        dv.allocator,
        &dv.unencrypted_data_key,
        &dv.keyring_trace,
        &dv.edks.encrypted_data_keys,
        &dv.encryption_context,
        dv.alg));
    TEST_ASSERT_ADDR_NOT_NULL(dv.unencrypted_data_key.buffer);
    TEST_ASSERT(!dv.kms_client_mock->ExpectingOtherCalls());

    return 0;
}

/**
 * If a discovery-mode keyring has one account ID in its discovery filter, and
 * OnDecrypt is called with a single EDK whose key provider info is not in the
 * discovery filter's account ID set, then the keyring must fail to decrypt the
 * EDK, and must not make any KMS calls.
 */
int decrypt1AccountDiscoveryFilter_mismatchedProviderInfoAccount_returnsFailureWithoutKmsCall() {
    DecryptValues dv;
    struct aws_cryptosdk_keyring *keyring = t_create_discovery_keyring(dv.kms_client_mock, { TEST_ACCOUNT_ID_0 });
    t_append_c_str_key_to_edks(
        dv.allocator, &dv.edks.encrypted_data_keys, &dv.ct_bb, TEST_ACCOUNT1_KEY_ARNS[0].c_str(), dv.provider_id);
    TEST_ASSERT_SUCCESS(aws_cryptosdk_keyring_on_decrypt(
        keyring,
        dv.allocator,
        &dv.unencrypted_data_key,
        &dv.keyring_trace,
        &dv.edks.encrypted_data_keys,
        &dv.encryption_context,
        dv.alg));
    TEST_ASSERT_ADDR_NULL(dv.unencrypted_data_key.buffer);
    TEST_ASSERT(!dv.kms_client_mock->ExpectingOtherCalls());

    return 0;
}

/**
 * If a discovery-mode keyring has one account ID in its discovery filter, and
 * OnDecrypt is called with a single EDK whose key provider info ARN has a
 * different partition than the discovery filter, then the keyring must fail to
 * decrypt the EDK, and must not make any KMS calls.
 */
int decrypt1AccountDiscoveryFilter_mismatchedProviderInfoPartition_returnsFailureWithoutKmsCall() {
    DecryptValues dv;
    struct aws_cryptosdk_keyring *keyring = t_create_discovery_keyring(dv.kms_client_mock, { TEST_ACCOUNT_ID_0 });
    t_append_c_str_key_to_edks(
        dv.allocator,
        &dv.edks.encrypted_data_keys,
        &dv.ct_bb,
        "arn:aws-us-gov:kms:us-west-2:000011110000:key/bad",
        dv.provider_id);
    TEST_ASSERT_SUCCESS(aws_cryptosdk_keyring_on_decrypt(
        keyring,
        dv.allocator,
        &dv.unencrypted_data_key,
        &dv.keyring_trace,
        &dv.edks.encrypted_data_keys,
        &dv.encryption_context,
        dv.alg));
    TEST_ASSERT_ADDR_NULL(dv.unencrypted_data_key.buffer);
    TEST_ASSERT(!dv.kms_client_mock->ExpectingOtherCalls());

    return 0;
}

/**
 * If a discovery-mode keyring has one account ID in its discovery filter, and
 * OnDecrypt is called with a list of n-many EDKs of which x-many are
 * authorized by the discovery filter, then the keyring must only call KMS
 * (n - x)-many times.
 */
int decrypt1AccountDiscoveryFilter_someAuthorizedEdks_onlyCallsKmsForAuthorizedEdks() {
    DecryptValues dv;
    struct aws_cryptosdk_keyring *keyring = t_create_discovery_keyring(dv.kms_client_mock, { TEST_ACCOUNT_ID_0 });

    Aws::Vector<Aws::String> key_arns = {
        TEST_ACCOUNT1_KEY_ARNS[0],  // account ID not in filter
        TEST_ACCOUNT0_KEY_ARNS[0],
        "arn:aws-us-gov:kms:us-fake-1:000011110000:key/bad",  // partition differs from filter
        TEST_ACCOUNT0_KEY_ARNS[1],
    };
    for (const auto &key_arn : key_arns) {
        t_append_c_str_key_to_edks(
            dv.allocator, &dv.edks.encrypted_data_keys, &dv.ct_bb, key_arn.c_str(), dv.provider_id);
    }

    dv.kms_client_mock->ExpectDecryptAccumulator(dv.GetRequest().WithKeyId(key_arns[1]), dv.GetErrorOutcome("asdf"));
    dv.kms_client_mock->ExpectDecryptAccumulator(dv.GetRequest().WithKeyId(key_arns[3]), dv.GetErrorOutcome("asdf"));

    TEST_ASSERT_SUCCESS(aws_cryptosdk_keyring_on_decrypt(
        keyring,
        dv.allocator,
        &dv.unencrypted_data_key,
        &dv.keyring_trace,
        &dv.edks.encrypted_data_keys,
        &dv.encryption_context,
        dv.alg));
    TEST_ASSERT_ADDR_NULL(dv.unencrypted_data_key.buffer);
    TEST_ASSERT(!dv.kms_client_mock->ExpectingOtherCalls());

    return 0;
}

/**
 * If a discovery-mode keyring has one account ID in its discovery filter, and
 * OnDecrypt is called with a list of EDKs of which some aren't authorized by
 * the discovery filter, then the keyring must only call KMS for the authorized
 * EDKs. Furthermore, if the first KMS call fails but the second KMS call
 * succeeds, then the EDK for the second call must be decrypted.
 */
int decrypt1AccountDiscoveryFilter_someAuthorizedEdks_decryptsSecondIfFirstCallFails() {
    DecryptValues dv;
    struct aws_cryptosdk_keyring *keyring = t_create_discovery_keyring(dv.kms_client_mock, { TEST_ACCOUNT_ID_0 });

    Aws::Vector<Aws::String> key_arns = {
        TEST_ACCOUNT1_KEY_ARNS[0],
        TEST_ACCOUNT0_KEY_ARNS[0],
        TEST_ACCOUNT1_KEY_ARNS[1],
    };
    Aws::String target_key_arn          = TEST_ACCOUNT0_KEY_ARNS[1];
    const char *target_pt               = "target plaintext";
    Aws::Utils::ByteBuffer target_ct_bb = t_aws_utils_bb_from_char("target ciphertext");

    for (const auto &key_arn : key_arns) {
        t_append_c_str_key_to_edks(
            dv.allocator, &dv.edks.encrypted_data_keys, &dv.ct_bb, key_arn.c_str(), dv.provider_id);
    }
    // Fourth key belongs to this account and has different ciphertext
    t_append_c_str_key_to_edks(
        dv.allocator, &dv.edks.encrypted_data_keys, &target_ct_bb, target_key_arn.c_str(), dv.provider_id);

    dv.kms_client_mock->ExpectDecryptAccumulator(dv.GetRequest().WithKeyId(key_arns[1]), dv.GetErrorOutcome("asdf"));
    dv.kms_client_mock->ExpectDecryptAccumulator(
        dv.GetRequest().WithKeyId(target_key_arn).WithCiphertextBlob(target_ct_bb),
        dv.GetResult().WithKeyId(target_key_arn).WithPlaintext(t_aws_utils_bb_from_char(target_pt)));

    TEST_ASSERT_SUCCESS(aws_cryptosdk_keyring_on_decrypt(
        keyring,
        dv.allocator,
        &dv.unencrypted_data_key,
        &dv.keyring_trace,
        &dv.edks.encrypted_data_keys,
        &dv.encryption_context,
        dv.alg));
    TEST_ASSERT(aws_byte_buf_eq_c_str(&dv.unencrypted_data_key, target_pt));
    TEST_ASSERT(!dv.kms_client_mock->ExpectingOtherCalls());

    return 0;
}

/**
 * If a discovery-mode keyring has one account ID in its discovery filter, and
 * OnDecrypt is called with a list of EDKs of which all are unauthorized by the
 * discovery filter, then the keyring must fail to decrypt each EDK, and must
 * not make any KMS calls.
 */
int decrypt1AccountDiscoveryFilter_noAuthorizedEdks_returnsFailureWithoutKmsCall() {
    DecryptValues dv;
    struct aws_cryptosdk_keyring *keyring = t_create_discovery_keyring(dv.kms_client_mock, { TEST_ACCOUNT_ID_0 });
    for (const auto &key_arn : TEST_ACCOUNT1_KEY_ARNS) {
        t_append_c_str_key_to_edks(
            dv.allocator, &dv.edks.encrypted_data_keys, &dv.ct_bb, key_arn.c_str(), dv.provider_id);
    }

    TEST_ASSERT_SUCCESS(aws_cryptosdk_keyring_on_decrypt(
        keyring,
        dv.allocator,
        &dv.unencrypted_data_key,
        &dv.keyring_trace,
        &dv.edks.encrypted_data_keys,
        &dv.encryption_context,
        dv.alg));
    TEST_ASSERT_ADDR_NULL(dv.unencrypted_data_key.buffer);
    TEST_ASSERT(!dv.kms_client_mock->ExpectingOtherCalls());

    return 0;
}

/**
 * If a discovery-mode keyring has multiple account IDs in its discovery
 * filter, and OnDecrypt is called with a single EDK authorized by the
 * discovery filter, then the keyring must succeed.
 */
int decryptMultiAccountDiscoveryFilter_authorizedProviderInfoArn_returnsSuccess() {
    DecryptValues dv;
    struct aws_cryptosdk_keyring *keyring =
        t_create_discovery_keyring(dv.kms_client_mock, { TEST_ACCOUNT_ID_0, TEST_ACCOUNT_ID_1 });
    Aws::String key_id = TEST_ACCOUNT1_KEY_ARNS[0];
    t_append_c_str_key_to_edks(dv.allocator, &dv.edks.encrypted_data_keys, &dv.ct_bb, key_id.c_str(), dv.provider_id);
    dv.kms_client_mock->ExpectDecryptAccumulator(dv.GetRequest().WithKeyId(key_id), dv.GetResult().WithKeyId(key_id));
    TEST_ASSERT_SUCCESS(aws_cryptosdk_keyring_on_decrypt(
        keyring,
        dv.allocator,
        &dv.unencrypted_data_key,
        &dv.keyring_trace,
        &dv.edks.encrypted_data_keys,
        &dv.encryption_context,
        dv.alg));
    TEST_ASSERT_ADDR_NOT_NULL(dv.unencrypted_data_key.buffer);
    TEST_ASSERT(!dv.kms_client_mock->ExpectingOtherCalls());

    return 0;
}

/**
 * If a discovery-mode keyring has multiple account IDs in its discovery
 * filter, and OnDecrypt is called with a single EDK whose key provider info is
 * not in the discovery filter's account ID set, then the keyring must fail to
 * decrypt the EDK, and must not make any KMS calls.
 */
int decryptMultiAccountDiscoveryFilter_mismatchedProviderInfoAccount_returnsFailureWithoutKmsCall() {
    DecryptValues dv;
    struct aws_cryptosdk_keyring *keyring =
        t_create_discovery_keyring(dv.kms_client_mock, { TEST_ACCOUNT_ID_1, TEST_ACCOUNT_ID_2 });
    t_append_c_str_key_to_edks(
        dv.allocator, &dv.edks.encrypted_data_keys, &dv.ct_bb, TEST_ACCOUNT0_KEY_ARNS[0].c_str(), dv.provider_id);
    TEST_ASSERT_SUCCESS(aws_cryptosdk_keyring_on_decrypt(
        keyring,
        dv.allocator,
        &dv.unencrypted_data_key,
        &dv.keyring_trace,
        &dv.edks.encrypted_data_keys,
        &dv.encryption_context,
        dv.alg));
    TEST_ASSERT_ADDR_NULL(dv.unencrypted_data_key.buffer);
    TEST_ASSERT(!dv.kms_client_mock->ExpectingOtherCalls());

    return 0;
}

/**
 * If a discovery-mode keyring has multiple account IDs in its discovery
 * filter, and OnDecrypt is called with a single EDK whose key provider info
 * ARN has a different partition than the discovery filter, then the keyring
 * must fail to decrypt the EDK, and must not make any KMS calls.
 */
int decryptMultiAccountDiscoveryFilter_mismatchedProviderInfoPartition_returnsFailureWithoutKmsCall() {
    DecryptValues dv;
    struct aws_cryptosdk_keyring *keyring =
        t_create_discovery_keyring(dv.kms_client_mock, { TEST_ACCOUNT_ID_0, TEST_ACCOUNT_ID_1 });
    t_append_c_str_key_to_edks(
        dv.allocator,
        &dv.edks.encrypted_data_keys,
        &dv.ct_bb,
        "arn:aws-us-gov:kms:us-west-2:000011110000:key/bad",
        dv.provider_id);
    TEST_ASSERT_SUCCESS(aws_cryptosdk_keyring_on_decrypt(
        keyring,
        dv.allocator,
        &dv.unencrypted_data_key,
        &dv.keyring_trace,
        &dv.edks.encrypted_data_keys,
        &dv.encryption_context,
        dv.alg));
    TEST_ASSERT_ADDR_NULL(dv.unencrypted_data_key.buffer);
    TEST_ASSERT(!dv.kms_client_mock->ExpectingOtherCalls());

    return 0;
}

/**
 * If a discovery-mode keyring has multiple account IDs in its discovery
 * filter, and OnDecrypt is called with a list of n-many EDKs of which x-many
 * are authorized by the discovery filter, then the keyring must only call KMS
 * (n - x)-many times.
 */
int decryptMultiAccountDiscoveryFilter_someAuthorizedEdks_onlyCallsKmsForAuthorizedEdks() {
    DecryptValues dv;
    struct aws_cryptosdk_keyring *keyring =
        t_create_discovery_keyring(dv.kms_client_mock, { TEST_ACCOUNT_ID_0, TEST_ACCOUNT_ID_2 });

    Aws::Vector<Aws::String> key_arns = {
        TEST_ACCOUNT1_KEY_ARNS[0],  // account ID not in filter
        TEST_ACCOUNT0_KEY_ARNS[0],
        "arn:aws-us-gov:kms:us-fake-1:000011110000:key/bad",  // partition differs from filter
        TEST_ACCOUNT0_KEY_ARNS[1],
        TEST_ACCOUNT1_KEY_ARNS[1],  // account ID not in filter
    };
    for (const auto &key_arn : key_arns) {
        t_append_c_str_key_to_edks(
            dv.allocator, &dv.edks.encrypted_data_keys, &dv.ct_bb, key_arn.c_str(), dv.provider_id);
    }

    dv.kms_client_mock->ExpectDecryptAccumulator(dv.GetRequest().WithKeyId(key_arns[1]), dv.GetErrorOutcome("asdf"));
    dv.kms_client_mock->ExpectDecryptAccumulator(dv.GetRequest().WithKeyId(key_arns[3]), dv.GetErrorOutcome("asdf"));

    TEST_ASSERT_SUCCESS(aws_cryptosdk_keyring_on_decrypt(
        keyring,
        dv.allocator,
        &dv.unencrypted_data_key,
        &dv.keyring_trace,
        &dv.edks.encrypted_data_keys,
        &dv.encryption_context,
        dv.alg));
    TEST_ASSERT_ADDR_NULL(dv.unencrypted_data_key.buffer);
    TEST_ASSERT(!dv.kms_client_mock->ExpectingOtherCalls());

    return 0;
}

/**
 * If a discovery-mode keyring has multiple account IDs in its discovery
 * filter, and OnDecrypt is called with a list of EDKs of which some aren't
 * authorized by the discovery filter, then the keyring must only call KMS for
 * the authorized EDKs. Furthermore, if the first KMS call fails but the second
 * KMS call succeeds, then the EDK for the second call must be decrypted.
 */
int decryptMultiAccountDiscoveryFilter_someAuthorizedEdks_decryptsSecondIfFirstCallFails() {
    DecryptValues dv;
    struct aws_cryptosdk_keyring *keyring =
        t_create_discovery_keyring(dv.kms_client_mock, { TEST_ACCOUNT_ID_0, TEST_ACCOUNT_ID_2 });

    Aws::Vector<Aws::String> key_arns = {
        TEST_ACCOUNT1_KEY_ARNS[0],  // account ID not in filter
        TEST_ACCOUNT0_KEY_ARNS[0],
        "arn:aws-us-gov:kms:us-fake-1:000011110000:key/bad",  // partition differs from filter
        TEST_ACCOUNT0_KEY_ARNS[1],
        TEST_ACCOUNT1_KEY_ARNS[1],  // account ID not in filter
    };
    Aws::String target_key_arn          = TEST_ACCOUNT0_KEY_ARNS[1];
    const char *target_pt               = "target plaintext";
    Aws::Utils::ByteBuffer target_ct_bb = t_aws_utils_bb_from_char("target ciphertext");

    for (const auto &key_arn : key_arns) {
        t_append_c_str_key_to_edks(
            dv.allocator, &dv.edks.encrypted_data_keys, &dv.ct_bb, key_arn.c_str(), dv.provider_id);
    }
    // Last key belongs to this account and has different ciphertext
    t_append_c_str_key_to_edks(
        dv.allocator, &dv.edks.encrypted_data_keys, &target_ct_bb, target_key_arn.c_str(), dv.provider_id);

    dv.kms_client_mock->ExpectDecryptAccumulator(dv.GetRequest().WithKeyId(key_arns[1]), dv.GetErrorOutcome("asdf"));
    dv.kms_client_mock->ExpectDecryptAccumulator(dv.GetRequest().WithKeyId(key_arns[3]), dv.GetErrorOutcome("asdf"));
    dv.kms_client_mock->ExpectDecryptAccumulator(
        dv.GetRequest().WithKeyId(target_key_arn).WithCiphertextBlob(target_ct_bb),
        dv.GetResult().WithKeyId(target_key_arn).WithPlaintext(t_aws_utils_bb_from_char(target_pt)));

    TEST_ASSERT_SUCCESS(aws_cryptosdk_keyring_on_decrypt(
        keyring,
        dv.allocator,
        &dv.unencrypted_data_key,
        &dv.keyring_trace,
        &dv.edks.encrypted_data_keys,
        &dv.encryption_context,
        dv.alg));
    TEST_ASSERT(aws_byte_buf_eq_c_str(&dv.unencrypted_data_key, target_pt));
    TEST_ASSERT(!dv.kms_client_mock->ExpectingOtherCalls());

    return 0;
}

// Postcondition: If the caller provides a KMS client, then BuildClientSupplier MUST return a client supplier wrapping the provided client.
int buildClientSupplier_withClient() {
    TestValues test_values;
    std::shared_ptr<Aws::KMS::KMSClient> client(test_values.kms_client_mock);
    auto client_supplier = Private::BuildClientSupplier({}, client, nullptr);
    std::function<void()> report_success;
    TEST_ASSERT(client_supplier->GetClient("region", report_success) == client);

    return 0;
}

// Postcondition: If the caller provides only one key ID and a client supplier, then BuildClientSupplier MUST call the client supplier to obtain a KMS client in the key's region. BuildClientSupplier MUST return a client supplier that only supplies the obtained KMS client.
int buildClientSupplier_withSingleKeyAndClientSupplier() {
    TestValues test_values;
    auto client_supplier_mock(Aws::MakeShared<KmsClientSupplierMock>(CLASS_TAG));
    Aws::Vector<Aws::String> key_ids{ test_values.key_id };
    auto client_supplier = Private::BuildClientSupplier(key_ids, nullptr, client_supplier_mock);

    TEST_ASSERT(client_supplier_mock->GetClientMocksMap().size() == 1);
    auto single_client = client_supplier_mock->GetClientMock(test_values.key_region);
    TEST_ASSERT((bool)single_client);

    std::function<void()> report_success;
    TEST_ASSERT(client_supplier->GetClient(test_values.key_region, report_success) == single_client);

    return 0;
}

// Postcondition: If the caller provides only one key ID and no client supplier, then BuildClientSupplier MUST create a KMS client in the key's region, and it MUST return a client supplier that only supplies the created KMS client.
int buildClientSupplier_withSingleKeyAndNoClientSupplier() {
    TestValues test_values;
    Aws::Vector<Aws::String> key_ids{ test_values.key_id };
    auto client_supplier = Private::BuildClientSupplier(key_ids, nullptr, nullptr);

    // Note: the KMS client interface doesn't expose its region, so we can't actually test it
    std::function<void()> report_success;
    TEST_ASSERT((bool)client_supplier->GetClient(test_values.key_region, report_success));

    return 0;
}

// Postcondition: If the caller provides a client supplier, and provides zero or at least two key IDs, then BuildClientSupplier MUST return the provided client supplier.
int buildClientSupplier_withZeroOrMultipleKeysAndClientSupplier() {
    TestValues test_values;
    auto client_supplier_mock(Aws::MakeShared<KmsClientSupplierMock>(CLASS_TAG));
    TEST_ASSERT(Private::BuildClientSupplier({}, nullptr, client_supplier_mock) == client_supplier_mock);
    TEST_ASSERT(
        Private::BuildClientSupplier({ test_values.key_id, test_values.key_id }, nullptr, client_supplier_mock) ==
        client_supplier_mock);

    return 0;
}

// Postcondition: If the caller does not provide a client supplier, and provides zero or at least two key IDs, then BuildClientSupplier MUST return a default client supplier.
int buildClientSupplier_withZeroOrMultipleKeysAndNoClientSupplier() {
    TestValues test_values;
    TEST_ASSERT((bool)Private::BuildClientSupplier({}, nullptr, nullptr));
    TEST_ASSERT((bool)Private::BuildClientSupplier({ test_values.key_id, test_values.key_id }, nullptr, nullptr));

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
    RUN_TEST(testBuilder_keyWithRegion_valid());
    RUN_TEST(testBuilder_keyWithoutRegion_invalid());
    RUN_TEST(testBuilder_emptyKey_invalid());
    RUN_TEST(testBuilder_emptyAdditionalKey_invalid());

    RUN_TEST(decrypt_validEdk_providesKeyProviderInfoAsKeyId());
    RUN_TEST(decrypt_distinctEdkKeyProviderInfos_callsKmsWithRespectiveKeyIds());
    RUN_TEST(decrypt_kmsResponseKeyIdDiffersFromKeyProviderInfo_returnsFailure());
    RUN_TEST(decrypt_kmsResponseKeyIdMatchesKeyProviderInfo_returnsSuccess());
    RUN_TEST(decrypt_publicConstructorForNonDiscoveryMode_returnsSuccess());

    // Non-discovery, single key name, single EDK
    RUN_TEST(nonDiscoverySingleKeyName_singleEdkMatchingKeyName_returnsSuccess());
    RUN_TEST(nonDiscoverySingleKeyName_singleEdkWithMismatchedKeyName_doesNotDecryptOrCallKms());
    // Non-discovery, single key name, list of EDKs
    RUN_TEST(nonDiscoverySingleKeyName_edksWithoutMatchingKeyName_returnsFailureWithoutKmsCall());
    RUN_TEST(nonDiscoverySingleKeyName_edksAllMatchingKeyName_decryptsFirstEdk());
    RUN_TEST(nonDiscoverySingleKeyName_edksAllMatchingKeyNameButFirstEdkFails_decryptsSecondEdk());
    RUN_TEST(nonDiscoverySingleKeyName_edksWithOneMatchingKeyProviderInfo_decryptsOnlyMatchingEdk());
    // Non-discovery, list of key names, single EDK
    RUN_TEST(nonDiscoveryKeyNames_singleEdkMatchingName_returnsSuccess());
    RUN_TEST(nonDiscoveryKeyNames_singleEdkWithMismatchedName_doesNotDecryptOrCallKms());
    // Non-discovery, list of key names, list of EDKs
    RUN_TEST(nonDiscoveryKeyNames_edksWithoutMatchingKeyName_returnsFailureWithoutKmsCall());
    RUN_TEST(nonDiscoveryKeyNames_edksAllMatchingKeyName_decryptsFirstEdk());
    RUN_TEST(nonDiscoveryKeyNames_edksAllMatchingKeyNameButFirstEdkFails_decryptsSecondEdk());
    RUN_TEST(nonDiscoveryKeyNames_edksWithOneMatchingKeyProviderInfo_decryptsOnlyMatchingEdk());

    // Discovery (implies no key names)
    RUN_TEST(decrypt_publicConstructorForDiscoveryMode_returnsSuccess());
    RUN_TEST(buildDiscovery_validFilter_returnsSuccess());
    RUN_TEST(buildDiscovery_nonsenseFilter_returnsSuccess());
    RUN_TEST(buildDiscovery_nullFilter_returnsNull());
    RUN_TEST(discoveryNoKeyNames_callWithDecryptableEdk_decryptsEdk());
    RUN_TEST(discoveryNoKeyNames_callWithUndecryptableEdk_failsToDecryptEdk());

    // Discovery filter builder
    RUN_TEST(discoveryFilterBuild_blankPartition_returnsFailure());
    RUN_TEST(discoveryFilterBuild_noAccountIds_returnsFailure());
    RUN_TEST(discoveryFilterBuild_invalidAccountIds_returnsFailure());

    // Decryption with discovery filter with 1 account ID
    RUN_TEST(decrypt1AccountDiscoveryFilter_edkWithoutProviderInfo_returnsFailureWithoutKmsCall());
    RUN_TEST(decrypt1AccountDiscoveryFilter_edkNonArnProviderInfo_returnsFailureWithoutKmsCall());
    RUN_TEST(decrypt1AccountDiscoveryFilter_authorizedProviderInfoArn_returnsSuccess());
    RUN_TEST(decrypt1AccountDiscoveryFilter_mismatchedProviderInfoAccount_returnsFailureWithoutKmsCall());
    RUN_TEST(decrypt1AccountDiscoveryFilter_mismatchedProviderInfoPartition_returnsFailureWithoutKmsCall());
    RUN_TEST(decrypt1AccountDiscoveryFilter_someAuthorizedEdks_onlyCallsKmsForAuthorizedEdks());
    RUN_TEST(decrypt1AccountDiscoveryFilter_someAuthorizedEdks_decryptsSecondIfFirstCallFails());
    RUN_TEST(decrypt1AccountDiscoveryFilter_noAuthorizedEdks_returnsFailureWithoutKmsCall());

    // Decryption with discovery filter with multiple account IDs
    RUN_TEST(decryptMultiAccountDiscoveryFilter_authorizedProviderInfoArn_returnsSuccess());
    RUN_TEST(decryptMultiAccountDiscoveryFilter_mismatchedProviderInfoAccount_returnsFailureWithoutKmsCall());
    RUN_TEST(decryptMultiAccountDiscoveryFilter_mismatchedProviderInfoPartition_returnsFailureWithoutKmsCall());
    RUN_TEST(decryptMultiAccountDiscoveryFilter_someAuthorizedEdks_onlyCallsKmsForAuthorizedEdks());
    RUN_TEST(decryptMultiAccountDiscoveryFilter_someAuthorizedEdks_decryptsSecondIfFirstCallFails());

    // BuildClientSupplier helper
    RUN_TEST(buildClientSupplier_withClient());
    RUN_TEST(buildClientSupplier_withSingleKeyAndClientSupplier());
    RUN_TEST(buildClientSupplier_withSingleKeyAndNoClientSupplier());
    RUN_TEST(buildClientSupplier_withZeroOrMultipleKeysAndClientSupplier());
    RUN_TEST(buildClientSupplier_withZeroOrMultipleKeysAndNoClientSupplier());

    Aws::ShutdownAPI(*options);
    Aws::Delete(options);
    return 0;
}
