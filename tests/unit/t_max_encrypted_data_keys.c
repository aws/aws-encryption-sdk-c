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

#include <aws/common/common.h>
#include <aws/common/encoding.h>
#include <aws/cryptosdk/private/cipher.h>
#include <aws/cryptosdk/private/session.h>
#include <aws/cryptosdk/session.h>
#include <stdlib.h>
#include "testing.h"
#include "testutil.h"
#include "zero_keyring.h"

#define BUFFER_SIZE (1 << 20)

static const char *DATA_KEY_B64               = "+p6+whPVw9kOrYLZFMRBJ2n6Vli6T/7TkjDouS+25s0=";
static const enum aws_cryptosdk_alg_id ALG_ID = ALG_AES256_GCM_IV12_TAG16_NO_KDF;

static uint8_t encrypt_output[BUFFER_SIZE];
static uint8_t decrypt_output[BUFFER_SIZE];

struct multi_edk_cmm {
    struct aws_cryptosdk_cmm base;
    struct aws_allocator *alloc;
    size_t num_edks;
};

static void setup_test() {
    memset(encrypt_output, 0, sizeof(encrypt_output));
    memset(decrypt_output, 0, sizeof(decrypt_output));
}

// Add cmm->num_edks many all-0 EDKs, and set a static data key
int multi_edk_cmm_generate_enc_materials(
    struct aws_cryptosdk_cmm *cmm,
    struct aws_cryptosdk_enc_materials **output,
    struct aws_cryptosdk_enc_request *request) {
    request->requested_alg = ALG_ID;
    struct aws_cryptosdk_enc_materials *materials =
        aws_cryptosdk_enc_materials_new(request->alloc, request->requested_alg);
    TEST_ASSERT_ADDR_NOT_NULL(materials);

    struct multi_edk_cmm *self = (struct multi_edk_cmm *)cmm;

    TEST_ASSERT_SUCCESS(aws_array_list_ensure_capacity(&materials->encrypted_data_keys, self->num_edks));
    memset(materials->encrypted_data_keys.data, 0, materials->encrypted_data_keys.current_size);
    materials->encrypted_data_keys.length = self->num_edks;

    materials->unencrypted_data_key = easy_b64_decode(DATA_KEY_B64);
    *output                         = materials;
    return AWS_OP_SUCCESS;
}

// Set static data key
int multi_edk_cmm_decrypt_materials(
    struct aws_cryptosdk_cmm *cmm,
    struct aws_cryptosdk_dec_materials **output,
    struct aws_cryptosdk_dec_request *request) {
    struct aws_cryptosdk_dec_materials *materials = aws_cryptosdk_dec_materials_new(request->alloc, request->alg);
    TEST_ASSERT_ADDR_NOT_NULL(materials);
    materials->unencrypted_data_key = easy_b64_decode(DATA_KEY_B64);
    *output                         = materials;
    return AWS_OP_SUCCESS;
}

static void multi_edk_cmm_destroy(struct aws_cryptosdk_cmm *cmm) {
    struct multi_edk_cmm *self = (struct multi_edk_cmm *)cmm;
    aws_mem_release(self->alloc, self);
}

static const struct aws_cryptosdk_cmm_vt multi_edk_cmm_vt = {
    .vt_size                = sizeof(struct aws_cryptosdk_cmm_vt),
    .name                   = "multi_edk_cmm",
    .destroy                = multi_edk_cmm_destroy,
    .generate_enc_materials = multi_edk_cmm_generate_enc_materials,
    .decrypt_materials      = multi_edk_cmm_decrypt_materials,
};

static struct aws_cryptosdk_cmm *multi_edk_cmm_new(size_t num_edks) {
    struct aws_allocator *alloc = aws_default_allocator();
    struct multi_edk_cmm *cmm   = aws_mem_acquire(alloc, sizeof(*cmm));
    aws_cryptosdk_cmm_base_init(&cmm->base, &multi_edk_cmm_vt);
    cmm->alloc    = alloc;
    cmm->num_edks = num_edks;
    return (struct aws_cryptosdk_cmm *)cmm;
}

static int set_max_edks_0() {
    setup_test();

    struct aws_cryptosdk_keyring *kr = aws_cryptosdk_zero_keyring_new(aws_default_allocator());
    struct aws_cryptosdk_session *session =
        aws_cryptosdk_session_new_from_keyring_2(aws_default_allocator(), AWS_CRYPTOSDK_DECRYPT, kr);
    TEST_ASSERT_ERROR(AWS_ERROR_INVALID_ARGUMENT, aws_cryptosdk_session_set_max_encrypted_data_keys(session, 0));
    aws_cryptosdk_keyring_release(kr);
    aws_cryptosdk_session_destroy(session);
    return 0;
}

static int set_max_edks_1() {
    setup_test();

    struct aws_cryptosdk_keyring *kr = aws_cryptosdk_zero_keyring_new(aws_default_allocator());
    struct aws_cryptosdk_session *session =
        aws_cryptosdk_session_new_from_keyring_2(aws_default_allocator(), AWS_CRYPTOSDK_DECRYPT, kr);
    TEST_ASSERT_SUCCESS(aws_cryptosdk_session_set_max_encrypted_data_keys(session, 1));
    aws_cryptosdk_keyring_release(kr);
    aws_cryptosdk_session_destroy(session);
    return 0;
}

static int set_max_edks_10() {
    setup_test();

    struct aws_cryptosdk_keyring *kr = aws_cryptosdk_zero_keyring_new(aws_default_allocator());
    struct aws_cryptosdk_session *session =
        aws_cryptosdk_session_new_from_keyring_2(aws_default_allocator(), AWS_CRYPTOSDK_DECRYPT, kr);
    TEST_ASSERT_SUCCESS(aws_cryptosdk_session_set_max_encrypted_data_keys(session, 10));
    aws_cryptosdk_keyring_release(kr);
    aws_cryptosdk_session_destroy(session);
    return 0;
}

static int set_max_edks_uint16_max() {
    setup_test();

    struct aws_cryptosdk_keyring *kr = aws_cryptosdk_zero_keyring_new(aws_default_allocator());
    struct aws_cryptosdk_session *session =
        aws_cryptosdk_session_new_from_keyring_2(aws_default_allocator(), AWS_CRYPTOSDK_DECRYPT, kr);
    TEST_ASSERT_SUCCESS(aws_cryptosdk_session_set_max_encrypted_data_keys(session, UINT16_MAX));
    aws_cryptosdk_keyring_release(kr);
    aws_cryptosdk_session_destroy(session);
    return 0;
}

static const char *PT_BYTES = "foobar";

static int do_encrypt(struct aws_cryptosdk_session *session, uint8_t *encrypt_output, size_t *output_len) {
    size_t input_len = strlen(PT_BYTES);
    size_t input_consumed;
    TEST_ASSERT_SUCCESS(aws_cryptosdk_session_set_message_size(session, input_len));
    int rv = aws_cryptosdk_session_process(
        session, encrypt_output, BUFFER_SIZE, output_len, (const uint8_t *)PT_BYTES, input_len, &input_consumed);
    if (rv) return rv;
    TEST_ASSERT_INT_EQ(input_len, input_consumed);
    TEST_ASSERT(aws_cryptosdk_session_is_done(session));
    return 0;
}

static int do_decrypt(
    struct aws_cryptosdk_session *session, uint8_t *encrypt_output, size_t input_len, uint8_t *decrypt_output) {
    size_t output_len;
    size_t input_consumed;
    int rv = aws_cryptosdk_session_process(
        session, decrypt_output, BUFFER_SIZE, &output_len, encrypt_output, input_len, &input_consumed);
    if (rv) return rv;
    TEST_ASSERT_INT_EQ(input_len, input_consumed);
    TEST_ASSERT(aws_cryptosdk_session_is_done(session));
    TEST_ASSERT_INT_EQ(strncmp(PT_BYTES, (const char *)decrypt_output, BUFFER_SIZE), 0);
    return 0;
}

static int encrypt_and_decrypt_no_max_edks() {
    setup_test();

    struct aws_cryptosdk_cmm *cmm = multi_edk_cmm_new(UINT16_MAX);
    struct aws_cryptosdk_session *session =
        aws_cryptosdk_session_new_from_cmm_2(aws_default_allocator(), AWS_CRYPTOSDK_ENCRYPT, cmm);
    aws_cryptosdk_cmm_release(cmm);
    TEST_ASSERT_SUCCESS(
        aws_cryptosdk_session_set_commitment_policy(session, COMMITMENT_POLICY_FORBID_ENCRYPT_ALLOW_DECRYPT));

    size_t output_len;
    TEST_ASSERT_SUCCESS(do_encrypt(session, encrypt_output, &output_len));
    aws_cryptosdk_session_reset(session, AWS_CRYPTOSDK_DECRYPT);
    TEST_ASSERT_SUCCESS(do_decrypt(session, encrypt_output, output_len, decrypt_output));
    aws_cryptosdk_session_destroy(session);
    return 0;
}

static int do_encrypt_with_n_edks(size_t num_edks) {
    struct aws_cryptosdk_cmm *cmm = multi_edk_cmm_new(num_edks);
    struct aws_cryptosdk_session *session =
        aws_cryptosdk_session_new_from_cmm_2(aws_default_allocator(), AWS_CRYPTOSDK_ENCRYPT, cmm);
    aws_cryptosdk_cmm_release(cmm);
    TEST_ASSERT_SUCCESS(
        aws_cryptosdk_session_set_commitment_policy(session, COMMITMENT_POLICY_FORBID_ENCRYPT_ALLOW_DECRYPT));
    TEST_ASSERT_SUCCESS(aws_cryptosdk_session_set_max_encrypted_data_keys(session, 3));

    size_t output_len;
    int rv = do_encrypt(session, encrypt_output, &output_len);
    aws_cryptosdk_session_destroy(session);
    return rv;
}

static int do_decrypt_with_n_edks(size_t num_edks) {
    struct aws_cryptosdk_cmm *cmm = multi_edk_cmm_new(num_edks);
    struct aws_cryptosdk_session *session =
        aws_cryptosdk_session_new_from_cmm_2(aws_default_allocator(), AWS_CRYPTOSDK_ENCRYPT, cmm);
    aws_cryptosdk_cmm_release(cmm);
    TEST_ASSERT_SUCCESS(
        aws_cryptosdk_session_set_commitment_policy(session, COMMITMENT_POLICY_FORBID_ENCRYPT_ALLOW_DECRYPT));

    size_t output_len;
    TEST_ASSERT_SUCCESS(do_encrypt(session, encrypt_output, &output_len));
    TEST_ASSERT_SUCCESS(aws_cryptosdk_session_reset(session, AWS_CRYPTOSDK_DECRYPT));
    TEST_ASSERT_SUCCESS(aws_cryptosdk_session_set_max_encrypted_data_keys(session, 3));
    int rv = do_decrypt(session, encrypt_output, output_len, decrypt_output);
    aws_cryptosdk_session_destroy(session);
    return rv;
}

static int encrypt_less_than_max_edks() {
    setup_test();

    TEST_ASSERT_SUCCESS(do_encrypt_with_n_edks(2));
    return 0;
}

static int encrypt_equal_to_max_edks() {
    setup_test();

    TEST_ASSERT_SUCCESS(do_encrypt_with_n_edks(3));
    return 0;
}

static int encrypt_more_than_max_edks() {
    setup_test();

    TEST_ASSERT_ERROR(AWS_CRYPTOSDK_ERR_LIMIT_EXCEEDED, do_encrypt_with_n_edks(4));
    return 0;
}

static int decrypt_less_than_max_edks() {
    setup_test();

    TEST_ASSERT_SUCCESS(do_decrypt_with_n_edks(2));
    return 0;
}

static int decrypt_equal_to_max_edks() {
    setup_test();

    TEST_ASSERT_SUCCESS(do_decrypt_with_n_edks(3));
    return 0;
}

static int decrypt_more_than_max_edks() {
    setup_test();

    TEST_ASSERT_ERROR(AWS_CRYPTOSDK_ERR_LIMIT_EXCEEDED, do_decrypt_with_n_edks(4));
    return 0;
}

struct test_case max_edks_test_cases[] = {
    { "max_edks", "set_max_edks_0", set_max_edks_0 },
    { "max_edks", "set_max_edks_1", set_max_edks_1 },
    { "max_edks", "set_max_edks_10", set_max_edks_10 },
    { "max_edks", "set_max_edks_uint16_max", set_max_edks_uint16_max },
    { "max_edks", "encrypt_and_decrypt_no_max_edks", encrypt_and_decrypt_no_max_edks },
    { "max_edks", "encrypt_less_than_max_edks", encrypt_less_than_max_edks },
    { "max_edks", "encrypt_equal_to_max_edks", encrypt_equal_to_max_edks },
    { "max_edks", "encrypt_more_than_max_edks", encrypt_more_than_max_edks },
    { "max_edks", "decrypt_less_than_max_edks", decrypt_less_than_max_edks },
    { "max_edks", "decrypt_equal_to_max_edks", decrypt_equal_to_max_edks },
    { "max_edks", "decrypt_more_than_max_edks", decrypt_more_than_max_edks },
    { NULL }
};
