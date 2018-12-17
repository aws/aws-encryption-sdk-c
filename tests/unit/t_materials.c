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

#include <aws/common/array_list.h>
#include <aws/common/string.h>
#include <aws/cryptosdk/cipher.h>
#include <aws/cryptosdk/default_cmm.h>
#include <aws/cryptosdk/enc_context.h>
#include <aws/cryptosdk/materials.h>
#include <aws/cryptosdk/session.h>
#include "bad_cmm.h"
#include "test_keyring.h"
#include "testing.h"
#include "zero_keyring.h"

int default_cmm_zero_keyring_enc_mat() {
    struct aws_hash_table enc_context;
    struct aws_allocator *alloc      = aws_default_allocator();
    struct aws_cryptosdk_keyring *kr = aws_cryptosdk_zero_keyring_new(alloc);
    struct aws_cryptosdk_cmm *cmm    = aws_cryptosdk_default_cmm_new(alloc, kr);

    aws_cryptosdk_enc_context_init(alloc, &enc_context);

    struct aws_cryptosdk_encryption_request req;
    req.enc_context   = &enc_context;
    req.requested_alg = 0;
    req.alloc         = aws_default_allocator();

    aws_cryptosdk_default_cmm_set_alg_id(cmm, AES_256_GCM_IV12_AUTH16_KDNONE_SIGNONE);

    struct aws_cryptosdk_encryption_materials *enc_mat;
    TEST_ASSERT_INT_EQ(AWS_OP_SUCCESS, aws_cryptosdk_cmm_generate_encryption_materials(cmm, &enc_mat, &req));
    TEST_ASSERT(req.requested_alg != 0);

    TEST_ASSERT_INT_EQ(enc_mat->alg, AES_256_GCM_IV12_AUTH16_KDNONE_SIGNONE);
    TEST_ASSERT_INT_EQ(enc_mat->alg, req.requested_alg);

    // clang-format off
    TEST_ASSERT_BUF_EQ(enc_mat->unencrypted_data_key,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00);
    // clang-format on

    TEST_ASSERT_INT_EQ(enc_mat->encrypted_data_keys.length, 1);
    struct aws_cryptosdk_edk *edk;
    TEST_ASSERT_INT_EQ(AWS_OP_SUCCESS, aws_array_list_get_at_ptr(&enc_mat->encrypted_data_keys, (void **)&edk, 0));

    TEST_ASSERT_BUF_EQ(edk->enc_data_key, 'n', 'u', 'l', 'l');
    TEST_ASSERT_BUF_EQ(edk->provider_id, 'n', 'u', 'l', 'l');
    TEST_ASSERT_BUF_EQ(edk->provider_info, 'n', 'u', 'l', 'l');

    aws_cryptosdk_encryption_materials_destroy(enc_mat);
    aws_cryptosdk_cmm_release(cmm);
    aws_cryptosdk_keyring_release(kr);
    aws_cryptosdk_enc_context_clean_up(&enc_context);

    return 0;
}

int default_cmm_zero_keyring_dec_mat() {
    struct aws_allocator *alloc      = aws_default_allocator();
    struct aws_cryptosdk_keyring *kr = aws_cryptosdk_zero_keyring_new(alloc);
    struct aws_cryptosdk_cmm *cmm    = aws_cryptosdk_default_cmm_new(alloc, kr);

    struct aws_cryptosdk_decryption_request req;
    req.alg   = AES_192_GCM_IV12_AUTH16_KDNONE_SIGNONE;
    req.alloc = aws_default_allocator();

    TEST_ASSERT_SUCCESS(aws_cryptosdk_edk_list_init(alloc, &req.encrypted_data_keys));
    struct aws_cryptosdk_edk edk;
    aws_cryptosdk_literally_null_edk(&edk);

    TEST_ASSERT_SUCCESS(aws_array_list_push_back(&req.encrypted_data_keys, (void *)&edk));

    struct aws_cryptosdk_decryption_materials *dec_mat;
    TEST_ASSERT_INT_EQ(AWS_OP_SUCCESS, aws_cryptosdk_cmm_decrypt_materials(cmm, &dec_mat, &req));

    // clang-format off
    TEST_ASSERT_BUF_EQ(dec_mat->unencrypted_data_key,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00);
    // clang-format on

    aws_cryptosdk_decryption_materials_destroy(dec_mat);
    aws_cryptosdk_cmm_release(cmm);
    aws_cryptosdk_keyring_release(kr);
    aws_array_list_clean_up(&req.encrypted_data_keys);
    return 0;
}

int default_cmm_alg_mismatch() {
    struct aws_hash_table enc_context;
    struct aws_allocator *alloc      = aws_default_allocator();
    struct aws_cryptosdk_keyring *kr = aws_cryptosdk_zero_keyring_new(aws_default_allocator());
    struct aws_cryptosdk_cmm *cmm    = aws_cryptosdk_default_cmm_new(alloc, kr);

    aws_cryptosdk_enc_context_init(alloc, &enc_context);

    struct aws_cryptosdk_encryption_request req;
    req.enc_context   = &enc_context;
    req.requested_alg = AES_192_GCM_IV12_AUTH16_KDNONE_SIGNONE;
    req.alloc         = aws_default_allocator();

    aws_cryptosdk_default_cmm_set_alg_id(cmm, AES_128_GCM_IV12_AUTH16_KDNONE_SIGNONE);

    struct aws_cryptosdk_encryption_materials *enc_mat;
    TEST_ASSERT_SUCCESS(aws_cryptosdk_cmm_generate_encryption_materials(cmm, &enc_mat, &req));
    // The algorithm requested by the higher level CMM should control
    TEST_ASSERT_INT_EQ(req.requested_alg, AES_192_GCM_IV12_AUTH16_KDNONE_SIGNONE);
    // ... and should be reflected in the result
    TEST_ASSERT_INT_EQ(enc_mat->alg, req.requested_alg);

    aws_cryptosdk_encryption_materials_destroy(enc_mat);
    aws_cryptosdk_cmm_release(cmm);
    aws_cryptosdk_keyring_release(kr);
    aws_cryptosdk_enc_context_clean_up(&enc_context);

    return 0;
}

int default_cmm_alg_match() {
    struct aws_hash_table enc_context;
    struct aws_allocator *alloc      = aws_default_allocator();
    struct aws_cryptosdk_keyring *kr = aws_cryptosdk_zero_keyring_new(aws_default_allocator());
    struct aws_cryptosdk_cmm *cmm    = aws_cryptosdk_default_cmm_new(alloc, kr);

    aws_cryptosdk_enc_context_init(alloc, &enc_context);

    struct aws_cryptosdk_encryption_request req;
    req.enc_context   = &enc_context;
    req.requested_alg = AES_192_GCM_IV12_AUTH16_KDNONE_SIGNONE;
    req.alloc         = aws_default_allocator();

    aws_cryptosdk_default_cmm_set_alg_id(cmm, AES_192_GCM_IV12_AUTH16_KDNONE_SIGNONE);

    struct aws_cryptosdk_encryption_materials *enc_mat;
    TEST_ASSERT_SUCCESS(aws_cryptosdk_cmm_generate_encryption_materials(cmm, &enc_mat, &req));
    TEST_ASSERT_INT_EQ(req.requested_alg, AES_192_GCM_IV12_AUTH16_KDNONE_SIGNONE);
    TEST_ASSERT_INT_EQ(enc_mat->alg, req.requested_alg);

    aws_cryptosdk_encryption_materials_destroy(enc_mat);
    aws_cryptosdk_cmm_release(cmm);
    aws_cryptosdk_keyring_release(kr);
    aws_cryptosdk_enc_context_clean_up(&enc_context);

    return 0;
}

static enum aws_cryptosdk_alg_id known_algorithms[] = {
    AES_256_GCM_IV12_AUTH16_KDSHA384_SIGEC384, AES_192_GCM_IV12_AUTH16_KDSHA384_SIGEC384,
    AES_128_GCM_IV12_AUTH16_KDSHA256_SIGEC256, AES_256_GCM_IV12_AUTH16_KDSHA256_SIGNONE,
    AES_192_GCM_IV12_AUTH16_KDSHA256_SIGNONE,  AES_128_GCM_IV12_AUTH16_KDSHA256_SIGNONE,
    AES_256_GCM_IV12_AUTH16_KDNONE_SIGNONE,    AES_192_GCM_IV12_AUTH16_KDNONE_SIGNONE,
    AES_128_GCM_IV12_AUTH16_KDNONE_SIGNONE
};

int default_cmm_context_presence() {
    AWS_STATIC_STRING_FROM_LITERAL(EC_PUBLIC_KEY_FIELD, "aws-crypto-public-key");

    struct aws_hash_table enc_context;
    struct aws_allocator *alloc      = aws_default_allocator();
    struct aws_cryptosdk_keyring *kr = aws_cryptosdk_zero_keyring_new(aws_default_allocator());
    struct aws_cryptosdk_cmm *cmm    = aws_cryptosdk_default_cmm_new(alloc, kr);

    aws_cryptosdk_enc_context_init(alloc, &enc_context);

    for (size_t i = 0; i < sizeof(known_algorithms) / sizeof(*known_algorithms); i++) {
        enum aws_cryptosdk_alg_id alg_id                 = known_algorithms[i];
        const struct aws_cryptosdk_alg_properties *props = aws_cryptosdk_alg_props(alg_id);

        aws_cryptosdk_enc_context_clear(&enc_context);

        struct aws_cryptosdk_encryption_request req;
        req.enc_context   = &enc_context;
        req.requested_alg = 0;
        req.alloc         = aws_default_allocator();

        aws_cryptosdk_default_cmm_set_alg_id(cmm, alg_id);

        struct aws_cryptosdk_encryption_materials *enc_mat;
        TEST_ASSERT_SUCCESS(aws_cryptosdk_cmm_generate_encryption_materials(cmm, &enc_mat, &req));
        TEST_ASSERT_INT_EQ(alg_id, req.requested_alg);

        struct aws_hash_element *pElem = NULL;

        aws_hash_table_find(&enc_context, EC_PUBLIC_KEY_FIELD, &pElem);
        if (props->signature_len) {
            TEST_ASSERT_ADDR_NOT_NULL(pElem);
            TEST_ASSERT_ADDR_NOT_NULL(enc_mat->signctx);
        } else {
            TEST_ASSERT_ADDR_NULL(pElem);
            TEST_ASSERT_ADDR_NULL(enc_mat->signctx);
        }

        aws_cryptosdk_encryption_materials_destroy(enc_mat);
    }

    aws_cryptosdk_cmm_release(cmm);
    aws_cryptosdk_keyring_release(kr);
    aws_cryptosdk_enc_context_clean_up(&enc_context);

    return 0;
}

int zero_size_cmm_does_not_run_vfs() {
    struct aws_cryptosdk_cmm cmm = aws_cryptosdk_zero_size_cmm();
    TEST_ASSERT_ERROR(AWS_ERROR_UNIMPLEMENTED, aws_cryptosdk_cmm_generate_encryption_materials(&cmm, NULL, NULL));

    TEST_ASSERT_ERROR(AWS_ERROR_UNIMPLEMENTED, aws_cryptosdk_cmm_decrypt_materials(&cmm, NULL, NULL));

    TEST_ASSERT_ERROR(AWS_ERROR_UNIMPLEMENTED, aws_cryptosdk_cmm_release_with_failed_return_value(&cmm));

    return 0;
}

int null_cmm_fails_vf_calls_cleanly() {
    struct aws_cryptosdk_cmm cmm = aws_cryptosdk_null_cmm();
    TEST_ASSERT_ERROR(AWS_ERROR_UNIMPLEMENTED, aws_cryptosdk_cmm_generate_encryption_materials(&cmm, NULL, NULL));

    TEST_ASSERT_ERROR(AWS_ERROR_UNIMPLEMENTED, aws_cryptosdk_cmm_decrypt_materials(&cmm, NULL, NULL));

    TEST_ASSERT_ERROR(AWS_ERROR_UNIMPLEMENTED, aws_cryptosdk_cmm_release_with_failed_return_value(&cmm));
    return 0;
}

int null_materials_release_is_noop() {
    aws_cryptosdk_cmm_release(NULL);
    aws_cryptosdk_keyring_release(NULL);

    return 0;
}

static bool destroy_called = false;
static void track_destroy_cmm(struct aws_cryptosdk_cmm *cmm) {
    (void)cmm;

    destroy_called = true;
}

static void track_destroy_keyring(struct aws_cryptosdk_keyring *keyring) {
    (void)keyring;

    destroy_called = true;
}

static const struct aws_cryptosdk_cmm_vt track_destroy_cmm_vt = {
    .vt_size = sizeof(track_destroy_cmm_vt), .name = "track_destroy_cmm_vt", .destroy = track_destroy_cmm
};

static const struct aws_cryptosdk_keyring_vt track_destroy_keyring_vt = {
    .vt_size = sizeof(track_destroy_keyring_vt), .name = "track_destroy_keyring_vt", .destroy = track_destroy_keyring
};

static int refcount_keyring() {
    struct aws_cryptosdk_keyring keyring;
    aws_cryptosdk_keyring_base_init(&keyring, &track_destroy_keyring_vt);
    destroy_called = false;

    TEST_ASSERT_INT_EQ(aws_atomic_load_int(&keyring.refcount), 1);
    TEST_ASSERT_ADDR_EQ(&keyring, aws_cryptosdk_keyring_retain(&keyring));
    TEST_ASSERT_INT_EQ(aws_atomic_load_int(&keyring.refcount), 2);
    TEST_ASSERT_INT_EQ(destroy_called, false);
    TEST_ASSERT_ADDR_EQ(&keyring, aws_cryptosdk_keyring_retain(&keyring));
    TEST_ASSERT_INT_EQ(aws_atomic_load_int(&keyring.refcount), 3);
    TEST_ASSERT_INT_EQ(destroy_called, false);

    aws_cryptosdk_keyring_release(&keyring);
    TEST_ASSERT_INT_EQ(aws_atomic_load_int(&keyring.refcount), 2);
    TEST_ASSERT_INT_EQ(destroy_called, false);

    aws_cryptosdk_keyring_release(&keyring);
    TEST_ASSERT_INT_EQ(aws_atomic_load_int(&keyring.refcount), 1);
    TEST_ASSERT_INT_EQ(destroy_called, false);

    aws_cryptosdk_keyring_release(&keyring);
    TEST_ASSERT_INT_EQ(destroy_called, true);

    return 0;
}

static int refcount_cmm() {
    struct aws_cryptosdk_cmm cmm;
    aws_cryptosdk_cmm_base_init(&cmm, &track_destroy_cmm_vt);
    destroy_called = false;

    TEST_ASSERT_INT_EQ(aws_atomic_load_int(&cmm.refcount), 1);
    TEST_ASSERT_ADDR_EQ(&cmm, aws_cryptosdk_cmm_retain(&cmm));
    TEST_ASSERT_INT_EQ(aws_atomic_load_int(&cmm.refcount), 2);
    TEST_ASSERT_INT_EQ(destroy_called, false);
    TEST_ASSERT_ADDR_EQ(&cmm, aws_cryptosdk_cmm_retain(&cmm));
    TEST_ASSERT_INT_EQ(aws_atomic_load_int(&cmm.refcount), 3);
    TEST_ASSERT_INT_EQ(destroy_called, false);

    aws_cryptosdk_cmm_release(&cmm);
    TEST_ASSERT_INT_EQ(aws_atomic_load_int(&cmm.refcount), 2);
    TEST_ASSERT_INT_EQ(destroy_called, false);

    aws_cryptosdk_cmm_release(&cmm);
    TEST_ASSERT_INT_EQ(aws_atomic_load_int(&cmm.refcount), 1);
    TEST_ASSERT_INT_EQ(destroy_called, false);

    aws_cryptosdk_cmm_release(&cmm);
    TEST_ASSERT_INT_EQ(destroy_called, true);

    return 0;
}

static int session_updates_cmm_refcount() {
    struct aws_cryptosdk_cmm cmm;
    struct aws_cryptosdk_session *session;
    aws_cryptosdk_cmm_base_init(&cmm, &track_destroy_cmm_vt);
    destroy_called = false;

    TEST_ASSERT_INT_EQ(aws_atomic_load_int(&cmm.refcount), 1);

    session = aws_cryptosdk_session_new_from_cmm(aws_default_allocator(), AWS_CRYPTOSDK_ENCRYPT, &cmm);
    TEST_ASSERT_INT_EQ(aws_atomic_load_int(&cmm.refcount), 2);

    aws_cryptosdk_cmm_release(&cmm);
    TEST_ASSERT_INT_EQ(aws_atomic_load_int(&cmm.refcount), 1);

    aws_cryptosdk_session_destroy(session);
    TEST_ASSERT_INT_EQ(destroy_called, true);

    return 0;
}

static struct test_keyring test_kr;
static struct aws_cryptosdk_keyring *kr;
static struct aws_allocator *alloc;
static struct aws_array_list edks;
static struct aws_array_list keyring_trace;

static void reset_test_keyring() {
    memset(&test_kr, 0, sizeof(test_kr));
    kr = &test_kr.base;
    aws_cryptosdk_keyring_base_init(kr, &test_keyring_vt);
}

static int setup_condition_violation_test() {
    alloc = aws_default_allocator();
    reset_test_keyring();
    TEST_ASSERT_SUCCESS(aws_cryptosdk_edk_list_init(alloc, &edks));
    TEST_ASSERT_SUCCESS(aws_cryptosdk_keyring_trace_init(alloc, &keyring_trace));
    return 0;
}

static void teardown_condition_violation_test() {
    aws_cryptosdk_edk_list_clean_up(&edks);
    aws_cryptosdk_keyring_trace_clean_up(&keyring_trace);
}

int on_encrypt_precondition_violation() {
    /* No data key but at least one EDK -> raise error and do not make virtual call */
    TEST_ASSERT_SUCCESS(setup_condition_violation_test());

    struct aws_byte_buf unencrypted_data_key = { 0 };
    struct aws_cryptosdk_edk edk             = { { 0 } };
    TEST_ASSERT_SUCCESS(aws_array_list_push_back(&edks, &edk));

    TEST_ASSERT_ERROR(
        AWS_CRYPTOSDK_ERR_BAD_STATE,
        aws_cryptosdk_keyring_on_encrypt(kr, alloc, &unencrypted_data_key, &keyring_trace, &edks, NULL, 0));

    TEST_ASSERT(!test_kr.on_encrypt_called);

    teardown_condition_violation_test();
    return 0;
}

int on_encrypt_postcondition_violation() {
    /* Generate data key of wrong length -> raise error after virtual call */
    TEST_ASSERT_SUCCESS(setup_condition_violation_test());
    test_kr.generated_data_key_to_return = aws_byte_buf_from_c_str("wrong data key length");

    struct aws_byte_buf unencrypted_data_key = { 0 };

    TEST_ASSERT_ERROR(
        AWS_CRYPTOSDK_ERR_BAD_STATE,
        aws_cryptosdk_keyring_on_encrypt(
            kr, alloc, &unencrypted_data_key, &keyring_trace, &edks, NULL, AES_256_GCM_IV12_AUTH16_KDSHA384_SIGEC384));

    TEST_ASSERT(test_kr.on_encrypt_called);

    teardown_condition_violation_test();
    return 0;
}

int on_decrypt_precondition_violation() {
    /* Unencrypted data key buffer already set -> raise error and do not make virtual call */
    TEST_ASSERT_SUCCESS(setup_condition_violation_test());

    struct aws_byte_buf unencrypted_data_key = aws_byte_buf_from_c_str("Oops, already set!");
    TEST_ASSERT_ERROR(
        AWS_CRYPTOSDK_ERR_BAD_STATE,
        aws_cryptosdk_keyring_on_decrypt(kr, alloc, &unencrypted_data_key, &keyring_trace, &edks, NULL, 0));

    TEST_ASSERT(!test_kr.on_decrypt_called);

    teardown_condition_violation_test();
    return 0;
}

int on_decrypt_postcondition_violation() {
    /* Decrypt data key of wrong length -> raise error after virtual call */
    TEST_ASSERT_SUCCESS(setup_condition_violation_test());

    struct aws_byte_buf unencrypted_data_key = { 0 };

    test_kr.decrypted_data_key_to_return = aws_byte_buf_from_c_str("wrong data key length");

    TEST_ASSERT_ERROR(
        AWS_CRYPTOSDK_ERR_BAD_CIPHERTEXT,
        aws_cryptosdk_keyring_on_decrypt(
            kr, alloc, &unencrypted_data_key, &keyring_trace, &edks, NULL, AES_256_GCM_IV12_AUTH16_KDSHA384_SIGEC384));

    teardown_condition_violation_test();
    return 0;
}

struct test_case materials_test_cases[] = {
    { "materials", "default_cmm_zero_keyring_enc_mat", default_cmm_zero_keyring_enc_mat },
    { "materials", "default_cmm_zero_keyring_dec_mat", default_cmm_zero_keyring_dec_mat },
    { "materials", "default_cmm_alg_mismatch", default_cmm_alg_mismatch },
    { "materials", "default_cmm_alg_match", default_cmm_alg_match },
    { "materials", "default_cmm_context_presence", default_cmm_context_presence },
    { "materials", "zero_size_cmm_does_not_run_vfs", zero_size_cmm_does_not_run_vfs },
    { "materials", "null_cmm_fails_vf_calls_cleanly", null_cmm_fails_vf_calls_cleanly },
    { "materials", "null_materials_release_is_noop", null_materials_release_is_noop },
    { "materials", "refcount_cmm", refcount_cmm },
    { "materials", "refcount_keyring", refcount_keyring },
    { "materials", "session_updates_cmm_refcount", session_updates_cmm_refcount },
    { "materials", "on_encrypt_precondition_violation", on_encrypt_precondition_violation },
    { "materials", "on_encrypt_postcondition_violation", on_encrypt_postcondition_violation },
    { "materials", "on_decrypt_precondition_violation", on_decrypt_precondition_violation },
    { "materials", "on_decrypt_postcondition_violation", on_decrypt_postcondition_violation },
    { NULL }
};
