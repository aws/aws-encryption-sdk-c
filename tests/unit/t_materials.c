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
#include <aws/cryptosdk/default_cmm.h>
#include <aws/cryptosdk/session.h>
#include "testing.h"
#include "zero_keyring.h"
#include "bad_cmm.h"

int default_cmm_zero_keyring_enc_mat() {
    struct aws_hash_table enc_context;
    struct aws_allocator * alloc = aws_default_allocator();
    struct aws_cryptosdk_keyring * kr = aws_cryptosdk_zero_keyring_new();
    struct aws_cryptosdk_cmm * cmm = aws_cryptosdk_default_cmm_new(alloc, kr);

    struct aws_cryptosdk_encryption_request req;
    req.enc_context = &enc_context; // this is uninitialized; we just want to see if it gets passed along
    req.requested_alg = AES_256_GCM_IV12_AUTH16_KDNONE_SIGNONE;
    req.alloc = aws_default_allocator();

    struct aws_cryptosdk_encryption_materials * enc_mat;
    TEST_ASSERT_INT_EQ(AWS_OP_SUCCESS,
                       aws_cryptosdk_cmm_generate_encryption_materials(cmm, &enc_mat, &req));

    TEST_ASSERT_ADDR_EQ(enc_mat->enc_context, &enc_context);
    TEST_ASSERT_INT_EQ(enc_mat->alg, AES_256_GCM_IV12_AUTH16_KDNONE_SIGNONE);

    TEST_ASSERT_BUF_EQ(enc_mat->unencrypted_data_key,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00);

    TEST_ASSERT_INT_EQ(enc_mat->encrypted_data_keys.length, 1);
    struct aws_cryptosdk_edk * edk;
    TEST_ASSERT_INT_EQ(AWS_OP_SUCCESS,
                       aws_array_list_get_at_ptr(&enc_mat->encrypted_data_keys, (void **)&edk, 0));

    TEST_ASSERT_BUF_EQ(edk->enc_data_key, 'n', 'u', 'l', 'l');
    TEST_ASSERT_BUF_EQ(edk->provider_id, 'n', 'u', 'l', 'l');
    TEST_ASSERT_BUF_EQ(edk->provider_info, 'n', 'u', 'l', 'l');

    aws_cryptosdk_encryption_materials_destroy(enc_mat);
    aws_cryptosdk_cmm_release(cmm);
    aws_cryptosdk_keyring_release(kr);

    return 0;
}

int default_cmm_zero_keyring_dec_mat() {
    struct aws_allocator * alloc = aws_default_allocator();
    struct aws_cryptosdk_keyring * kr = aws_cryptosdk_zero_keyring_new();
    struct aws_cryptosdk_cmm * cmm = aws_cryptosdk_default_cmm_new(alloc, kr);

    struct aws_cryptosdk_decryption_request req;
    req.alg = AES_192_GCM_IV12_AUTH16_KDNONE_SIGNONE;
    req.alloc = aws_default_allocator();

    aws_array_list_init_dynamic(&req.encrypted_data_keys, alloc, 1, sizeof(struct aws_cryptosdk_edk));
    struct aws_cryptosdk_edk edk;
    aws_cryptosdk_literally_null_edk(&edk);

    aws_array_list_push_back(&req.encrypted_data_keys, (void *) &edk);

    struct aws_cryptosdk_decryption_materials * dec_mat;
    TEST_ASSERT_INT_EQ(AWS_OP_SUCCESS, aws_cryptosdk_cmm_decrypt_materials(cmm, &dec_mat, &req));

    TEST_ASSERT_BUF_EQ(dec_mat->unencrypted_data_key,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00);

    aws_cryptosdk_decryption_materials_destroy(dec_mat);
    aws_cryptosdk_cmm_release(cmm);
    aws_cryptosdk_keyring_release(kr);
    aws_array_list_clean_up(&req.encrypted_data_keys);
    return 0;
}

int zero_size_cmm_does_not_run_vfs() {
    struct aws_cryptosdk_cmm cmm = aws_cryptosdk_zero_size_cmm();
    TEST_ASSERT_ERROR(AWS_ERROR_UNIMPLEMENTED,
                      aws_cryptosdk_cmm_generate_encryption_materials(&cmm, NULL, NULL));

    TEST_ASSERT_ERROR(AWS_ERROR_UNIMPLEMENTED,
                      aws_cryptosdk_cmm_decrypt_materials(&cmm, NULL, NULL));

    TEST_ASSERT_ERROR(AWS_ERROR_UNIMPLEMENTED,
                      aws_cryptosdk_cmm_release_with_failed_return_value(&cmm));

    return 0;
}

int null_cmm_fails_vf_calls_cleanly() {
    struct aws_cryptosdk_cmm cmm = aws_cryptosdk_null_cmm();
    TEST_ASSERT_ERROR(AWS_ERROR_UNIMPLEMENTED,
                      aws_cryptosdk_cmm_generate_encryption_materials(&cmm, NULL, NULL));

    TEST_ASSERT_ERROR(AWS_ERROR_UNIMPLEMENTED,
                      aws_cryptosdk_cmm_decrypt_materials(&cmm, NULL, NULL));

    TEST_ASSERT_ERROR(AWS_ERROR_UNIMPLEMENTED,
                      aws_cryptosdk_cmm_release_with_failed_return_value(&cmm));
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
    .vt_size = sizeof(track_destroy_cmm_vt),
    .name = "track_destroy_cmm_vt",
    .destroy = track_destroy_cmm
};

static const struct aws_cryptosdk_keyring_vt track_destroy_keyring_vt = {
    .vt_size = sizeof(track_destroy_keyring_vt),
    .name = "track_destroy_keyring_vt",
    .destroy = track_destroy_keyring
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

struct test_case materials_test_cases[] = {
    { "materials", "default_cmm_zero_keyring_enc_mat", default_cmm_zero_keyring_enc_mat },
    { "materials", "default_cmm_zero_keyring_dec_mat", default_cmm_zero_keyring_dec_mat },
    { "materials", "zero_size_cmm_does_not_run_vfs", zero_size_cmm_does_not_run_vfs },
    { "materials", "null_cmm_fails_vf_calls_cleanly", null_cmm_fails_vf_calls_cleanly },
    { "materials", "null_materials_release_is_noop", null_materials_release_is_noop },
    { "materials", "refcount_cmm", refcount_cmm },
    { "materials", "refcount_keyring", refcount_keyring },
    { "materials", "session_updates_cmm_refcount", session_updates_cmm_refcount },
    { NULL }
};
