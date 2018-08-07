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

#include <aws/cryptosdk/multi_mkp.h>
#include <aws/cryptosdk/materials.h>
#include <aws/common/string.h>

#include <stdlib.h>

#include "testing.h"
#include "testutil.h"
#include "zero_mk.h"
#include "counting_mk.h"

struct test_mkp {
    const struct aws_cryptosdk_mkp_vt *vt;

// Keys to return on get_master_keys
    struct aws_array_list mk_list;
// Decrypted key to return on decrypt_data_key
    struct aws_byte_buf decrypted_key;

// Nonzero to force the next call to the test MKP to fail
    int pending_error;

// Set to true after the corresponding methods are invoked
    bool destroy_called;
    bool decrypt_called;
    bool get_mk_called;
};

static struct test_mkp mkp1, mkp2, mkp3;
static struct aws_cryptosdk_mkp *multi_mkp;
static struct aws_array_list mk_list;
static struct aws_hash_table enc_context;
static struct aws_cryptosdk_edk test_edk;
static struct aws_cryptosdk_decryption_request dec_req;
static struct aws_cryptosdk_decryption_materials dec_mat;

static void test_mkp_clean_up(struct test_mkp *test_mkp) {
    aws_byte_buf_clean_up(&test_mkp->decrypted_key);
    aws_array_list_clean_up(&test_mkp->mk_list);
    memset(test_mkp, 0, sizeof(*test_mkp));
}

static void test_mkp_destroy(struct aws_cryptosdk_mkp *mkp) {
    ((struct test_mkp *)mkp)->destroy_called = true;
}

static int test_get_mks(
    struct aws_cryptosdk_mkp *mkp,
    struct aws_array_list *master_keys,
    const struct aws_hash_table *context
) {
    struct test_mkp *self = (struct test_mkp *)mkp;
    self->get_mk_called = true;

    if (self->pending_error) return aws_raise_error(self->pending_error);

// TODO: aws_array_list_push_all?
    size_t num_keys = aws_array_list_length(&self->mk_list);
    for (size_t i = 0; i < num_keys; i++) {
        struct aws_cryptosdk_mk *mk;

        if (aws_array_list_get_at(&self->mk_list, &mk, i)) abort();
        if (aws_array_list_push_back(master_keys, &mk)) abort();
    }

    return AWS_OP_SUCCESS;
}

static int test_decrypt(
    struct aws_cryptosdk_mkp *mkp,
    struct aws_cryptosdk_decryption_materials *dec_mat,
    const struct aws_cryptosdk_decryption_request *req
) {
    struct test_mkp *self = (struct test_mkp *)mkp;
    self->decrypt_called = true;

    if (self->pending_error) return aws_raise_error(self->pending_error);
    if (req != &dec_req) abort();

    if (self->decrypted_key.len) {
        aws_byte_buf_clean_up(&dec_mat->unencrypted_data_key);
        if (aws_byte_buf_init(checked_allocator(), &dec_mat->unencrypted_data_key, self->decrypted_key.len))
            abort();
        memcpy(dec_mat->unencrypted_data_key.buffer, self->decrypted_key.buffer, self->decrypted_key.len);
        dec_mat->unencrypted_data_key.len = self->decrypted_key.len;
    }

    return AWS_OP_SUCCESS;
}

const static struct aws_cryptosdk_mkp_vt test_mkp_vt = {
    .vt_size = sizeof(test_mkp_vt),
    .name = "test mkp",
    .destroy = test_mkp_destroy,
    .get_master_keys = test_get_mks,
    .decrypt_data_key = test_decrypt
};

static void test_mkp_init(struct test_mkp *test_mkp) {
    memset(test_mkp, 0, sizeof(*test_mkp));
    test_mkp->vt = &test_mkp_vt;

    if (aws_array_list_init_dynamic(&test_mkp->mk_list, checked_allocator(), 4, sizeof(struct aws_cryptosdk_mk *)))
        abort();

    if (aws_byte_buf_init(checked_allocator(), &test_mkp->decrypted_key, 32))
        abort();

    test_mkp->decrypted_key.len = 0;
}

static void test_init() {
    test_mkp_init(&mkp1);
    test_mkp_init(&mkp2);
    test_mkp_init(&mkp3);

    if (!(multi_mkp = aws_cryptosdk_multi_mkp_new(checked_allocator()))) {
        // OOM
        abort();
    }

    if (aws_array_list_init_dynamic(&mk_list, checked_allocator(), 4, sizeof(struct aws_cryptosdk_mk *)))
        abort();

    if (aws_hash_table_init(
        &enc_context,
        checked_allocator(),
        16,
        aws_hash_string, aws_string_eq,
        aws_string_destroy, aws_string_destroy
    ))
        abort();
    
    memset(&dec_mat, 0, sizeof(dec_mat));

    test_edk.provider_id = aws_byte_buf_from_c_str("foobar");
    test_edk.provider_info = aws_byte_buf_from_c_str("foobar");
    test_edk.enc_data_key = aws_byte_buf_from_c_str("foobar");
    dec_req.enc_context = &enc_context;
    aws_array_list_init_static(&dec_req.encrypted_data_keys, &test_edk, 1, sizeof(test_edk));

    dec_mat.alg = dec_req.alg = AES_256_GCM_IV12_AUTH16_KDNONE_SIGNONE;
}

static void test_cleanup() {
    aws_cryptosdk_mkp_destroy(multi_mkp);
    multi_mkp = NULL;

    aws_array_list_clean_up(&mk_list);
    aws_hash_table_clean_up(&enc_context);

    aws_byte_buf_clean_up(&dec_mat.unencrypted_data_key);
    test_mkp_clean_up(&mkp1);
    test_mkp_clean_up(&mkp2);
    test_mkp_clean_up(&mkp3);
}

static int test_empty_multi() {
    (void)test_mkp_vt; (void)test_mkp_init; (void)test_mkp_clean_up;
    test_init();

    TEST_ASSERT_SUCCESS(aws_cryptosdk_mkp_get_master_keys(multi_mkp, &mk_list, &enc_context));
    TEST_ASSERT_INT_EQ(0, aws_array_list_length(&mk_list));
    TEST_ASSERT_SUCCESS(aws_cryptosdk_mkp_decrypt_data_key(multi_mkp, &dec_mat, &dec_req));

    test_cleanup();

    return 0;
}

static int test_get_single() {
    test_init();

    struct aws_cryptosdk_mk *mk1 = aws_cryptosdk_zero_mk_new();
    TEST_ASSERT_SUCCESS(aws_array_list_push_back(&mkp1.mk_list, &mk1));

    TEST_ASSERT_SUCCESS(aws_cryptosdk_multi_mkp_add(multi_mkp, (struct aws_cryptosdk_mkp *)&mkp1));
    TEST_ASSERT_SUCCESS(aws_cryptosdk_mkp_get_master_keys(multi_mkp, &mk_list, &enc_context));
    TEST_ASSERT_INT_EQ(1, mkp1.get_mk_called);
    TEST_ASSERT_INT_EQ(0, mkp1.destroy_called);
    TEST_ASSERT_INT_EQ(0, mkp1.decrypt_called);

    struct aws_cryptosdk_mk *mk_result = NULL;
    TEST_ASSERT_INT_EQ(1, aws_array_list_length(&mk_list));
    TEST_ASSERT_SUCCESS(aws_array_list_get_at(&mk_list, &mk_result, 0));
    TEST_ASSERT_ADDR_EQ(mk1, mk_result);

    test_cleanup();
    return 0;
}

static int test_get_multi() {
    test_init();

    struct aws_cryptosdk_mk *mk1 = aws_cryptosdk_zero_mk_new();
    struct aws_cryptosdk_mk *mk2 = aws_cryptosdk_counting_mk();
    TEST_ASSERT_SUCCESS(aws_array_list_push_back(&mkp1.mk_list, &mk1));
    TEST_ASSERT_SUCCESS(aws_array_list_push_back(&mkp2.mk_list, &mk2));

    TEST_ASSERT_SUCCESS(aws_cryptosdk_multi_mkp_add(multi_mkp, (struct aws_cryptosdk_mkp *)&mkp1));
    TEST_ASSERT_SUCCESS(aws_cryptosdk_multi_mkp_add(multi_mkp, (struct aws_cryptosdk_mkp *)&mkp2));
    TEST_ASSERT_SUCCESS(aws_cryptosdk_mkp_get_master_keys(multi_mkp, &mk_list, &enc_context));
    TEST_ASSERT_INT_EQ(1, mkp1.get_mk_called);
    TEST_ASSERT_INT_EQ(0, mkp1.destroy_called);
    TEST_ASSERT_INT_EQ(0, mkp1.decrypt_called);
    TEST_ASSERT_INT_EQ(1, mkp2.get_mk_called);
    TEST_ASSERT_INT_EQ(0, mkp2.destroy_called);
    TEST_ASSERT_INT_EQ(0, mkp2.decrypt_called);

    struct aws_cryptosdk_mk *mk_result = NULL;
    TEST_ASSERT_INT_EQ(2, aws_array_list_length(&mk_list));

    TEST_ASSERT_SUCCESS(aws_array_list_get_at(&mk_list, &mk_result, 0));
    TEST_ASSERT_ADDR_EQ(mk1, mk_result);

    TEST_ASSERT_SUCCESS(aws_array_list_get_at(&mk_list, &mk_result, 1));
    TEST_ASSERT_ADDR_EQ(mk2, mk_result);

    test_cleanup();

    return 0;
}

static int test_get_errors() {
    test_init();

    struct aws_cryptosdk_mk *mk1 = aws_cryptosdk_zero_mk_new();
    struct aws_cryptosdk_mk *mk2 = aws_cryptosdk_counting_mk();
    TEST_ASSERT_SUCCESS(aws_array_list_push_back(&mkp1.mk_list, &mk1));
    TEST_ASSERT_SUCCESS(aws_array_list_push_back(&mkp2.mk_list, &mk2));

    mkp1.pending_error = 12345;

    TEST_ASSERT_SUCCESS(aws_cryptosdk_multi_mkp_add(multi_mkp, (struct aws_cryptosdk_mkp *)&mkp1));
    TEST_ASSERT_SUCCESS(aws_cryptosdk_multi_mkp_add(multi_mkp, (struct aws_cryptosdk_mkp *)&mkp2));
    TEST_ASSERT_ERROR(12345, aws_cryptosdk_mkp_get_master_keys(multi_mkp, &mk_list, &enc_context));
    TEST_ASSERT_INT_EQ(1, mkp1.get_mk_called);
    TEST_ASSERT_INT_EQ(0, mkp1.destroy_called);
    TEST_ASSERT_INT_EQ(0, mkp1.decrypt_called);
    TEST_ASSERT_INT_EQ(0, mkp2.get_mk_called);
    TEST_ASSERT_INT_EQ(0, mkp2.destroy_called);
    TEST_ASSERT_INT_EQ(0, mkp2.decrypt_called);

    test_cleanup();

    return 0;
}

static int test_decrypt_single() {
    test_init();

    struct aws_byte_buf the_key = aws_byte_buf_from_c_str("hunter2");

    TEST_ASSERT_SUCCESS(aws_byte_buf_cat(&mkp1.decrypted_key, 1, &the_key));
    TEST_ASSERT_SUCCESS(aws_cryptosdk_multi_mkp_add(multi_mkp, (struct aws_cryptosdk_mkp *)&mkp1));

    TEST_ASSERT_SUCCESS(aws_cryptosdk_mkp_decrypt_data_key(multi_mkp, &dec_mat, &dec_req));

    TEST_ASSERT_INT_EQ(the_key.len, dec_mat.unencrypted_data_key.len);
    TEST_ASSERT_INT_EQ(0, memcmp(the_key.buffer, dec_mat.unencrypted_data_key.buffer, the_key.len));

    test_cleanup();

    return 0;
}

static int test_decrypt_short_circuit() {
    test_init();
    struct aws_byte_buf the_key = aws_byte_buf_from_c_str("hunter2");

    TEST_ASSERT_SUCCESS(aws_byte_buf_cat(&mkp2.decrypted_key, 1, &the_key));
    TEST_ASSERT_SUCCESS(aws_cryptosdk_multi_mkp_add(multi_mkp, (struct aws_cryptosdk_mkp *)&mkp1));
    TEST_ASSERT_SUCCESS(aws_cryptosdk_multi_mkp_add(multi_mkp, (struct aws_cryptosdk_mkp *)&mkp2));
    TEST_ASSERT_SUCCESS(aws_cryptosdk_multi_mkp_add(multi_mkp, (struct aws_cryptosdk_mkp *)&mkp3));

    TEST_ASSERT_SUCCESS(aws_cryptosdk_mkp_decrypt_data_key(multi_mkp, &dec_mat, &dec_req));
    TEST_ASSERT_INT_EQ(1, mkp1.decrypt_called);
    TEST_ASSERT_INT_EQ(1, mkp2.decrypt_called);
    TEST_ASSERT_INT_EQ(0, mkp3.decrypt_called);

    TEST_ASSERT_INT_EQ(the_key.len, dec_mat.unencrypted_data_key.len);
    TEST_ASSERT_INT_EQ(0, memcmp(the_key.buffer, dec_mat.unencrypted_data_key.buffer, the_key.len));

    test_cleanup();

    return 0;
}

static int test_decrypt_skips_errors() {
    test_init();
    struct aws_byte_buf the_key = aws_byte_buf_from_c_str("hunter2");

    TEST_ASSERT_SUCCESS(aws_byte_buf_cat(&mkp3.decrypted_key, 1, &the_key));
    TEST_ASSERT_SUCCESS(aws_cryptosdk_multi_mkp_add(multi_mkp, (struct aws_cryptosdk_mkp *)&mkp1));
    TEST_ASSERT_SUCCESS(aws_cryptosdk_multi_mkp_add(multi_mkp, (struct aws_cryptosdk_mkp *)&mkp2));
    TEST_ASSERT_SUCCESS(aws_cryptosdk_multi_mkp_add(multi_mkp, (struct aws_cryptosdk_mkp *)&mkp3));

    mkp1.pending_error = 12345;

    TEST_ASSERT_SUCCESS(aws_cryptosdk_mkp_decrypt_data_key(multi_mkp, &dec_mat, &dec_req));
    TEST_ASSERT_INT_EQ(1, mkp1.decrypt_called);
    TEST_ASSERT_INT_EQ(1, mkp2.decrypt_called);
    TEST_ASSERT_INT_EQ(1, mkp3.decrypt_called);

    TEST_ASSERT_INT_EQ(the_key.len, dec_mat.unencrypted_data_key.len);
    TEST_ASSERT_INT_EQ(0, memcmp(the_key.buffer, dec_mat.unencrypted_data_key.buffer, the_key.len));

    test_cleanup();

    return 0;

}

struct test_case multi_mkp_test_cases[] = {
    { "multi_mkp", "test_empty_multi", test_empty_multi },
    { "multi_mkp", "test_get_single", test_get_single },
    { "multi_mkp", "test_get_multi", test_get_multi },
    { "multi_mkp", "test_get_errors", test_get_errors },
    { "multi_mkp", "test_decrypt_single", test_decrypt_single },
    { "multi_mkp", "test_decrypt_short_circuit", test_decrypt_short_circuit },
    { "multi_mkp", "test_decrypt_skips_errors", test_decrypt_skips_errors },
    { NULL }
};
