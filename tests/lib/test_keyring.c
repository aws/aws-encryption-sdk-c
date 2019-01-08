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

#include "test_keyring.h"
#include "../unit/testing.h"

static void test_keyring_destroy(struct aws_cryptosdk_keyring *kr) {
    struct test_keyring *self = (struct test_keyring *)kr;
    self->destroy_called      = true;
}

AWS_STATIC_STRING_FROM_LITERAL(name_space, "test keyring");
AWS_STATIC_STRING_FROM_LITERAL(name, "test key");

static int test_keyring_on_encrypt(
    struct aws_cryptosdk_keyring *kr,
    struct aws_allocator *request_alloc,
    struct aws_byte_buf *unencrypted_data_key,
    struct aws_array_list *keyring_trace,
    struct aws_array_list *edks,
    const struct aws_hash_table *enc_ctx,
    enum aws_cryptosdk_alg_id alg) {
    (void)enc_ctx;
    struct test_keyring *self = (struct test_keyring *)kr;

    if (!self->ret && !self->skip_output) {
        uint32_t flags = AWS_CRYPTOSDK_WRAPPING_KEY_ENCRYPTED_DATA_KEY;
        if (!unencrypted_data_key->buffer) {
            *unencrypted_data_key = self->generated_data_key_to_return;
            flags |= AWS_CRYPTOSDK_WRAPPING_KEY_GENERATED_DATA_KEY;
        }

        static struct aws_cryptosdk_edk edk;
        edk.ciphertext    = aws_byte_buf_from_c_str("test keyring generate edk");
        edk.provider_id   = aws_byte_buf_from_c_str("test keyring generate provider id");
        edk.provider_info = aws_byte_buf_from_c_str("test keyring generate provider info");
        aws_array_list_push_back(edks, &edk);

        // This should only fail on memory allocation errors.
        // In production code we ignore errors from this, as there isn't really
        // a sensible way to handle them. But here we check for failure just to
        // make sure this code has actually run properly.
        TEST_ASSERT_SUCCESS(
            aws_cryptosdk_keyring_trace_add_record(request_alloc, keyring_trace, name_space, name, flags));
    }

    self->on_encrypt_called = true;
    return self->ret;
}

static int test_keyring_on_decrypt(
    struct aws_cryptosdk_keyring *kr,
    struct aws_allocator *request_alloc,
    struct aws_byte_buf *unencrypted_data_key,
    struct aws_array_list *keyring_trace,
    const struct aws_array_list *edks,
    const struct aws_hash_table *enc_ctx,
    enum aws_cryptosdk_alg_id alg) {
    (void)edks;
    (void)enc_ctx;
    (void)alg;
    struct test_keyring *self = (struct test_keyring *)kr;
    if (!self->ret && !self->skip_output) {
        *unencrypted_data_key = self->decrypted_data_key_to_return;
        if (self->decrypted_data_key_to_return.buffer) {
            if (aws_cryptosdk_keyring_trace_add_record(
                    request_alloc, keyring_trace, name_space, name, AWS_CRYPTOSDK_WRAPPING_KEY_DECRYPTED_DATA_KEY)) {
                abort();
            }
        }
    }
    self->on_decrypt_called = true;
    return self->ret;
}

const struct aws_cryptosdk_keyring_vt test_keyring_vt = { .vt_size    = sizeof(test_keyring_vt),
                                                          .name       = "test keyring",
                                                          .destroy    = test_keyring_destroy,
                                                          .on_encrypt = test_keyring_on_encrypt,
                                                          .on_decrypt = test_keyring_on_decrypt };
