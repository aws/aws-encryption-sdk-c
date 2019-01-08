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
#include <assert.h>
#include <aws/cryptosdk/list_utils.h>
#include <aws/cryptosdk/materials.h>
#include <aws/cryptosdk/multi_keyring.h>

struct multi_keyring {
    struct aws_cryptosdk_keyring base;
    struct aws_allocator *alloc;
    struct aws_cryptosdk_keyring *generator;
    struct aws_array_list children;  // list of (struct aws_cryptosdk_keyring *)
};

static int call_on_encrypt_on_list(
    const struct aws_array_list *keyrings,
    struct aws_allocator *request_alloc,
    struct aws_byte_buf *unencrypted_data_key,
    struct aws_array_list *keyring_trace,
    struct aws_array_list *edks,
    const struct aws_hash_table *enc_context,
    enum aws_cryptosdk_alg_id alg) {
    size_t num_keyrings = aws_array_list_length(keyrings);
    for (size_t list_idx = 0; list_idx < num_keyrings; ++list_idx) {
        struct aws_cryptosdk_keyring *child;
        if (aws_array_list_get_at(keyrings, (void *)&child, list_idx)) return AWS_OP_ERR;
        if (aws_cryptosdk_keyring_on_encrypt(
                child, request_alloc, unencrypted_data_key, keyring_trace, edks, enc_context, alg))
            return AWS_OP_ERR;
    }
    return AWS_OP_SUCCESS;
}

static int multi_keyring_on_encrypt(
    struct aws_cryptosdk_keyring *multi,
    struct aws_allocator *request_alloc,
    struct aws_byte_buf *unencrypted_data_key,
    struct aws_array_list *keyring_trace,
    struct aws_array_list *edks,
    const struct aws_hash_table *enc_context,
    enum aws_cryptosdk_alg_id alg) {
    struct multi_keyring *self = (struct multi_keyring *)multi;

    struct aws_array_list my_edks;
    if (aws_cryptosdk_edk_list_init(request_alloc, &my_edks)) return AWS_OP_ERR;
    struct aws_array_list my_trace;
    if (aws_cryptosdk_keyring_trace_init(request_alloc, &my_trace)) {
        aws_cryptosdk_edk_list_clean_up(&my_edks);
        return AWS_OP_ERR;
    }

    int ret = AWS_OP_SUCCESS;
    if (!unencrypted_data_key->buffer) {
        if (!self->generator) {
            ret = aws_raise_error(AWS_CRYPTOSDK_ERR_BAD_STATE);
            goto out;
        }
        if (aws_cryptosdk_keyring_on_encrypt(
                self->generator, request_alloc, unencrypted_data_key, &my_trace, &my_edks, enc_context, alg)) {
            ret = AWS_OP_ERR;
            goto out;
        }
        if (!unencrypted_data_key->buffer) {
            /* Keyrings are not required to generate a data key when it is not
             * provided, but generator keyrings are.
             */
            ret = aws_raise_error(AWS_CRYPTOSDK_ERR_BAD_STATE);
            goto out;
        }
    }

    if (call_on_encrypt_on_list(
            &self->children, request_alloc, unencrypted_data_key, &my_trace, &my_edks, enc_context, alg) ||
        aws_cryptosdk_transfer_list(edks, &my_edks)) {
        ret = AWS_OP_ERR;
        goto out;
    }
    aws_cryptosdk_transfer_list(keyring_trace, &my_trace);

out:
    aws_cryptosdk_edk_list_clean_up(&my_edks);
    aws_cryptosdk_keyring_trace_clean_up(&my_trace);
    return ret;
}

static int multi_keyring_on_decrypt(
    struct aws_cryptosdk_keyring *multi,
    struct aws_allocator *request_alloc,
    struct aws_byte_buf *unencrypted_data_key,
    struct aws_array_list *keyring_trace,
    const struct aws_array_list *edks,
    const struct aws_hash_table *enc_context,
    enum aws_cryptosdk_alg_id alg) {
    /* If one of the contained keyrings succeeds at decrypting the data key, return success,
     * but if we fail to decrypt the data key, only return success if there were no
     * errors reported from child keyrings.
     */
    int ret_if_no_decrypt = AWS_OP_SUCCESS;

    struct multi_keyring *self = (struct multi_keyring *)multi;

    if (self->generator) {
        int decrypt_err = aws_cryptosdk_keyring_on_decrypt(
            self->generator, request_alloc, unencrypted_data_key, keyring_trace, edks, enc_context, alg);
        if (unencrypted_data_key->buffer) return AWS_OP_SUCCESS;
        if (decrypt_err) ret_if_no_decrypt = AWS_OP_ERR;
    }

    size_t num_children = aws_array_list_length(&self->children);
    for (size_t child_idx = 0; child_idx < num_children; ++child_idx) {
        struct aws_cryptosdk_keyring *child;
        if (aws_array_list_get_at(&self->children, (void *)&child, child_idx)) return AWS_OP_ERR;

        // if decrypt data key fails, keep trying with other keyrings
        int decrypt_err = aws_cryptosdk_keyring_on_decrypt(
            child, request_alloc, unencrypted_data_key, keyring_trace, edks, enc_context, alg);
        if (unencrypted_data_key->buffer) return AWS_OP_SUCCESS;
        if (decrypt_err) ret_if_no_decrypt = AWS_OP_ERR;
    }
    return ret_if_no_decrypt;
}

static void multi_keyring_destroy(struct aws_cryptosdk_keyring *multi) {
    struct multi_keyring *self = (struct multi_keyring *)multi;
    size_t n_keys              = aws_array_list_length(&self->children);

    for (size_t i = 0; i < n_keys; i++) {
        struct aws_cryptosdk_keyring *child;
        if (!aws_array_list_get_at(&self->children, (void *)&child, i)) {
            aws_cryptosdk_keyring_release(child);
        }
    }

    aws_cryptosdk_keyring_release(self->generator);

    aws_array_list_clean_up(&self->children);
    aws_mem_release(self->alloc, self);
}

static const struct aws_cryptosdk_keyring_vt vt = { .vt_size    = sizeof(struct aws_cryptosdk_keyring_vt),
                                                    .name       = "multi keyring",
                                                    .destroy    = multi_keyring_destroy,
                                                    .on_encrypt = multi_keyring_on_encrypt,
                                                    .on_decrypt = multi_keyring_on_decrypt };

struct aws_cryptosdk_keyring *aws_cryptosdk_multi_keyring_new(
    struct aws_allocator *alloc, struct aws_cryptosdk_keyring *generator) {
    struct multi_keyring *multi = aws_mem_acquire(alloc, sizeof(struct multi_keyring));
    if (!multi) return NULL;
    if (aws_array_list_init_dynamic(&multi->children, alloc, 4, sizeof(struct aws_cryptosdk_keyring *))) {
        aws_mem_release(alloc, multi);
        return NULL;
    }

    aws_cryptosdk_keyring_base_init(&multi->base, &vt);

    if (generator) aws_cryptosdk_keyring_retain(generator);
    multi->generator = generator;
    multi->alloc     = alloc;
    return (struct aws_cryptosdk_keyring *)multi;
}

int aws_cryptosdk_multi_keyring_set_generator(
    struct aws_cryptosdk_keyring *multi, struct aws_cryptosdk_keyring *generator) {
    struct multi_keyring *self = (struct multi_keyring *)multi;

    if (self->generator) return aws_raise_error(AWS_ERROR_UNSUPPORTED_OPERATION);
    self->generator = aws_cryptosdk_keyring_retain(generator);

    return AWS_OP_SUCCESS;
}

int aws_cryptosdk_multi_keyring_add_child(struct aws_cryptosdk_keyring *multi, struct aws_cryptosdk_keyring *child) {
    struct multi_keyring *self = (struct multi_keyring *)multi;

    aws_cryptosdk_keyring_retain(child);

    return aws_array_list_push_back(&self->children, (void *)&child);
}
