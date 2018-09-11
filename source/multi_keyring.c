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
#include <aws/cryptosdk/multi_keyring.h>
#include <aws/cryptosdk/private/materials.h>
#include <assert.h>

struct multi_keyring {
    const struct aws_cryptosdk_keyring_vt *vt;
    struct aws_allocator *alloc;
    struct aws_cryptosdk_keyring *generator;
    struct aws_array_list children; // list of (struct aws_cryptosdk_keyring *)
};

static int call_encrypt_dk_on_list(const struct aws_array_list *keyrings,
                                   struct aws_byte_buf * unencrypted_data_key,
                                   struct aws_array_list * edks,
                                   const struct aws_hash_table * enc_context,
                                   enum aws_cryptosdk_alg_id alg) {
    size_t num_keyrings = aws_array_list_length(keyrings);
    for (size_t list_idx = 0; list_idx < num_keyrings; ++list_idx) {
        struct aws_cryptosdk_keyring *child;
        if (aws_array_list_get_at(keyrings, (void *)&child, list_idx)) return AWS_OP_ERR;
        if (aws_cryptosdk_keyring_generate_or_encrypt_data_key(child,
                                                               unencrypted_data_key,
                                                               edks,
                                                               enc_context,
                                                               alg)) return AWS_OP_ERR;
    }
    return AWS_OP_SUCCESS;
}

static int transfer_edk_list(struct aws_array_list *dest, struct aws_array_list *src) {
    size_t src_len = aws_array_list_length(src);
    for (size_t src_idx = 0; src_idx < src_len; ++src_idx) {
        void *item_ptr;
        if (aws_array_list_get_at_ptr(src, &item_ptr, src_idx)) return AWS_OP_ERR;
        if (aws_array_list_push_back(dest, item_ptr)) return AWS_OP_ERR;
    }
    /* This clear is important. It does not free any memory, but it resets the length of the
     * source list to zero, so that the EDK buffers in its list will NOT get freed when the
     * EDK list gets destroyed. We do not want to free those buffers, because we made a shallow
     * copy of the EDK list to the destination array list, so it still uses all the same buffers.
     */
    aws_array_list_clear(src);
    return AWS_OP_SUCCESS;
}

static int multi_keyring_generate_or_encrypt_data_key(struct aws_cryptosdk_keyring *multi,
                                                      struct aws_byte_buf *unencrypted_data_key,
                                                      struct aws_array_list *edks,
                                                      const struct aws_hash_table *enc_context,
                                                      enum aws_cryptosdk_alg_id alg) {
    struct multi_keyring *self = (struct multi_keyring *)multi;

    struct aws_array_list my_edks;
    if (aws_array_list_init_dynamic(&my_edks,
                                    self->alloc,
                                    aws_array_list_length(&self->children) + 1,
                                    sizeof(struct aws_cryptosdk_edk))) return AWS_OP_ERR;

    int ret = AWS_OP_SUCCESS;
    if (!unencrypted_data_key->buffer) {
        if (!self->generator) {
            ret = aws_raise_error(AWS_CRYPTOSDK_ERR_BAD_STATE);
            goto out;
        }
        if (aws_cryptosdk_keyring_generate_or_encrypt_data_key(self->generator,
                                                               unencrypted_data_key,
                                                               &my_edks,
                                                               enc_context,
                                                               alg)) {
            ret = AWS_OP_ERR;
            goto out;
        }
    }
    assert(unencrypted_data_key->buffer);

    if (call_encrypt_dk_on_list(&self->children,
                                unencrypted_data_key,
                                &my_edks,
                                enc_context,
                                alg) ||
        transfer_edk_list(edks, &my_edks)) {
        ret = AWS_OP_ERR;
    }

out:
    aws_cryptosdk_edk_list_clean_up(&my_edks);
    return ret;
}

static int multi_keyring_decrypt_data_key(struct aws_cryptosdk_keyring *multi,
                                          struct aws_byte_buf * unencrypted_data_key,
                                          const struct aws_array_list * edks,
                                          const struct aws_hash_table * enc_context,
                                          enum aws_cryptosdk_alg_id alg) {

    /* If one of the contained keyrings succeeds at decrypting the data key, return success,
     * but if we fail to decrypt the data key, only return success if there were no
     * errors reported from child keyrings.
     */
    int ret_if_no_decrypt = AWS_OP_SUCCESS;

    struct multi_keyring *self = (struct multi_keyring *)multi;

    if (self->generator) {
        int decrypt_err = aws_cryptosdk_keyring_decrypt_data_key(self->generator,
                                                                 unencrypted_data_key,
                                                                 edks,
                                                                 enc_context,
                                                                 alg);
        if (unencrypted_data_key->buffer) return AWS_OP_SUCCESS;
        if (decrypt_err) ret_if_no_decrypt = AWS_OP_ERR;
    }

    size_t num_children = aws_array_list_length(&self->children);
    for (size_t child_idx = 0; child_idx < num_children; ++child_idx) {
        struct aws_cryptosdk_keyring *child;
        if (aws_array_list_get_at(&self->children, (void *)&child, child_idx)) return AWS_OP_ERR;

        // if decrypt data key fails, keep trying with other keyrings
        int decrypt_err = aws_cryptosdk_keyring_decrypt_data_key(child,
                                                                 unencrypted_data_key,
                                                                 edks,
                                                                 enc_context,
                                                                 alg);
        if (unencrypted_data_key->buffer) return AWS_OP_SUCCESS;
        if (decrypt_err) ret_if_no_decrypt = AWS_OP_ERR;
    }
    return ret_if_no_decrypt;
}

static void multi_keyring_destroy(struct aws_cryptosdk_keyring *multi) {
    struct multi_keyring *self = (struct multi_keyring *)multi;
    aws_array_list_clean_up(&self->children);
    aws_mem_release(self->alloc, self);
}

static const struct aws_cryptosdk_keyring_vt vt = {
    .vt_size = sizeof(struct aws_cryptosdk_keyring_vt),
    .name = "multi keyring",
    .destroy = multi_keyring_destroy,
    .generate_or_encrypt_data_key = multi_keyring_generate_or_encrypt_data_key,
    .decrypt_data_key = multi_keyring_decrypt_data_key
};

struct aws_cryptosdk_keyring *aws_cryptosdk_multi_keyring_new(
    struct aws_allocator * alloc,
    struct aws_cryptosdk_keyring *generator) {

    struct multi_keyring * multi = aws_mem_acquire(alloc, sizeof(struct multi_keyring));
    if (!multi) return NULL;
    if (aws_array_list_init_dynamic(&multi->children, alloc, 4,
                                    sizeof(struct aws_cryptosdk_keyring *))) {
        aws_mem_release(alloc, multi);
        return NULL;
    }
    multi->alloc = alloc;
    multi->vt = &vt;
    multi->generator = generator;
    return (struct aws_cryptosdk_keyring *)multi;
}

int aws_cryptosdk_multi_keyring_set_generator(struct aws_cryptosdk_keyring *multi,
                                              struct aws_cryptosdk_keyring *generator) {
    struct multi_keyring *self = (struct multi_keyring *)multi;

    if (self->generator) return aws_raise_error(AWS_ERROR_UNIMPLEMENTED);
    self->generator = generator;
    return AWS_OP_SUCCESS;
}

int aws_cryptosdk_multi_keyring_add(struct aws_cryptosdk_keyring *multi,
                                    struct aws_cryptosdk_keyring *child) {
    struct multi_keyring *self = (struct multi_keyring *)multi;
    return aws_array_list_push_back(&self->children, (void *)&child);
}
