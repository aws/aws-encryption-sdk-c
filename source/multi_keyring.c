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

struct multi_keyring {
    const struct aws_cryptosdk_keyring_vt *vt;
    struct aws_allocator *alloc;
    struct aws_array_list children;
};

/* There may already be EDKs in the encryption materials object if, for example,
 * this multi-keyring was a child keyring of a different multi-keyring. In order
 * not to tamper with the existing EDK list in the encryption materials object,
 * this keyring creates a temporary copy of the encryption materials object
 * with an empty EDK list. This allows it to destroy its entire list in
 * case of any errors by child keyrings.
 */
static struct aws_cryptosdk_encryption_materials *copy_relevant_parts_of_enc_mat(
    struct aws_cryptosdk_encryption_materials *enc_mat) {
    struct aws_cryptosdk_encryption_materials *enc_mat_copy =
        aws_cryptosdk_encryption_materials_new(enc_mat->alloc, enc_mat->alg);
    if (!enc_mat_copy) return NULL;

    enc_mat_copy->enc_context = enc_mat->enc_context;

    if (aws_byte_buf_init_copy(enc_mat->alloc,
                               &enc_mat_copy->unencrypted_data_key,
                               &enc_mat->unencrypted_data_key)) {
        aws_cryptosdk_encryption_materials_destroy(enc_mat_copy);
        return NULL;
    }
    return enc_mat_copy;
}

static int call_encrypt_dk_on_list(struct aws_cryptosdk_encryption_materials *enc_mat,
                                   const struct aws_array_list *keyrings,
                                   bool include_first) {
    size_t num_keyrings = aws_array_list_length(keyrings);
    size_t start_idx = include_first ? 0 : 1;

    for (size_t child_idx = start_idx; child_idx < num_keyrings; ++child_idx) {
        struct aws_cryptosdk_keyring *child_keyring;
        if (aws_array_list_get_at(keyrings, (void *)&child_keyring, child_idx)) return AWS_OP_ERR;
        if (aws_cryptosdk_keyring_encrypt_data_key(child_keyring, enc_mat)) return AWS_OP_ERR;
    }
    return AWS_OP_SUCCESS;
}

static int transfer_list(struct aws_array_list *dest, struct aws_array_list *src) {
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

static int multi_keyring_encrypt_data_key(struct aws_cryptosdk_keyring *multi,
                                          struct aws_cryptosdk_encryption_materials *enc_mat) {
    struct multi_keyring *self = (struct multi_keyring *)multi;

    struct aws_cryptosdk_encryption_materials *enc_mat_copy =
        copy_relevant_parts_of_enc_mat(enc_mat);
    if (!enc_mat_copy) return AWS_OP_ERR;

    int ret = AWS_OP_SUCCESS;
    if (call_encrypt_dk_on_list(enc_mat_copy, &self->children, true) ||
        transfer_list(&enc_mat->encrypted_data_keys, &enc_mat_copy->encrypted_data_keys)) {
        ret = AWS_OP_ERR;
    }

    aws_cryptosdk_encryption_materials_destroy(enc_mat_copy);
    return ret;
}

static int multi_keyring_generate_data_key(struct aws_cryptosdk_keyring *multi,
                                           struct aws_cryptosdk_encryption_materials *enc_mat) {
    struct multi_keyring *self = (struct multi_keyring *)multi;
    size_t num_keyrings = aws_array_list_length(&self->children);
    if (!num_keyrings) return AWS_OP_SUCCESS;

    struct aws_cryptosdk_encryption_materials *enc_mat_copy =
        copy_relevant_parts_of_enc_mat(enc_mat);
    if (!enc_mat_copy) return AWS_OP_ERR;

    int ret = AWS_OP_SUCCESS;
    struct aws_cryptosdk_keyring *child_keyring;
    if (aws_array_list_get_at(&self->children, (void *)&child_keyring, 0) ||
        aws_cryptosdk_keyring_generate_data_key(child_keyring, enc_mat_copy) ||
        !enc_mat_copy->unencrypted_data_key.buffer ||
        call_encrypt_dk_on_list(enc_mat_copy, &self->children, false) ||
        aws_byte_buf_init_copy(enc_mat->alloc,
                               &enc_mat->unencrypted_data_key,
                               &enc_mat_copy->unencrypted_data_key) ||
        transfer_list(&enc_mat->encrypted_data_keys, &enc_mat_copy->encrypted_data_keys)) {
        aws_byte_buf_clean_up_secure(&enc_mat->unencrypted_data_key);
        ret = AWS_OP_ERR;
    }

    aws_cryptosdk_encryption_materials_destroy(enc_mat_copy);
    return ret;
}

static int multi_keyring_decrypt_data_key(struct aws_cryptosdk_keyring *multi,
                                          struct aws_cryptosdk_decryption_materials *dec_mat,
                                          const struct aws_cryptosdk_decryption_request *request) {
    int ret_if_no_decrypt = AWS_OP_SUCCESS;

    struct multi_keyring *self = (struct multi_keyring *)multi;
    size_t num_keyrings = aws_array_list_length(&self->children);

    for (size_t child_idx = 0; child_idx < num_keyrings; ++child_idx) {
        struct aws_cryptosdk_keyring *child_keyring;
        if (aws_array_list_get_at(&self->children, (void *)&child_keyring, child_idx)) return AWS_OP_ERR;

        // if decrypt data key fails, keep trying with other keyrings
        int result = aws_cryptosdk_keyring_decrypt_data_key(child_keyring, dec_mat, request);
        if (result == AWS_OP_SUCCESS && dec_mat->unencrypted_data_key.buffer) {
            return AWS_OP_SUCCESS;
        }
        if (result) {
            /* If one of the child keyrings succeeds at decrypting the data key, return success,
             * but if we fail to decrypt the data key, only return success if there were no
             * errors reported from child keyrings.
             */
            ret_if_no_decrypt = AWS_OP_ERR;
        }
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
    .name = "multi kr",
    .destroy = multi_keyring_destroy,
    .generate_data_key = multi_keyring_generate_data_key,
    .encrypt_data_key = multi_keyring_encrypt_data_key,
    .decrypt_data_key = multi_keyring_decrypt_data_key
};

struct aws_cryptosdk_keyring *aws_cryptosdk_multi_keyring_new(struct aws_allocator * alloc) {
    struct multi_keyring * multi = aws_mem_acquire(alloc, sizeof(struct multi_keyring));
    if (!multi) return NULL;
    if (aws_array_list_init_dynamic(&multi->children, alloc, 4, sizeof(struct aws_cryptosdk_keyring *))) {
        aws_mem_release(alloc, multi);
        return NULL;
    }
    multi->alloc = alloc;
    multi->vt = &vt;
    return (struct aws_cryptosdk_keyring *)multi;
}

int aws_cryptosdk_multi_keyring_add(struct aws_cryptosdk_keyring * multi,
                                    struct aws_cryptosdk_keyring * kr_to_add) {
    struct multi_keyring *self = (struct multi_keyring *)multi;
    return aws_array_list_push_back(&self->children, (void *)&kr_to_add);
}
