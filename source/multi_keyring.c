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

struct multi_keyring {
    struct aws_cryptosdk_keyring base;
    struct aws_allocator *alloc;
    struct aws_cryptosdk_keyring *generator;
    struct aws_array_list children; // list of (struct aws_cryptosdk_keyring *)
};

/* There may already be EDKs in the encryption materials object if, for example,
 * this multi-keyring was a child keyring of a different multi-keyring. In order
 * not to tamper with the existing EDK list in the encryption materials object,
 * this keyring creates a temporary copy of the encryption materials object
 * with an empty EDK list. This allows it to destroy its entire list in
 * case of any errors by child keyrings.
 */
static struct aws_cryptosdk_encryption_materials *copy_relevant_parts_of_enc_mat_init(
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
                                   const struct aws_array_list *keyrings) {
    size_t num_keyrings = aws_array_list_length(keyrings);
    for (size_t list_idx = 0; list_idx < num_keyrings; ++list_idx) {
        struct aws_cryptosdk_keyring *child;
        if (aws_array_list_get_at(keyrings, (void *)&child, list_idx)) return AWS_OP_ERR;
        if (aws_cryptosdk_keyring_encrypt_data_key(child, enc_mat)) return AWS_OP_ERR;
    }
    return AWS_OP_SUCCESS;
}

static int multi_keyring_encrypt_data_key(struct aws_cryptosdk_keyring *multi,
                                          struct aws_cryptosdk_encryption_materials *enc_mat) {
    struct multi_keyring *self = (struct multi_keyring *)multi;

    // FIXME: this check should be moved to materials.h before virtual function call
    // if we keep separate generate and encrypt calls
    if (!enc_mat->unencrypted_data_key.buffer) return aws_raise_error(AWS_CRYPTOSDK_ERR_BAD_STATE);

    struct aws_cryptosdk_encryption_materials *enc_mat_copy =
        copy_relevant_parts_of_enc_mat_init(enc_mat);
    if (!enc_mat_copy) return AWS_OP_ERR;

    int ret = AWS_OP_SUCCESS;
    if (self->generator) {
        if (aws_cryptosdk_keyring_encrypt_data_key(self->generator, enc_mat_copy)) {
            ret = AWS_OP_ERR;
            goto out;
        }
    }

    if (call_encrypt_dk_on_list(enc_mat_copy, &self->children) ||
        aws_cryptosdk_transfer_edk_list(&enc_mat->encrypted_data_keys, &enc_mat_copy->encrypted_data_keys)) {
        ret = AWS_OP_ERR;
    }

out:
    aws_cryptosdk_encryption_materials_destroy(enc_mat_copy);
    return ret;
}

static int multi_keyring_generate_data_key(struct aws_cryptosdk_keyring *multi,
                                           struct aws_cryptosdk_encryption_materials *enc_mat) {
    struct multi_keyring *self = (struct multi_keyring *)multi;

    // FIXME: this check should be moved to materials.h before virtual function call
    // if we keep separate generate and encrypt calls
    if (enc_mat->unencrypted_data_key.buffer || aws_array_list_length(&enc_mat->encrypted_data_keys))
        return aws_raise_error(AWS_CRYPTOSDK_ERR_BAD_STATE);

    if (!self->generator) return aws_raise_error(AWS_CRYPTOSDK_ERR_BAD_STATE);

    struct aws_cryptosdk_encryption_materials *enc_mat_copy =
        copy_relevant_parts_of_enc_mat_init(enc_mat);
    if (!enc_mat_copy) return AWS_OP_ERR;

    int ret = AWS_OP_SUCCESS;
    if (aws_cryptosdk_keyring_generate_data_key(self->generator, enc_mat_copy) ||
        !enc_mat_copy->unencrypted_data_key.buffer ||
        call_encrypt_dk_on_list(enc_mat_copy, &self->children) ||
        aws_byte_buf_init_copy(enc_mat->alloc,
                               &enc_mat->unencrypted_data_key,
                               &enc_mat_copy->unencrypted_data_key) ||
        aws_cryptosdk_transfer_edk_list(&enc_mat->encrypted_data_keys, &enc_mat_copy->encrypted_data_keys)) {
        aws_byte_buf_clean_up_secure(&enc_mat->unencrypted_data_key);
        ret = AWS_OP_ERR;
    }

    aws_cryptosdk_encryption_materials_destroy(enc_mat_copy);
    return ret;
}

static int multi_keyring_decrypt_data_key(struct aws_cryptosdk_keyring *multi,
                                          struct aws_cryptosdk_decryption_materials *dec_mat,
                                          const struct aws_cryptosdk_decryption_request *request) {
    // FIXME: this check should be moved to materials.h before virtual function call
    if (dec_mat->unencrypted_data_key.buffer) return aws_raise_error(AWS_CRYPTOSDK_ERR_BAD_STATE);

    /* If one of the contained keyrings succeeds at decrypting the data key, return success,
     * but if we fail to decrypt the data key, only return success if there were no
     * errors reported from child keyrings.
     */
    int ret_if_no_decrypt = AWS_OP_SUCCESS;

    struct multi_keyring *self = (struct multi_keyring *)multi;

    if (self->generator) {
        int decrypt_err = aws_cryptosdk_keyring_decrypt_data_key(self->generator, dec_mat, request);
        if (dec_mat->unencrypted_data_key.buffer) return AWS_OP_SUCCESS;
        if (decrypt_err) ret_if_no_decrypt = AWS_OP_ERR;
    }

    size_t num_children = aws_array_list_length(&self->children);
    for (size_t child_idx = 0; child_idx < num_children; ++child_idx) {
        struct aws_cryptosdk_keyring *child;
        if (aws_array_list_get_at(&self->children, (void *)&child, child_idx)) return AWS_OP_ERR;

        // if decrypt data key fails, keep trying with other keyrings
        int decrypt_err = aws_cryptosdk_keyring_decrypt_data_key(child, dec_mat, request);
        if (dec_mat->unencrypted_data_key.buffer) return AWS_OP_SUCCESS;
        if (decrypt_err) ret_if_no_decrypt = AWS_OP_ERR;
    }
    return ret_if_no_decrypt;
}

static void multi_keyring_destroy(struct aws_cryptosdk_keyring *multi) {
    struct multi_keyring *self = (struct multi_keyring *)multi;
    size_t n_keys = aws_array_list_length(&self->children);

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

static const struct aws_cryptosdk_keyring_vt vt = {
    .vt_size = sizeof(struct aws_cryptosdk_keyring_vt),
    .name = "multi keyring",
    .destroy = multi_keyring_destroy,
    .generate_data_key = multi_keyring_generate_data_key,
    .encrypt_data_key = multi_keyring_encrypt_data_key,
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

    aws_cryptosdk_keyring_base_init(&multi->base, &vt);

    multi->alloc = alloc;
    multi->generator = generator;
    return (struct aws_cryptosdk_keyring *)multi;
}

int aws_cryptosdk_multi_keyring_set_generator(struct aws_cryptosdk_keyring *multi,
                                              struct aws_cryptosdk_keyring *generator) {
    struct multi_keyring *self = (struct multi_keyring *)multi;

    if (self->generator) return aws_raise_error(AWS_CRYPTOSDK_ERR_BAD_STATE);
    self->generator = aws_cryptosdk_keyring_retain(generator);

    return AWS_OP_SUCCESS;
}

int aws_cryptosdk_multi_keyring_add(struct aws_cryptosdk_keyring *multi,
                                    struct aws_cryptosdk_keyring *child) {
    struct multi_keyring *self = (struct multi_keyring *)multi;

    aws_cryptosdk_keyring_retain(child);

    return aws_array_list_push_back(&self->children, (void *)&child);
}
