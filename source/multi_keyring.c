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

static int call_encrypt_dk_on_list(struct aws_cryptosdk_encryption_materials *enc_mat,
                                   const struct aws_array_list * keyrings,
                                   bool include_first) {
    size_t num_keyrings = aws_array_list_length(keyrings);
    size_t start_idx = include_first ? 0 : 1;
    int ret = AWS_OP_SUCCESS;

    // We allow some encrypt data key calls to fail. If they do, we report the error
    // but still return the encryption materials with data key/EDKs.
    for (size_t child_idx = start_idx; child_idx < num_keyrings; ++child_idx) {
        struct aws_cryptosdk_keyring *child_keyring;
        if (aws_array_list_get_at(keyrings, (void *)&child_keyring, child_idx)) return AWS_OP_ERR;
        if (aws_cryptosdk_keyring_encrypt_data_key(child_keyring, enc_mat)) ret = AWS_OP_ERR;
    }
    return ret;
}

static int multi_keyring_encrypt_data_key(struct aws_cryptosdk_keyring *multi,
                                     struct aws_cryptosdk_encryption_materials *enc_mat) {
    struct multi_keyring *self = (struct multi_keyring *)multi;
    return call_encrypt_dk_on_list(enc_mat, &self->children, true);
}

static int multi_keyring_generate_data_key(struct aws_cryptosdk_keyring *multi,
                                      struct aws_cryptosdk_encryption_materials *enc_mat) {
    struct multi_keyring *self = (struct multi_keyring *)multi;
    size_t num_keyrings = aws_array_list_length(&self->children);
    if (!num_keyrings) return AWS_OP_SUCCESS;

    struct aws_cryptosdk_keyring *child_keyring;
    if (aws_array_list_get_at(&self->children, (void *)&child_keyring, 0)) return AWS_OP_ERR;
    if (aws_cryptosdk_keyring_generate_data_key(child_keyring, enc_mat)) return AWS_OP_ERR;

    if (enc_mat->unencrypted_data_key.buffer) {
        return call_encrypt_dk_on_list(enc_mat, &self->children, false);
    }
    return AWS_OP_ERR;
}

static int multi_keyring_decrypt_data_key(struct aws_cryptosdk_keyring * multi,
                                     struct aws_cryptosdk_decryption_materials * dec_mat,
                                     const struct aws_cryptosdk_decryption_request * request) {
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
            /* If any of the child keyrings succeeds at decrypting the data key return success,
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
