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
#include <aws/cryptosdk/multi_kr.h>

struct multi_kr {
    const struct aws_cryptosdk_kr_vt *vt;
    struct aws_allocator *alloc;
    struct aws_array_list krs;
};

static int call_encrypt_dk_on_list(struct aws_cryptosdk_encryption_materials *enc_mat,
                                   const struct aws_array_list * keyrings,
                                   bool include_first) {
    size_t num_krs = aws_array_list_length(keyrings);
    size_t start_idx = include_first ? 0 : 1;
    int ret = AWS_OP_SUCCESS;

    // We allow some encrypt data key calls to fail. If they do, we report the error
    // but still return the encryption materials with data key/EDKs.
    for (size_t child_idx = start_idx; child_idx < num_krs; ++child_idx) {
        struct aws_cryptosdk_kr *child_kr;
        if (aws_array_list_get_at(keyrings, (void *)&child_kr, child_idx)) return AWS_OP_ERR;
        if (aws_cryptosdk_kr_encrypt_data_key(child_kr, enc_mat)) ret = AWS_OP_ERR;
    }
    return ret;
}

static int multi_kr_encrypt_data_key(struct aws_cryptosdk_kr *multi,
                                     struct aws_cryptosdk_encryption_materials *enc_mat) {
    struct multi_kr *self = (struct multi_kr *)multi;
    return call_encrypt_dk_on_list(enc_mat, &self->krs, true);
}

static int multi_kr_generate_data_key(struct aws_cryptosdk_kr *multi,
                                      struct aws_cryptosdk_encryption_materials *enc_mat) {
    struct multi_kr *self = (struct multi_kr *)multi;
    size_t num_krs = aws_array_list_length(&self->krs);
    if (!num_krs) return AWS_OP_SUCCESS;

    struct aws_cryptosdk_kr *child_kr;
    if (aws_array_list_get_at(&self->krs, (void *)&child_kr, 0)) return AWS_OP_ERR;
    if (aws_cryptosdk_kr_generate_data_key(child_kr, enc_mat)) return AWS_OP_ERR;

    if (enc_mat->unencrypted_data_key.buffer) {
        return call_encrypt_dk_on_list(enc_mat, &self->krs, false);
    }
    return AWS_OP_ERR;
}

static int multi_kr_decrypt_data_key(struct aws_cryptosdk_kr * multi,
                                     struct aws_cryptosdk_decryption_materials * dec_mat,
                                     const struct aws_cryptosdk_decryption_request * request) {
    int ret_if_no_decrypt = AWS_OP_SUCCESS;

    struct multi_kr *self = (struct multi_kr *)multi;
    size_t num_krs = aws_array_list_length(&self->krs);

    for (size_t child_idx = 0; child_idx < num_krs; ++child_idx) {
        struct aws_cryptosdk_kr *child_kr;
        if (aws_array_list_get_at(&self->krs, (void *)&child_kr, child_idx)) return AWS_OP_ERR;

        // if decrypt data key fails, keep trying with other keyrings
        int result = aws_cryptosdk_kr_decrypt_data_key(child_kr, dec_mat, request);
        if (result == AWS_OP_SUCCESS && dec_mat->unencrypted_data_key.buffer) {
            return AWS_OP_SUCCESS;
        }
        if (result) {
            /* If any of the child KRs succeeds at decrypting the data key return success,
             * but if we fail to decrypt the data key, only return success if there were no
             * errors reported from child KRs.
             */
            ret_if_no_decrypt = AWS_OP_ERR;
        }
    }
    return ret_if_no_decrypt;
}

static void multi_kr_destroy(struct aws_cryptosdk_kr *multi) {
    struct multi_kr *self = (struct multi_kr *)multi;
    aws_array_list_clean_up(&self->krs);
    aws_mem_release(self->alloc, self);
}

static const struct aws_cryptosdk_kr_vt vt = {
    .vt_size = sizeof(struct aws_cryptosdk_kr_vt),
    .name = "multi kr",
    .destroy = multi_kr_destroy,
    .generate_data_key = multi_kr_generate_data_key,
    .encrypt_data_key = multi_kr_encrypt_data_key,
    .decrypt_data_key = multi_kr_decrypt_data_key
};

struct aws_cryptosdk_kr *aws_cryptosdk_multi_kr_new(struct aws_allocator * alloc) {
    struct multi_kr * multi = aws_mem_acquire(alloc, sizeof(struct multi_kr));
    if (!multi) return NULL;
    if (aws_array_list_init_dynamic(&multi->krs, alloc, 4, sizeof(struct aws_cryptosdk_kr *))) {
        aws_mem_release(alloc, multi);
        return NULL;
    }
    multi->alloc = alloc;
    multi->vt = &vt;
    return (struct aws_cryptosdk_kr *)multi;
}

int aws_cryptosdk_multi_kr_add(struct aws_cryptosdk_kr * multi,
                               struct aws_cryptosdk_kr * kr_to_add) {
    struct multi_kr *self = (struct multi_kr *)multi;
    return aws_array_list_push_back(&self->krs, (void *)&kr_to_add);
}
