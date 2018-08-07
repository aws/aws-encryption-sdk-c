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
#include <assert.h>

static void destroy_multi(struct aws_cryptosdk_mkp *mkp);
static int get_master_keys_multi(struct aws_cryptosdk_mkp *mkp,
                                 struct aws_array_list *master_keys, // list of (aws_cryptosdk_mk *)
                                 const struct aws_hash_table *enc_context);
static int decrypt_data_key_multi(struct aws_cryptosdk_mkp *mkp,
                                  struct aws_cryptosdk_decryption_materials *dec_mat,
                                  const struct aws_cryptosdk_decryption_request *request);

struct aws_cryptosdk_multi_mkp {
    const struct aws_cryptosdk_mkp_vt *vt;
    struct aws_allocator *alloc;
    struct aws_array_list list;
};

static const struct aws_cryptosdk_mkp_vt vtable = {
    .vt_size = sizeof(vtable),
    .name = "Multi master key provider",
    .destroy = destroy_multi,
    .get_master_keys = get_master_keys_multi,
    .decrypt_data_key = decrypt_data_key_multi
};

struct aws_cryptosdk_mkp *aws_cryptosdk_multi_mkp_new(struct aws_allocator *alloc) {
    struct aws_cryptosdk_multi_mkp *mkp = aws_mem_acquire(alloc, sizeof(*mkp));
    if (!mkp) return NULL;

    if (aws_array_list_init_dynamic(&mkp->list, alloc, 4, sizeof(struct aws_cryptosdk_mkp *))) {
        aws_mem_release(alloc, mkp);
        return NULL;
    }

    mkp->vt = &vtable;
    mkp->alloc = alloc;

    return (struct aws_cryptosdk_mkp *)mkp;
}

int aws_cryptosdk_multi_mkp_add(
    struct aws_cryptosdk_mkp *multi_mkp,
    struct aws_cryptosdk_mkp *mkp
) {
    struct aws_cryptosdk_multi_mkp *self = (struct aws_cryptosdk_multi_mkp *)multi_mkp;

    if (self->vt != &vtable) return aws_raise_error(AWS_CRYPTOSDK_ERR_TYPE_MISMATCH);

    // TODO - need an illegal argument / null argument error
    if (!mkp) return aws_raise_error(AWS_ERROR_UNKNOWN);

    return aws_array_list_push_back(&self->list, &mkp);
}

static void destroy_multi(struct aws_cryptosdk_mkp *mkp) {
    struct aws_cryptosdk_multi_mkp *self = (struct aws_cryptosdk_multi_mkp *)mkp;
    assert(self->vt == &vtable);

    aws_array_list_clean_up(&self->list);
    aws_mem_release(self->alloc, self);
}

static int get_master_keys_multi(struct aws_cryptosdk_mkp *mkp,
                                 struct aws_array_list *master_keys, // list of (aws_cryptosdk_mk *)
                                 const struct aws_hash_table *enc_context) {
    struct aws_cryptosdk_multi_mkp *self = (struct aws_cryptosdk_multi_mkp *)mkp;
    assert(self->vt == &vtable);

    size_t len = aws_array_list_length(&self->list);
    for (size_t i = 0; i < len; i++) {
        struct aws_cryptosdk_mkp *child;

        if (aws_array_list_get_at(&self->list, &child, i)) {
            // Should be impossible, but deal with it as best we can
            return aws_raise_error(AWS_ERROR_UNKNOWN);
        }

        if (aws_cryptosdk_mkp_get_master_keys(child, master_keys, enc_context)) {
            return AWS_OP_ERR;
        }
    }

    return AWS_OP_SUCCESS;
}

static int decrypt_data_key_multi(struct aws_cryptosdk_mkp *mkp,
                                  struct aws_cryptosdk_decryption_materials *dec_mat,
                                  const struct aws_cryptosdk_decryption_request *dec_req) {
    struct aws_cryptosdk_multi_mkp *self = (struct aws_cryptosdk_multi_mkp *)mkp;
    assert(self->vt == &vtable);

    size_t len = aws_array_list_length(&self->list);
    for (size_t i = 0; i < len; i++) {
        struct aws_cryptosdk_mkp *child;

        if (aws_array_list_get_at(&self->list, &child, i)) {
            // Should be impossible, but deal with it as best we can
            return aws_raise_error(AWS_ERROR_UNKNOWN);
        }

        int result = aws_cryptosdk_mkp_decrypt_data_key(child, dec_mat, dec_req);
        // If the decrypt operation failed, we'll still try with the other child MKPs (if any)
        if (result == AWS_OP_SUCCESS && dec_mat->unencrypted_data_key.len) {
            return AWS_OP_SUCCESS;
        }
    }

    return AWS_OP_SUCCESS;
}
