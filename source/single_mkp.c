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
#include <aws/cryptosdk/single_mkp.h>

struct aws_cryptosdk_single_mkp {
    struct aws_cryptosdk_mkp_vt * vt;
    struct aws_allocator * alloc;
    struct aws_cryptosdk_mk * mk;
};

static void single_mkp_destroy(struct aws_cryptosdk_mkp * mkp) {
    struct aws_cryptosdk_single_mkp * self = (struct aws_cryptosdk_single_mkp *) mkp;
    if (self && self->alloc) aws_mem_release(self->alloc, self);
}

static int single_mkp_get_master_keys(struct aws_cryptosdk_mkp * mkp,
                                      struct aws_array_list * master_keys, // list of (aws_cryptosdk_mk *)
                                      const struct aws_hash_table * enc_context) {
    struct aws_cryptosdk_single_mkp * self = (struct aws_cryptosdk_single_mkp *) mkp;
    return aws_array_list_push_back(master_keys, &self->mk); // copies *address* of MK into the list
}

static int single_mkp_decrypt_data_key(struct aws_cryptosdk_mkp * mkp,
                                       struct aws_byte_buf * unencrypted_data_key,
                                       const struct aws_array_list * encrypted_data_keys,
                                       const struct aws_hash_table * enc_context,
                                       enum aws_cryptosdk_alg_id alg) {
    struct aws_cryptosdk_single_mkp * self = (struct aws_cryptosdk_single_mkp *) mkp;
    return aws_cryptosdk_mk_decrypt_data_key(self->mk,
                                             unencrypted_data_key,
                                             encrypted_data_keys,
                                             enc_context,
                                             alg);
}

static struct aws_cryptosdk_mkp_vt aws_cryptosdk_single_mkp_vt = {
    .vt_size = sizeof(struct aws_cryptosdk_mkp_vt),
    .name = "single mkp",
    .destroy = single_mkp_destroy,
    .get_master_keys = single_mkp_get_master_keys,
    .decrypt_data_key = single_mkp_decrypt_data_key
};

struct aws_cryptosdk_mkp * aws_cryptosdk_single_mkp_new(struct aws_allocator * alloc,
                                                        struct aws_cryptosdk_mk * mk) {
    struct aws_cryptosdk_single_mkp * mkp = aws_mem_acquire(alloc,
                                                            sizeof(struct aws_cryptosdk_single_mkp));
    if (!mkp) return NULL;

    mkp->vt = &aws_cryptosdk_single_mkp_vt;
    mkp->alloc = alloc;
    mkp->mk = mk;

    return (struct aws_cryptosdk_mkp *) mkp;
}
