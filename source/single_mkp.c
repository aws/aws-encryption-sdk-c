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

struct single_mkp {
    struct aws_cryptosdk_mkp_vt * vt;
    struct aws_allocator * alloc;
    struct aws_cryptosdk_mk * mk;
};

static void single_mkp_destroy(struct aws_cryptosdk_mkp * mkp) {
    struct single_mkp * self = (struct single_mkp *) mkp;
    if (self && self->alloc) aws_mem_release(self->alloc, self);
}

static int single_mkp_get_master_keys(struct aws_cryptosdk_mkp * mkp,
                                      struct aws_array_list * master_keys, // list of (aws_cryptosdk_mk *)
                                      const struct aws_hash_table * enc_context) {
    struct single_mkp * self = (struct single_mkp *) mkp;
    /* What is being pushed onto the array is the address of the MK, which is the value
     * of self->mk, not its address. However, aws_array_list_push_back expects a pointer to
     * the memory to be copied into the list as its second argument.
     */
    return aws_array_list_push_back(master_keys, &self->mk);
}

static int single_mkp_decrypt_data_key(struct aws_cryptosdk_mkp * mkp,
                                       struct aws_cryptosdk_decryption_materials * dec_mat,
                                       const struct aws_cryptosdk_decryption_request * request) {
    struct single_mkp * self = (struct single_mkp *) mkp;
    return aws_cryptosdk_mk_decrypt_data_key(self->mk, dec_mat, request);
}

static struct aws_cryptosdk_mkp_vt single_mkp_vt = {
    .vt_size = sizeof(struct aws_cryptosdk_mkp_vt),
    .name = "single mkp",
    .destroy = single_mkp_destroy,
    .get_master_keys = single_mkp_get_master_keys,
    .decrypt_data_key = single_mkp_decrypt_data_key
};

struct aws_cryptosdk_mkp * aws_cryptosdk_single_mkp_new(struct aws_allocator * alloc,
                                                        struct aws_cryptosdk_mk * mk) {
    struct single_mkp * mkp = aws_mem_acquire(alloc, sizeof(struct single_mkp));
    if (!mkp) return NULL;

    mkp->vt = &single_mkp_vt;
    mkp->alloc = alloc;
    mkp->mk = mk;

    return (struct aws_cryptosdk_mkp *) mkp;
}
