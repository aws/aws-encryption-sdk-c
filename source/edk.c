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
#include <aws/cryptosdk/edk.h>

int aws_cryptosdk_edk_list_init(struct aws_allocator *alloc, struct aws_array_list *edk_list) {
    const int initial_size = 4;  // arbitrary starting point, list will resize as necessary
    return aws_array_list_init_dynamic(edk_list, alloc, initial_size, sizeof(struct aws_cryptosdk_edk));
}

void aws_cryptosdk_edk_clean_up(struct aws_cryptosdk_edk *edk) {
    if (edk->provider_id.allocator)
        aws_byte_buf_clean_up(&edk->provider_id);
    if (edk->provider_info.allocator)
        aws_byte_buf_clean_up(&edk->provider_info);
    if (edk->ciphertext.allocator)
        aws_byte_buf_clean_up(&edk->ciphertext);
}

void aws_cryptosdk_edk_list_clear(struct aws_array_list *edk_list) {
    size_t num_keys = edk_list->length;
    for (size_t key_idx = 0; key_idx < num_keys; ++key_idx) {
        struct aws_cryptosdk_edk *edk;
        if (!aws_array_list_get_at_ptr(edk_list, (void **)&edk, key_idx)) {
            aws_cryptosdk_edk_clean_up(edk);
        }
    }
    aws_array_list_clear(edk_list);
}

void aws_cryptosdk_edk_list_clean_up(struct aws_array_list *edk_list) {
    aws_cryptosdk_edk_list_clear(edk_list);
    aws_array_list_clean_up(edk_list);
}

int aws_cryptosdk_edk_init_clone(
    struct aws_allocator *alloc, struct aws_cryptosdk_edk *dest, const struct aws_cryptosdk_edk *src) {
    memset(dest, 0, sizeof(*dest));

    if (aws_byte_buf_init_copy(&dest->provider_id, alloc, &src->provider_id) ||
        aws_byte_buf_init_copy(&dest->provider_info, alloc, &src->provider_info) ||
        aws_byte_buf_init_copy(&dest->ciphertext, alloc, &src->ciphertext)) {
        aws_cryptosdk_edk_clean_up(dest);
        memset(dest, 0, sizeof(*dest));

        return AWS_OP_ERR;
    }

    return AWS_OP_SUCCESS;
}
