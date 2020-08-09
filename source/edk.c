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
    AWS_PRECONDITION(aws_cryptosdk_edk_is_valid(edk));

    if (edk->provider_id.allocator) aws_byte_buf_clean_up(&edk->provider_id);
    if (edk->provider_info.allocator) aws_byte_buf_clean_up(&edk->provider_info);
    if (edk->ciphertext.allocator) aws_byte_buf_clean_up(&edk->ciphertext);
    AWS_POSTCONDITION(aws_cryptosdk_edk_is_valid(edk));
}

void aws_cryptosdk_edk_list_clear(struct aws_array_list *edk_list) {
    AWS_PRECONDITION(aws_cryptosdk_edk_list_is_valid(edk_list));

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
    AWS_PRECONDITION(aws_allocator_is_valid(alloc));
    AWS_PRECONDITION(AWS_OBJECT_PTR_IS_READABLE(dest));
    AWS_PRECONDITION(aws_cryptosdk_edk_is_valid(src));

    AWS_ZERO_STRUCT(*dest);

    if (aws_byte_buf_init_copy(&dest->provider_id, alloc, &src->provider_id) ||
        aws_byte_buf_init_copy(&dest->provider_info, alloc, &src->provider_info) ||
        aws_byte_buf_init_copy(&dest->ciphertext, alloc, &src->ciphertext)) {
        aws_cryptosdk_edk_clean_up(dest);
        AWS_ZERO_STRUCT(*dest);

        return AWS_OP_ERR;
    }

    return AWS_OP_SUCCESS;
}

bool aws_cryptosdk_edk_is_valid(const struct aws_cryptosdk_edk *const edk) {
    return AWS_OBJECT_PTR_IS_READABLE(edk) && aws_byte_buf_is_valid(&edk->provider_id) &&
           aws_byte_buf_is_valid(&edk->provider_info) && aws_byte_buf_is_valid(&edk->ciphertext);
}

bool aws_cryptosdk_edk_list_elements_are_valid(const struct aws_array_list *edk_list) {
    size_t len = edk_list->length;
    for (size_t i = 0; i < len; ++i) {
        struct aws_cryptosdk_edk *edk;
        if (!aws_array_list_get_at_ptr(edk_list, (void **)&edk, i)) {
            if (!aws_cryptosdk_edk_is_valid(edk)) {
                return false;
            }
        }
    }
    return true;
}

bool aws_cryptosdk_edk_list_is_valid(const struct aws_array_list *edk_list) {
    if (!AWS_OBJECT_PTR_IS_READABLE(edk_list)) {
        return false;
    }
    if (!aws_array_list_is_valid(edk_list)) {
        return false;
    }
    if (edk_list->item_size != sizeof(struct aws_cryptosdk_edk)) {
        return false;
    }

#if AWS_DEEP_CHECKS == 1
    return aws_cryptosdk_edk_list_elements_are_valid(edk_list);
#else
    return true;
#endif /* AWS_DEEP_CHECKS == 1 */
}

bool aws_cryptosdk_empty_edk_list_is_valid(const struct aws_array_list *edk_list) {
    AWS_PRECONDITION(AWS_OBJECT_PTR_IS_READABLE(edk_list));
    AWS_PRECONDITION(edk_list->length == 0);
    return aws_array_list_is_valid(edk_list) && (edk_list->item_size == sizeof(struct aws_cryptosdk_edk));
}
