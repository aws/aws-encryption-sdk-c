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
    const int initial_size = 4; // arbitrary starting point, list will resize as necessary
    return aws_array_list_init_dynamic(edk_list,
                                       alloc,
                                       initial_size,
                                       sizeof(struct aws_cryptosdk_edk));
}

void aws_cryptosdk_edk_clean_up(struct aws_cryptosdk_edk * edk) {
    aws_byte_buf_clean_up(&edk->provider_id);
    aws_byte_buf_clean_up(&edk->provider_info);
    aws_byte_buf_clean_up(&edk->enc_data_key);
}

void aws_cryptosdk_edk_list_clear(struct aws_array_list * edk_list) {
    size_t num_keys = edk_list->length;
    for (size_t key_idx = 0 ; key_idx < num_keys ; ++key_idx) {
        struct aws_cryptosdk_edk * edk;
        if (!aws_array_list_get_at_ptr(edk_list, (void **)&edk, key_idx)) {
            aws_cryptosdk_edk_clean_up(edk);
        }
    }
    aws_array_list_clear(edk_list);
}

void aws_cryptosdk_edk_list_clean_up(struct aws_array_list * edk_list) {
    aws_cryptosdk_edk_list_clear(edk_list);
    aws_array_list_clean_up(edk_list);
}

int aws_cryptosdk_transfer_edk_list(struct aws_array_list *dest, struct aws_array_list *src) {
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

int aws_cryptosdk_edk_init_clone(struct aws_allocator *alloc, struct aws_cryptosdk_edk *dest, const struct aws_cryptosdk_edk *src) {
    memset(dest, 0, sizeof(*dest));

    if (
        aws_byte_buf_init_copy(&dest->provider_id, alloc, &src->provider_id)
     || aws_byte_buf_init_copy(&dest->provider_info, alloc, &src->provider_info)
     || aws_byte_buf_init_copy(&dest->enc_data_key, alloc, &src->enc_data_key)
    ) {
        aws_cryptosdk_edk_clean_up(dest);
        memset(dest, 0, sizeof(*dest));

        return AWS_OP_ERR;
    }

    return AWS_OP_SUCCESS;
}

int aws_cryptosdk_edk_list_copy_all(struct aws_allocator *alloc, struct aws_array_list *dest, const struct aws_array_list *src) {
    size_t initial_length = aws_array_list_length(dest);
    size_t src_length = aws_array_list_length(src);
    int lasterr;

    for (size_t i = 0; i < src_length; i++) {
        void *vp_edk;
        const struct aws_cryptosdk_edk *p_edk;
        struct aws_cryptosdk_edk new_edk;

        if (aws_array_list_get_at_ptr(src, &vp_edk, i)) {
            goto err;
        }

        p_edk = vp_edk;

        if (aws_cryptosdk_edk_init_clone(alloc, &new_edk, p_edk)) {
            goto err;
        }

        if (aws_array_list_push_back(dest, &new_edk)) {
            aws_cryptosdk_edk_clean_up(&new_edk);
            goto err;
        }
    }

    return AWS_OP_SUCCESS;
err:
    lasterr = aws_last_error();

    while (aws_array_list_length(dest) > initial_length) {
        struct aws_cryptosdk_edk new_edk;

        if (aws_array_list_back(dest, &new_edk) || aws_array_list_pop_back(dest)) {
            /*
             * We had elements at aws_array_list, but not anymore, it seems.
             * Someone must be mucking with the destination list from another thread;
             * abort before we do any more damage.
             */
            abort();
        }

        aws_cryptosdk_edk_clean_up(&new_edk);
    }

    return aws_raise_error(lasterr);
}
