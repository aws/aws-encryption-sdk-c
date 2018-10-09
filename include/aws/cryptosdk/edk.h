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

#ifndef AWS_CRYPTOSDK_EDK_H
#define AWS_CRYPTOSDK_EDK_H

#include <aws/common/array_list.h>
#include <aws/common/byte_buf.h>

#include <aws/cryptosdk/exports.h>

/*
 * This public interface to the encrypted data key (EDK) objects is provided for
 * developers of CMMs and keyrings only. If you are a user of the AWS Encryption
 * SDK for C and you are not developing your own CMMs and/or keyrings, you do not
 * need to use it and you should not do so.
 */

struct aws_cryptosdk_edk {
    struct aws_byte_buf name_space;
    struct aws_byte_buf provider_info;
    struct aws_byte_buf enc_data_key;
};

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Deallocates all memory associated with an EDK. Setting all bytes of EDK to
 * zero upon creation will make this safe to call even if some buffers are unused.
 */
AWS_CRYPTOSDK_API
void aws_cryptosdk_edk_clean_up(struct aws_cryptosdk_edk *edk);

/**
 * Allocates an empty list of EDKs.
 */
AWS_CRYPTOSDK_API
int aws_cryptosdk_edk_list_init(struct aws_allocator *alloc, struct aws_array_list *edk_list);

/**
 * Deallocates all memory associated with all EDKs in the list and then deallocates the list.
 */
AWS_CRYPTOSDK_API
void aws_cryptosdk_edk_list_clean_up(struct aws_array_list *edk_list);

/**
 * Deallocates all memory associated with all EDKs in the list and then clears the list.
 * The array list itself remains allocated but empty.
 */
AWS_CRYPTOSDK_API
void aws_cryptosdk_edk_list_clear(struct aws_array_list *edk_list);

/**
 * Returns true if the contents of all EDK byte buffers are identical, false otherwise.
 */
AWS_CRYPTOSDK_STATIC_INLINE bool aws_cryptosdk_edk_eq(const struct aws_cryptosdk_edk *a, const struct aws_cryptosdk_edk *b) {
    return aws_byte_buf_eq(&a->enc_data_key, &b->enc_data_key) &&
        aws_byte_buf_eq(&a->provider_info, &b->provider_info) &&
        aws_byte_buf_eq(&a->name_space, &b->name_space);
}

/**
 * Appends the contents of source EDK list to destination EDK list, and clears source list,
 * but does not clean it up. This makes a shallow copy of all EDKs, so byte buffers are not
 * duplicated. Their ownership is just transferred from the source list to the destination.
 */
AWS_CRYPTOSDK_API
int aws_cryptosdk_transfer_edk_list(struct aws_array_list *dest, struct aws_array_list *src);

#ifdef __cplusplus
}
#endif

#endif // AWS_CRYPTOSDK_EDK_H

