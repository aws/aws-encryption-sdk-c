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

#ifndef AWS_CRYPTOSDK_PRIVATE_MATERIALS_H
#define AWS_CRYPTOSDK_PRIVATE_MATERIALS_H

#include <aws/cryptosdk/materials.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Deallocates all memory associated with an EDK. Setting all bytes of EDK to
 * zero upon creation will make this safe to call even if some buffers are unused.
 */
void aws_cryptosdk_edk_clean_up(struct aws_cryptosdk_edk * edk);

/**
 * Deallocates all memory associated with all EDKs in the list and then deallocates the list.
 */
void aws_cryptosdk_edk_list_clean_up(struct aws_array_list * edk_list);

/**
 * Returns true if the contents of all EDK byte buffers are identical, false otherwise.
 */
static inline bool aws_cryptosdk_edk_eq(const struct aws_cryptosdk_edk * a, const struct aws_cryptosdk_edk * b) {
    return aws_byte_buf_eq(&a->enc_data_key, &b->enc_data_key) &&
        aws_byte_buf_eq(&a->provider_info, &b->provider_info) &&
        aws_byte_buf_eq(&a->provider_id, &b->provider_id);
}

#ifdef __cplusplus
}
#endif

#endif // AWS_CRYPTOSDK_PRIVATE_MATERIALS_H
