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
#ifndef AWS_CRYPTOSDK_LIST_UTILS_H
#define AWS_CRYPTOSDK_LIST_UTILS_H

#include <aws/common/array_list.h>
#include <aws/cryptosdk/exports.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Appends the contents of source list to destination list, and clears source list but
 * does not clean it up. This makes shallow copies of all pointers in the source list, so
 * for example byte buffers and strings are not duplicated. Their ownership is just
 * transferred from the source list to the destination.
 */
AWS_CRYPTOSDK_API
int aws_cryptosdk_transfer_list(struct aws_array_list *dest, struct aws_array_list *src);

/**
 * _Copies_ all EDKs in the list at src, appending the copies to dest. dest must already be initialized.
 *
 * On failure, the destination list is unchanged.
 */
AWS_CRYPTOSDK_API
int aws_cryptosdk_edk_list_copy_all(
    struct aws_allocator *alloc, struct aws_array_list *dest, const struct aws_array_list *src);

#ifdef __cplusplus
}
#endif

#endif  // AWS_CRYPTOSDK_LIST_UTILS_H
