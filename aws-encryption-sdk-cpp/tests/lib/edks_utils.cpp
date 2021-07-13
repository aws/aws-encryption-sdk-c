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

#include "edks_utils.h"

/*
 * On Windows, we can't have classes fully implemented in headers that are dllexported,
 * so make sure to give the compiler a place to generate the exported symbols.
 */
Aws::Cryptosdk::Testing::Edks::Edks(struct aws_allocator *allocator) {
    aws_cryptosdk_edk_list_init(allocator, &encrypted_data_keys);
}
Aws::Cryptosdk::Testing::Edks::~Edks() {
    aws_cryptosdk_edk_list_clean_up(&encrypted_data_keys);
}
