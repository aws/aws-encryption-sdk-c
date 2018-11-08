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

#ifndef CACHE_TEST_LIB_H
#define CACHE_TEST_LIB_H

#include <aws/cryptosdk/materials.h>

void gen_enc_materials(struct aws_allocator *alloc, struct aws_cryptosdk_encryption_materials **p_materials, int index, enum aws_cryptosdk_alg_id alg, int n_edks);
bool materials_eq(const struct aws_cryptosdk_encryption_materials *a, const struct aws_cryptosdk_encryption_materials *b);

#endif