/*
 * Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
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

#pragma once

#include <aws/common/common.h>
#include <aws/cryptosdk/cipher.h>
#include <aws/cryptosdk/edk.h>

/**
 * Allocates the members of the context and ensures that internal pointers are pointing to the correct objects. 
 */
void ensure_md_context_has_allocated_members(struct aws_cryptosdk_md_context *ctx);

/**
 * Allocates the members of the context and ensures that internal pointers are pointing to the correct objects. 
 */
void ensure_sig_ctx_has_allocated_members(struct aws_cryptosdk_sig_ctx *ctx);

/**
 * Ensures that the edk members are all bounded as less than max_size.
 */
bool aws_cryptosdk_edk_is_bounded(const struct aws_cryptosdk_edk* edk, const size_t max_size);

/**
 * Ensures that all fields in the edk are properly allocated.
 */
void ensure_cryptosdk_edk_has_allocated_members(struct aws_cryptosdk_edk* edk);
