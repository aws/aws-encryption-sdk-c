#ifndef AWS_CRYPTOSDK_MAKE_COMMON_DATA_STRUCTURES_H
#define AWS_CRYPTOSDK_MAKE_COMMON_DATA_STRUCTURES_H

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

#include <aws/common/common.h>
#include <aws/cryptosdk/cipher.h>
#include <aws/cryptosdk/private/framefmt.h>
#include <proof_helpers/make_common_data_structures.h>
#include <proof_helpers/proof_allocators.h>
#include <stdint.h>
#include <stdlib.h>

/**
 * This function creates a valid alg properties data structure by
 * calling the initializer in cipher.h. This is the only valid way to
 * construct an alg_props structure, and that is why
 * [aws_cryptosdk_alg_properties_is_valid] checks whether the pointer
 * of alg_props is the same as the one returned after calling the
 * [aws_cryptosdk_alg_props] initializer.
 */
void ensure_alg_properties_is_allocated(struct aws_cryptosdk_alg_properties **alg_props);

#endif /* AWS_CRYPTOSDK_MAKE_COMMON_DATA_STRUCTURES_H */
