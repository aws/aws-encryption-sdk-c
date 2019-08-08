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

void ensure_alg_properties_has_allocated_names(struct aws_cryptosdk_alg_properties *const alg_props);
void ensure_record_has_allocated_members(struct aws_cryptosdk_keyring_trace_record *record, size_t max_len);
void ensure_trace_has_allocated_records(struct aws_array_list *trace, size_t max_len);
