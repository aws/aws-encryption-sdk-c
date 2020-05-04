/*
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License").
 * You may not use this file except in compliance with the License.
 * A copy of the License is located at
 *
 *  http://aws.amazon.com/apache2.0
 *
 * or in the "license" file accompanying this file. This file is distributed
 * on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
 * express or implied. See the License for the specific language governing
 * permissions and limitations under the License.
 */

#include <aws/cryptosdk/private/utils.h>
#include <make_common_data_structures.h>
#include <proof_helpers/make_common_data_structures.h>
#include <proof_helpers/utils.h>

void aws_cryptosdk_compare_hash_elems_by_key_string_harness() {
    /* Non-deterministic inputs. */
    struct aws_hash_element *elem_a = can_fail_malloc(sizeof(*elem_a));
    if (elem_a != NULL) {
        if (nondet_bool()) {
            elem_a->key = ensure_string_is_allocated_bounded_length(MAX_STRING_LEN);
            __CPROVER_assume(aws_string_is_valid(elem_a->key));
        } else {
            elem_a->key = NULL;
        }
    }

    struct aws_hash_element *elem_b = can_fail_malloc(sizeof(*elem_b));
    if (elem_b != NULL) {
        if (nondet_bool()) {
            elem_b->key = ensure_string_is_allocated_bounded_length(MAX_STRING_LEN);
            __CPROVER_assume(aws_string_is_valid(elem_b->key));
        } else {
            elem_b->key = NULL;
        }
    }

    bool nondet_lhs = nondet_bool();

    /* Pre-conditions. */
    __CPROVER_assume(elem_a != NULL);
    __CPROVER_assume(elem_b != NULL);

    /* Operation under verification. */
    if (aws_cryptosdk_compare_hash_elems_by_key_string(elem_a, nondet_lhs ? elem_b : elem_a) == AWS_OP_SUCCESS) {
        const struct aws_string *key_a = (const struct aws_string *)elem_a->key;
        const struct aws_string *key_b = (const struct aws_string *)elem_b->key;
        if (nondet_lhs && key_a != NULL && key_b != NULL) {
            assert_bytes_match(key_a->bytes, key_b->bytes, key_a->len);
        }
    }
    if (elem_a->key != NULL) {
        assert(aws_string_is_valid(elem_a->key));
    }
    if (elem_b->key != NULL) {
        assert(aws_string_is_valid(elem_b->key));
    }
}
