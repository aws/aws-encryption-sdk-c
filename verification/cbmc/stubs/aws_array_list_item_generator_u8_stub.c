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

#include <proof_helpers/make_common_data_structures.h>

/*
 * A generator function as described in the comment
 * in aws_cryptosdk_hash_elems_array_init_stub.c:
 *
 * If the consumer of the list does not use the elements in the list,
 * we can just leave it undefined. This is sound, as it gives you a totally
 * nondet. value every time you use a list element, and is the default
 * behaviour of CBMC. But if it is used, we need a way for the harness
 * to specify valid values for the element, for example if they are copying
 * values out of the table. They can do this by defining
 * -DAWS_CRYPTOSDK_HASH_ELEMS_ARRAY_INIT_GENERATOR=the_generator_fn
 *   where the_generator_fn has signature
 * the_generator_fn(struct aws_array_list *elems).
 *   [elems] is a pointer to the array_list whose values need to be set
 */
void array_list_item_generator(struct aws_array_list *elems) {
    assert(elems->item_size == sizeof(struct aws_hash_element));
    for (size_t index = 0; index < elems->length; ++index) {
        struct aws_hash_element *val = (struct aws_hash_element *)((uint8_t *)elems->data + (elems->item_size * index));
        /* Due to the cast to uint16, the entire size of the enc_ctx must be less than < UINT16_MAX
         * This is a simple way to ensure this without a call to enc_ctx_size. */
        struct aws_string *key = ensure_string_is_allocated_nondet_length();
        __CPROVER_assume(aws_string_is_valid(key));
        __CPROVER_assume(key->len <= UINT8_MAX);
        val->key                 = key;
        struct aws_string *value = ensure_string_is_allocated_nondet_length();
        __CPROVER_assume(aws_string_is_valid(value));
        __CPROVER_assume(value->len <= UINT8_MAX);
        val->value = value;
    }
}
