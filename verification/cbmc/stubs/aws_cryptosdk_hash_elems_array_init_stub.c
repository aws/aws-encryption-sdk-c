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

#include <aws/common/byte_buf.h>
#include <aws/common/common.h>
#include <aws/common/hash_table.h>
#include <aws/common/math.h>

#include <aws/cryptosdk/error.h>
#include <aws/cryptosdk/private/enc_ctx.h>
#include <aws/cryptosdk/private/utils.h>

#include <proof_helpers/utils.h>

/* If the consumer of the list doesn't use the elements in the list, we can just leave it undef
 * This is sound, as it gives you a totally nondet value every time you use a list element, and is the default behaviour
 * of CBMC. But if it is used, we need a way for the harness to specify valid values for the element, for example if
 * they are copying values out of the table. They can do this by defining
 * -DAWS_CRYPTOSDK_HASH_ELEMS_ARRAY_INIT_GENERATOR=the_generator_fn, wher the_generator_fn has signature
 * the_generator_fn(struct aws_array_list *elems).
 *   [elems] is a pointer to the array_list whose values need to be set
 */
#ifdef AWS_CRYPTOSDK_HASH_ELEMS_ARRAY_INIT_GENERATOR
void AWS_CRYPTOSDK_HASH_ELEMS_ARRAY_INIT_GENERATOR(struct aws_array_list *elems);
#endif

int aws_cryptosdk_hash_elems_array_init(
    struct aws_allocator *alloc, struct aws_array_list *elems, const struct aws_hash_table *map) {
    AWS_PRECONDITION(AWS_OBJECT_PTR_IS_READABLE(alloc));
    AWS_PRECONDITION(AWS_OBJECT_PTR_IS_WRITABLE(elems));
    AWS_PRECONDITION(aws_hash_table_is_valid(map));

    size_t entry_count = aws_hash_table_get_entry_count(map);
    elems->alloc       = alloc;
    elems->item_size   = sizeof(struct aws_hash_element);
    elems->length      = entry_count;
    __CPROVER_assume(elems->current_size >= elems->length * elems->item_size);
    elems->data = malloc(elems->current_size);
    /* Malloc can return NULL, assume that elems->data (which would come from map) isn't NULL */
    __CPROVER_assume(elems->data != NULL);

#ifdef AWS_CRYPTOSDK_HASH_ELEMS_ARRAY_INIT_GENERATOR
    AWS_CRYPTOSDK_HASH_ELEMS_ARRAY_INIT_GENERATOR(elems);
#endif
    AWS_POSTCONDITION(aws_array_list_length(elems) == entry_count);
    AWS_POSTCONDITION(aws_array_list_is_valid(elems));

    return nondet_int();
}
