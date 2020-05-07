/*
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"). You may not
 * use
 * this file except in compliance with the License. A copy of the License is
 * located at
 *
 *     http://aws.amazon.com/apache2.0/
 *
 * or in the "license" file accompanying this file. This file is distributed on
 * an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express
 * or
 * implied. See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <aws/cryptosdk/edk.h>
#include <proof_helpers/cryptosdk/make_common_data_structures.h>
#include <proof_helpers/make_common_data_structures.h>
#include <proof_helpers/proof_allocators.h>
#include <proof_helpers/utils.h>

bool aws_array_list_is_valid(const struct aws_array_list *AWS_RESTRICT list) {
    if (!list) {
        return false;
    }

    bool data_is_valid =
        ((list->current_size == 0 && list->data == NULL) || AWS_MEM_IS_WRITABLE(list->data, list->current_size));
    bool item_size_is_valid = (list->item_size != 0);
    return data_is_valid && item_size_is_valid;
}

bool aws_array_list_is_valid_deep(const struct aws_array_list *AWS_RESTRICT list) {
    if (!list) {
        return false;
    }
    size_t required_size        = list->length * list->item_size;
    bool required_size_is_valid = true;
    bool current_size_is_valid  = (list->current_size >= required_size);
    bool data_is_valid =
        ((list->current_size == 0 && list->data == NULL) || AWS_MEM_IS_WRITABLE(list->data, list->current_size));
    bool item_size_is_valid = (list->item_size != 0);
    return required_size_is_valid && current_size_is_valid && data_is_valid && item_size_is_valid;
}

// allocator, dest, src
typedef int (*clone_item_fn)(struct aws_allocator *, void *, const void *);
typedef void (*clean_up_item_fn)(void *);

size_t g_item_size;

int cloner(struct aws_allocator *alloc, void *dest, const void *src) {
    assert(AWS_MEM_IS_READABLE(src, g_item_size));
    assert(AWS_MEM_IS_WRITABLE(dest, g_item_size));
    uint8_t *d = (uint8_t *)dest;
    *d         = 0xab;
    return nondet_int();
}

void cleanup(void *p) {
    uint8_t *d = (uint8_t *)p;
    assert(*d == 0xab);
}

void list_copy_all_harness() {
    struct aws_array_list *dest = can_fail_malloc(sizeof(*dest));
    __CPROVER_assume(dest != NULL);
    __CPROVER_assume(aws_array_list_is_bounded(dest, NUM_ELEMS, ITEM_SIZE));
    ensure_array_list_has_allocated_data_member(dest);
    __CPROVER_assume(aws_array_list_is_valid_deep(dest));

    struct aws_array_list *src = can_fail_malloc(sizeof(*src));
    __CPROVER_assume(src != NULL);
    __CPROVER_assume(aws_array_list_is_bounded(src, NUM_ELEMS, ITEM_SIZE));
    ensure_array_list_has_allocated_data_member(src);
    __CPROVER_assume(aws_array_list_is_valid_deep(src));

    g_item_size                          = src->item_size;
    const struct aws_array_list old_dest = *dest;
    const struct aws_array_list old_src  = *src;
    if (list_copy_all(can_fail_allocator(), dest, src, cloner, cleanup) == AWS_OP_SUCCESS) {
        assert(src->length == old_src.length);
        assert(dest->length == old_dest.length + old_src.length);
    } else {
        assert(src->length == old_src.length);
        assert(dest->length == old_dest.length);
    }
    assert(aws_array_list_is_valid(src));
    assert(aws_array_list_is_valid(dest));
}

#include <aws/common/error.inl>
