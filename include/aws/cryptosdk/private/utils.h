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
#ifndef AWS_CRYPTOSDK_PRIVATE_UTILS_H
#define AWS_CRYPTOSDK_PRIVATE_UTILS_H

#include <aws/common/array_list.h>
#include <aws/common/hash_table.h>
#include <aws/common/string.h>

/**
 * Allocates array list and places all hash elements from map into it.
 * No guarantees are made about the order of elements.
 *
 * On failure, does not allocate any memory.
 */
int aws_hash_table_get_elems_array_init(struct aws_allocator * alloc,
                                        struct aws_array_list * elems,
                                        const struct aws_hash_table * map);


/**
 * For sorting arrays of struct aws_hash_elements by doing string comparison on
 * keys. Comparator takes arguments that are (const struct aws_hash_element *) cast
 * to (const void *).
 *
 * This is a comparator function that can be used with aws_array_list_sort.
 */
int aws_array_list_compare_hash_elements_by_key_string(const void * elem_a,
                                                       const void * elem_b);

/**
 * Returns true if bytes of string and cursor are the same, false otherwise.
 */
bool aws_string_eq_byte_cursor(const struct aws_string * str,
                               const struct aws_byte_cursor * cur);


#endif // AWS_CRYPTOSDK_PRIVATE_UTILS_H
