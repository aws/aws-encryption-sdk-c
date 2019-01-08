/*
 * Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
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

#include <aws/common/atomics.h>
#include <aws/common/common.h>

#include <stdint.h>
#include <stdlib.h>

//prevents an issue on atomics_fallback.inl
#define AWS_ATOMICS_HAVE_THREAD_FENCE

typedef size_t aws_atomic_impl_int_t;

/**
 * Does an atomic fetch and add.  Since this is single-threaded CBMC, no need for actual atomic operations.
 */
size_t aws_atomic_fetch_add_explicit(volatile struct aws_atomic_var *var, size_t n, enum aws_memory_order order) {
       size_t retval = AWS_ATOMIC_VAR_INTVAL(var);
       AWS_ATOMIC_VAR_INTVAL(var) += n;
       return retval;
}

/**
 * Initializes an atomic variable with an integer value. This operation should be done before any
 * other operations on this atomic variable, and must be done before attempting any parallel operations.
 */
AWS_STATIC_IMPL
void aws_atomic_init_int(volatile struct aws_atomic_var *var, size_t n) {
    AWS_ATOMIC_VAR_INTVAL(var) = n;
}
