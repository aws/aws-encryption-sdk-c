/*
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
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

#include <aws/common/atomics.h>

/**
 *  For sequential proofs, we directly access the atomic value.
 *  Adds n to *var, and returns the previous value of *var (ignoring order).
 */
size_t aws_atomic_fetch_add_explicit(struct aws_atomic_var *var, size_t n, enum aws_memory_order order) {
    size_t rval = *((size_t *)AWS_ATOMIC_VAR_PTRVAL(var));
    *((size_t *)AWS_ATOMIC_VAR_PTRVAL(var)) += n;
    return rval;
}
