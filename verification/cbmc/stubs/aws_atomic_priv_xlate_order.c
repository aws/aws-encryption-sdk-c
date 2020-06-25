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

/**
 * Takes the existing list, and simply returns it. If the list originally nondeterminstic,
 * this is sound (although it may lead to spurious proof failures if the code under test required the sorted property).
 */

#include <aws/common/atomics.h>

/* The use of this stubs improves coverage results while keeping safety guarantees. */
int aws_atomic_priv_xlate_order(enum aws_memory_order order) {
    assert(
        order == aws_memory_order_relaxed || order == aws_memory_order_acquire || order == aws_memory_order_release ||
        order == aws_memory_order_acq_rel || order == aws_memory_order_seq_cst);
    int nondet_order;
    return nondet_order;
}
