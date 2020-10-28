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

#include <aws/common/math.h>
#include <proof_helpers/nondet.h>

/**
 * If a + b overflows, returns AWS_OP_ERR; otherwise adds
 * a + b, returns the result in *r, and non-deterministically returns either
 * AWS_OP_SUCCESS or AWS_OP_ERR. This increases coverage even for smaller bounds.
 */
int aws_add_size_checked(size_t a, size_t b, size_t *r) {
    if (__CPROVER_overflow_plus(a, b)) return aws_raise_error(AWS_ERROR_OVERFLOW_DETECTED);
    *r = a + b;
    return nondet_bool() ? AWS_OP_SUCCESS : aws_raise_error(AWS_ERROR_OVERFLOW_DETECTED);
}
