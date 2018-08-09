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
#include <aws/cryptosdk/multi_kr.h>
#include "testing.h"

int can_create_multi_kr() {
    struct aws_cryptosdk_kr * multi = aws_cryptosdk_multi_kr_new(aws_default_allocator());
    TEST_ASSERT_ADDR_NOT_NULL(multi);
    aws_cryptosdk_kr_destroy(multi);
    return 0;
}

struct test_case multi_kr_test_cases[] = {
    { "multi_kr", "can_create_multi_kr", can_create_multi_kr },
    { NULL }
};
