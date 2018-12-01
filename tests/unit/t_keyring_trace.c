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
#include <aws/cryptosdk/keyring_trace.h>
#include "testing.h"

AWS_STATIC_STRING_FROM_LITERAL(kms_namespace, "aws-kms");
AWS_STATIC_STRING_FROM_LITERAL(kms_key, "key_arn");
int init_and_clean_up() {
    struct aws_allocator *alloc = aws_default_allocator();
    struct aws_array_list trace;
    TEST_ASSERT_SUCCESS(aws_cryptosdk_keyring_trace_init(alloc, &trace));

    struct aws_cryptosdk_keyring_trace_item item;
    item.flags = AWS_CRYPTOSDK_WRAPPING_KEY_GENERATED_DATA_KEY |
        AWS_CRYPTOSDK_WRAPPING_KEY_ENCRYPTED_DATA_KEY |
        AWS_CRYPTOSDK_WRAPPING_KEY_SIGNED_ENC_CTX;

    TEST_ASSERT_SUCCESS(aws_cryptosdk_wrapping_key_init(alloc,
                                                        &item.wrapping_key,
                                                        kms_namespace,
                                                        kms_key));
    TEST_ASSERT_SUCCESS(aws_array_list_push_back(&trace, (void *)&item));

    aws_cryptosdk_keyring_trace_clean_up(&trace);
    return 0;
}

struct test_case keyring_trace_test_cases[] = {
    { "keyring_trace", "init_and_clean_up", init_and_clean_up},
    { NULL }
};
