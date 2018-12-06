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
#include <aws/common/hash_table.h>
#include "testing.h"
#include "testutil.h"

AWS_STATIC_STRING_FROM_LITERAL(kms_name_space, "aws-kms");
AWS_STATIC_STRING_FROM_LITERAL(kms_key, "key_arn");
int keyring_trace_add_record_works() {
    struct aws_allocator *alloc = aws_default_allocator();
    struct aws_array_list trace;
    TEST_ASSERT_SUCCESS(aws_cryptosdk_keyring_trace_init(alloc, &trace));

    TEST_ASSERT_SUCCESS(aws_cryptosdk_keyring_trace_add_record(
                            alloc,
                            &trace,
                            kms_name_space,
                            kms_key,
                            AWS_CRYPTOSDK_WRAPPING_KEY_GENERATED_DATA_KEY |
                            AWS_CRYPTOSDK_WRAPPING_KEY_ENCRYPTED_DATA_KEY |
                            AWS_CRYPTOSDK_WRAPPING_KEY_SIGNED_ENC_CTX));

    TEST_ASSERT_SUCCESS(assert_keyring_trace_record(
                            &trace,
                            0,
                            aws_string_bytes(kms_name_space),
                            aws_string_bytes(kms_key),
                            AWS_CRYPTOSDK_WRAPPING_KEY_GENERATED_DATA_KEY |
                            AWS_CRYPTOSDK_WRAPPING_KEY_ENCRYPTED_DATA_KEY |
                            AWS_CRYPTOSDK_WRAPPING_KEY_SIGNED_ENC_CTX));
    
    aws_cryptosdk_keyring_trace_clean_up(&trace);
    return 0;
}

struct test_case keyring_trace_test_cases[] = {
    { "keyring_trace", "keyring_trace_add_record_works", keyring_trace_add_record_works},
    { NULL }
};
