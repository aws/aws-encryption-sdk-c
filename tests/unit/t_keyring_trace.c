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
#include <aws/cryptosdk/private/keyring_trace.h>
#include <aws/cryptosdk/list_utils.h>
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

int keyring_trace_copy_all_works() {
    struct aws_allocator *alloc = aws_default_allocator();
    struct aws_array_list traces[2];

    for (int i = 0; i < 2; ++i) {
        TEST_ASSERT_SUCCESS(aws_cryptosdk_keyring_trace_init(alloc, &traces[i]));
    }

    TEST_ASSERT_SUCCESS(aws_cryptosdk_keyring_trace_add_record_c_str(
                            alloc,
                            &traces[0],
                            "foo",
                            "bar",
                            AWS_CRYPTOSDK_WRAPPING_KEY_GENERATED_DATA_KEY |
                            AWS_CRYPTOSDK_WRAPPING_KEY_ENCRYPTED_DATA_KEY));

    TEST_ASSERT_SUCCESS(aws_cryptosdk_keyring_trace_add_record_c_str(
                            alloc,
                            &traces[0],
                            "foo",
                            "baz",
                            AWS_CRYPTOSDK_WRAPPING_KEY_DECRYPTED_DATA_KEY));

    TEST_ASSERT_SUCCESS(aws_cryptosdk_keyring_trace_add_record_c_str(
                            alloc,
                            &traces[0],
                            "foot",
                            "bath",
                            AWS_CRYPTOSDK_WRAPPING_KEY_VERIFIED_ENC_CTX));

    TEST_ASSERT_SUCCESS(aws_cryptosdk_keyring_trace_copy_all(alloc, &traces[1], &traces[0]));

    // both copies of trace have identical parameters
    TEST_ASSERT(aws_cryptosdk_keyring_trace_eq(&traces[0], &traces[1]));

    // both copies of trace are using separate strings (deep copy)
    for (int record_idx = 0; record_idx < 3; ++record_idx) {
        struct aws_cryptosdk_keyring_trace_record *rec[2];
        TEST_ASSERT_SUCCESS(aws_array_list_get_at_ptr(&traces[0], (void **)&rec[0], record_idx));
        TEST_ASSERT_SUCCESS(aws_array_list_get_at_ptr(&traces[1], (void **)&rec[1], record_idx));

        TEST_ASSERT_ADDR_NE(rec[0]->wrapping_key_namespace, rec[1]->wrapping_key_namespace);
        TEST_ASSERT_ADDR_NE(rec[0]->wrapping_key_name, rec[1]->wrapping_key_name);
    }

    // each copy of trace has correct parameters
    for (int i = 0; i < 2; ++i) {
        TEST_ASSERT_SUCCESS(assert_keyring_trace_record(
                                &traces[i],
                                0,
                                "foo",
                                "bar",
                                AWS_CRYPTOSDK_WRAPPING_KEY_GENERATED_DATA_KEY |
                                AWS_CRYPTOSDK_WRAPPING_KEY_ENCRYPTED_DATA_KEY));

        TEST_ASSERT_SUCCESS(assert_keyring_trace_record(
                                &traces[i],
                                1,
                                "foo",
                                "baz",
                                AWS_CRYPTOSDK_WRAPPING_KEY_DECRYPTED_DATA_KEY));

        TEST_ASSERT_SUCCESS(assert_keyring_trace_record(
                                &traces[i],
                                2,
                                "foot",
                                "bath",
                                AWS_CRYPTOSDK_WRAPPING_KEY_VERIFIED_ENC_CTX));

        aws_cryptosdk_keyring_trace_clean_up(&traces[i]);
    }
    return 0;
}

struct test_case keyring_trace_test_cases[] = {
    { "keyring_trace", "keyring_trace_add_record_works", keyring_trace_add_record_works},
    { "keyring_trace", "keyring_trace_copy_all_works", keyring_trace_copy_all_works},
    { NULL }
};
