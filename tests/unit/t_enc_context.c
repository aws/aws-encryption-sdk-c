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
#include <aws/cryptosdk/enc_context.h>
#include <aws/cryptosdk/error.h>
#include "testing.h"

AWS_STATIC_STRING_FROM_LITERAL(empty, "");
AWS_STATIC_STRING_FROM_LITERAL(foo, "foo");
AWS_STATIC_STRING_FROM_LITERAL(bar, "bar");
AWS_STATIC_STRING_FROM_LITERAL(foobar, "foobar");
AWS_STATIC_STRING_FROM_LITERAL(foobaz, "foobaz");
AWS_STATIC_STRING_FROM_LITERAL(bar_food, "bar food");
AWS_STATIC_STRING_FROM_LITERAL(bar_null_food, "bar\0food");
AWS_STATIC_STRING_FROM_LITERAL(bar_null_back, "bar\0back");

int get_sorted_elems_array_test() {
    const struct aws_string * keys[] = {foo, bar, foobar, empty, bar_null_food};
    const struct aws_string * vals[] = {bar, foo, foobaz, bar_food, bar_null_back};
    int num_elems = sizeof(keys)/sizeof(const struct aws_string *);

    const struct aws_string * sorted_keys[] = {empty, bar, bar_null_food, foo, foobar};
    const struct aws_string * sorted_vals[] = {bar_food, foo, bar_null_back, bar, foobaz};

    struct aws_allocator * alloc = aws_default_allocator();

    struct aws_hash_table map;
    TEST_ASSERT_INT_EQ(aws_hash_table_init(&map, alloc, 10, aws_hash_string, aws_string_eq, NULL, NULL),
                       AWS_OP_SUCCESS);

    for (int idx = 0; idx < num_elems; ++idx) {
        struct aws_hash_element * elem;
        TEST_ASSERT_INT_EQ(aws_hash_table_create(&map, (void *)keys[idx], &elem, NULL), AWS_OP_SUCCESS);
        elem->value = (void *)vals[idx];
    }

    struct aws_array_list elems;
    TEST_ASSERT_INT_EQ(aws_hash_table_get_elems_array_init(alloc, &elems, &map), AWS_OP_SUCCESS);
    aws_array_list_sort(&elems, aws_array_list_compare_hash_elements_by_key_string);

    TEST_ASSERT_INT_EQ(elems.length, num_elems);
    for (int idx = 0; idx < num_elems; ++idx) {
        struct aws_hash_element elem;
        TEST_ASSERT_INT_EQ(aws_array_list_get_at(&elems, (void *)&elem, idx), AWS_OP_SUCCESS);
        TEST_ASSERT(aws_string_eq((const struct aws_string *)elem.key, sorted_keys[idx]));
        TEST_ASSERT(aws_string_eq((const struct aws_string *)elem.value, sorted_vals[idx]));
    }
    aws_array_list_clean_up(&elems);
    aws_hash_table_clean_up(&map);
    return 0;
}

int serialize_empty_enc_context() {
    const uint8_t serialized_ctx[] = {0x00, 0x00};

    struct aws_allocator * alloc = aws_default_allocator();

    struct aws_hash_table enc_context;
    TEST_ASSERT_INT_EQ(aws_hash_table_init(&enc_context, alloc, 10, aws_hash_string, aws_string_eq, NULL, NULL),
                       AWS_OP_SUCCESS);

    struct aws_byte_buf output;
    TEST_ASSERT_INT_EQ(aws_cryptosdk_serialize_enc_context_init(alloc, &output, &enc_context), AWS_OP_SUCCESS);
    TEST_ASSERT_INT_EQ(output.len, sizeof(serialized_ctx));
    TEST_ASSERT_INT_EQ(0, memcmp(output.buffer, serialized_ctx, output.len));
    aws_byte_buf_clean_up(&output);
    aws_hash_table_clean_up(&enc_context);
    return 0;
}

int serialize_valid_enc_context() {
    const uint8_t serialized_ctx[] =
        "\x00\x04"
        "\x00\x15""aws-crypto-public-key\x00\x44""AmZvwV/dN6o9p/usAnJdRcdnE12UbaDHuEFPeyVkw5FC1ULGlSznzDdD3FP8SW1UMg=="
        "\x00\x05key_a\x00\x07value_a"
        "\x00\x05key_b\x00\x07value_b"
        "\x00\x05key_c\x00\x07value_c";

    AWS_STATIC_STRING_FROM_LITERAL(key_a, "key_a");
    AWS_STATIC_STRING_FROM_LITERAL(value_a, "value_a");
    AWS_STATIC_STRING_FROM_LITERAL(key_b, "key_b");
    AWS_STATIC_STRING_FROM_LITERAL(value_b, "value_b");
    AWS_STATIC_STRING_FROM_LITERAL(key_c, "key_c");
    AWS_STATIC_STRING_FROM_LITERAL(value_c, "value_c");
    AWS_STATIC_STRING_FROM_LITERAL(aws_crypto_public_key, "aws-crypto-public-key");
    AWS_STATIC_STRING_FROM_LITERAL(public_key_val, "AmZvwV/dN6o9p/usAnJdRcdnE12UbaDHuEFPeyVkw5FC1ULGlSznzDdD3FP8SW1UMg==");

    const struct aws_string * keys[] = {key_b, key_a, aws_crypto_public_key, key_c};
    const struct aws_string * vals[] = {value_b, value_a, public_key_val, value_c};
    int num_elems = sizeof(keys)/sizeof(const struct aws_string *);

    struct aws_allocator * alloc = aws_default_allocator();

    struct aws_hash_table enc_context;
    TEST_ASSERT_INT_EQ(aws_hash_table_init(&enc_context, alloc, 10, aws_hash_string, aws_string_eq, NULL, NULL),
                       AWS_OP_SUCCESS);

    for (int idx = 0; idx < num_elems; ++idx) {
        struct aws_hash_element * elem;
        TEST_ASSERT_INT_EQ(aws_hash_table_create(&enc_context, (void *)keys[idx], &elem, NULL), AWS_OP_SUCCESS);
        elem->value = (void *)vals[idx];
    }

    struct aws_byte_buf output;
    TEST_ASSERT_INT_EQ(aws_cryptosdk_serialize_enc_context_init(alloc, &output, &enc_context), AWS_OP_SUCCESS);
    TEST_ASSERT_INT_EQ(output.len, sizeof(serialized_ctx) - 1);
    TEST_ASSERT_INT_EQ(0, memcmp(output.buffer, serialized_ctx, output.len));
    aws_byte_buf_clean_up(&output);
    aws_hash_table_clean_up(&enc_context);
    return 0;
}

#define ASSERT_SERIALIZATION_ERR_SET \
    do { \
        TEST_ASSERT_INT_EQ(aws_last_error(), AWS_CRYPTOSDK_ERR_SERIALIZATION); \
        aws_reset_error(); \
    } while (0)

int serialize_error_when_element_too_long() {
    struct aws_allocator * alloc = aws_default_allocator();

    AWS_STATIC_STRING_FROM_LITERAL(empty, "");
    uint8_t bytes[UINT16_MAX+1];
    const struct aws_string * str = aws_string_from_array_new(alloc, bytes, UINT16_MAX+1);
    TEST_ASSERT_ADDR_NOT_NULL(str);

    struct aws_hash_table enc_context;
    TEST_ASSERT_INT_EQ(aws_hash_table_init(&enc_context, alloc, 10, aws_hash_string, aws_string_eq, NULL, aws_string_destroy),
                       AWS_OP_SUCCESS);

    struct aws_hash_element * elem;
    TEST_ASSERT_INT_EQ(aws_hash_table_create(&enc_context, (void *)empty, &elem, NULL), AWS_OP_SUCCESS);
    elem->value = (void *)str;
    
    struct aws_byte_buf output;
    TEST_ASSERT_INT_EQ(aws_cryptosdk_serialize_enc_context_init(alloc, &output, &enc_context), AWS_OP_ERR);
    ASSERT_SERIALIZATION_ERR_SET;

    aws_hash_table_clean_up(&enc_context);
    return 0;
}

int serialize_error_when_serialized_len_too_long() {
    struct aws_allocator * alloc = aws_default_allocator();
#define TWO_TO_THE_FIFTEENTH ((UINT16_MAX + 1) >> 1)
    uint8_t bytes[TWO_TO_THE_FIFTEENTH];
    const struct aws_string * str = aws_string_from_array_new(alloc, bytes, TWO_TO_THE_FIFTEENTH);
    TEST_ASSERT_ADDR_NOT_NULL(str);

    struct aws_hash_table enc_context;
    // only setting destroy function on value so it doesn't try to destroy same string twice
    TEST_ASSERT_INT_EQ(aws_hash_table_init(&enc_context, alloc, 10, aws_hash_string, aws_string_eq, NULL, aws_string_destroy),
                       AWS_OP_SUCCESS);

    struct aws_hash_element * elem;
    TEST_ASSERT_INT_EQ(aws_hash_table_create(&enc_context, (void *)str, &elem, NULL), AWS_OP_SUCCESS);
    elem->value = (void *)str;

    struct aws_byte_buf output;
    TEST_ASSERT_INT_EQ(aws_cryptosdk_serialize_enc_context_init(alloc, &output, &enc_context), AWS_OP_ERR);
    ASSERT_SERIALIZATION_ERR_SET;

    aws_hash_table_clean_up(&enc_context);
    return 0;
}


/* Convenience functions for a hash table which uses uint64_t as keys, and whose hash function
 * is just the identity function.
 */
static uint64_t hash_uint64_identity(const void *a) {
    return *(uint64_t *)a;
}

static bool hash_uint64_eq(const void *a, const void *b) {
    uint64_t my_a = *(uint64_t *)a;
    uint64_t my_b = *(uint64_t *)b;
    return my_a == my_b;
}

int serialize_error_when_too_many_elements() {
    /* This test is "cheating", so to speak, in that it uses integer elements instead of aws_strings, which
     * would not function properly with the serialization code and crash, except that the check for the entry
     * count of the hash table happens before any of the code that would crash. However, it is already a high
     * memory usage test and doing it the "right" way would require us to construct 2^16 distinct string objects
     * and hash all of them, making it an even higher memory usage test.
     */
    struct aws_allocator * alloc = aws_default_allocator();
    struct aws_hash_table enc_context;
    TEST_ASSERT_INT_EQ(aws_hash_table_init(&enc_context, alloc, UINT16_MAX + 10, hash_uint64_identity, hash_uint64_eq, NULL, NULL),
                       AWS_OP_SUCCESS);
    /* This won't preserve the hash elements to look up later, but that doesn't matter for this test.
     * Need to start at 1 because 0 is not an acceptable element hash value, which prevents item creation.
     */
    for (uint64_t idx = 1; idx < UINT16_MAX + 2; ++idx) {
        int was_created = 0;
        TEST_ASSERT_INT_EQ(aws_hash_table_create(&enc_context, (void *)&idx, NULL, &was_created), AWS_OP_SUCCESS);
        TEST_ASSERT_INT_EQ(was_created, 1);
    }
    struct aws_byte_buf output;
    TEST_ASSERT_INT_EQ(aws_cryptosdk_serialize_enc_context_init(alloc, &output, &enc_context), AWS_OP_ERR);
    ASSERT_SERIALIZATION_ERR_SET;
    aws_hash_table_clean_up(&enc_context);
    return 0;
}

struct test_case enc_context_test_cases[] = {
    { "enc_context", "get_sorted_elems_array_test", get_sorted_elems_array_test },
    { "enc_context", "serialize_empty_enc_context", serialize_empty_enc_context },
    { "enc_context", "serialize_valid_enc_context", serialize_valid_enc_context },
    { "enc_context", "serialize_error_when_element_too_long", serialize_error_when_element_too_long },
    { "enc_context", "serialize_error_when_serialized_len_too_long", serialize_error_when_serialized_len_too_long },
    { "enc_context", "serialize_error_when_too_many_elements", serialize_error_when_too_many_elements },
    { NULL }
};
