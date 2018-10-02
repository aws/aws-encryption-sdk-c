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
#include <aws/cryptosdk/private/enc_context.h>
#include <aws/cryptosdk/private/utils.h>
#include <aws/cryptosdk/error.h>
#include "testing.h"

/*
 * Warning: this file uses aws_hash_table_init instead of aws_cryptosdk_enc_context_init
 * in many places because it does a few tricky things, including disabling some of the
 * destructors to avoid double frees and setting up a very large table to avoid
 * reallocations.
 */

AWS_STATIC_STRING_FROM_LITERAL(empty, "");
AWS_STATIC_STRING_FROM_LITERAL(foo, "foo");
AWS_STATIC_STRING_FROM_LITERAL(bar, "bar");
AWS_STATIC_STRING_FROM_LITERAL(foobar, "foobar");
AWS_STATIC_STRING_FROM_LITERAL(foobaz, "foobaz");
AWS_STATIC_STRING_FROM_LITERAL(bar_food, "bar food");
AWS_STATIC_STRING_FROM_LITERAL(bar_null_food, "bar\0food");
AWS_STATIC_STRING_FROM_LITERAL(bar_null_back, "bar\0back");

static int serialize_init(struct aws_allocator *alloc, struct aws_byte_buf *buf, const struct aws_hash_table *enc_context) {
    size_t len;

    if (aws_cryptosdk_context_size(&len, enc_context)) return AWS_OP_ERR;
    if (aws_byte_buf_init(alloc, buf, len)) return AWS_OP_ERR;

    return aws_cryptosdk_context_serialize(alloc, buf, enc_context);
}

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
    TEST_ASSERT_INT_EQ(aws_cryptosdk_hash_elems_array_init(alloc, &elems, &map), AWS_OP_SUCCESS);
    aws_array_list_sort(&elems, aws_cryptosdk_compare_hash_elems_by_key_string);

    TEST_ASSERT_INT_EQ(elems.length, num_elems);
    for (int idx = 0; idx < num_elems; ++idx) {
        struct aws_hash_element elem;
        TEST_ASSERT_INT_EQ(aws_array_list_get_at(&elems, (void *)&elem, idx), AWS_OP_SUCCESS);
        TEST_ASSERT(aws_string_eq((const struct aws_string *)elem.key, sorted_keys[idx]));
        TEST_ASSERT(aws_string_eq((const struct aws_string *)elem.value, sorted_vals[idx]));
    }
    aws_array_list_clean_up(&elems);
    aws_cryptosdk_enc_context_clean_up(&map);
    return 0;
}

int serialize_empty_enc_context() {
    struct aws_allocator * alloc = aws_default_allocator();

    struct aws_hash_table enc_context;
    TEST_ASSERT_INT_EQ(aws_hash_table_init(&enc_context, alloc, 10, aws_hash_string, aws_string_eq, NULL, NULL),
                       AWS_OP_SUCCESS);

    struct aws_byte_buf output = { 0 };
    size_t len;
    TEST_ASSERT_SUCCESS(aws_cryptosdk_context_size(&len, &enc_context));
    TEST_ASSERT_INT_EQ(len, 0);

    TEST_ASSERT_SUCCESS(aws_cryptosdk_context_serialize(alloc, &output, &enc_context));
    TEST_ASSERT_INT_EQ(output.len, 0);

    aws_byte_buf_clean_up(&output);
    aws_cryptosdk_enc_context_clean_up(&enc_context);
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
    TEST_ASSERT_INT_EQ(serialize_init(alloc, &output, &enc_context), AWS_OP_SUCCESS);
    TEST_ASSERT_INT_EQ(output.len, sizeof(serialized_ctx) - 1);
    TEST_ASSERT_INT_EQ(0, memcmp(output.buffer, serialized_ctx, output.len));
    aws_byte_buf_clean_up(&output);
    aws_cryptosdk_enc_context_clean_up(&enc_context);
    return 0;
}

int serialize_valid_enc_context_unsigned_comparison() {
    const uint8_t serialized_ctx[] =
        "\x00\x02"
        "\x00\x09""aaaaaaaa\x7f"
        "\x00\x08""BBBBBBBB"
        "\x00\x09""aaaaaaaa\x80"
        "\x00\x08""AAAAAAAA";

    AWS_STATIC_STRING_FROM_LITERAL(key_a, "aaaaaaaa\x80");
    AWS_STATIC_STRING_FROM_LITERAL(value_a, "AAAAAAAA");
    AWS_STATIC_STRING_FROM_LITERAL(key_b, "aaaaaaaa\x7f");
    AWS_STATIC_STRING_FROM_LITERAL(value_b, "BBBBBBBB");

    const struct aws_string * keys[] = {key_a, key_b};
    const struct aws_string * vals[] = {value_a, value_b};
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
    TEST_ASSERT_INT_EQ(serialize_init(alloc, &output, &enc_context), AWS_OP_SUCCESS);
    TEST_ASSERT_INT_EQ(output.len, sizeof(serialized_ctx) - 1);
    TEST_ASSERT_INT_EQ(0, memcmp(output.buffer, serialized_ctx, output.len));

    aws_byte_buf_clean_up(&output);
    aws_cryptosdk_enc_context_clean_up(&enc_context);
    return 0;
}

int serialize_error_when_element_too_long() {
    struct aws_allocator * alloc = aws_default_allocator();

    uint8_t bytes[UINT16_MAX+1] = {0};
    const struct aws_string * str = aws_string_new_from_array(alloc, bytes, UINT16_MAX+1);
    TEST_ASSERT_ADDR_NOT_NULL(str);

    struct aws_hash_table enc_context;
    TEST_ASSERT_INT_EQ(aws_hash_table_init(&enc_context, alloc, 10, aws_hash_string, aws_string_eq, NULL, aws_string_destroy),
                       AWS_OP_SUCCESS);

    struct aws_hash_element * elem;
    TEST_ASSERT_INT_EQ(aws_hash_table_create(&enc_context, (void *)empty, &elem, NULL), AWS_OP_SUCCESS);
    elem->value = (void *)str;
    
    struct aws_byte_buf output;
    TEST_ASSERT_ERROR(AWS_CRYPTOSDK_ERR_LIMIT_EXCEEDED,
                      serialize_init(alloc, &output, &enc_context));

    aws_cryptosdk_enc_context_clean_up(&enc_context);
    return 0;
}

int serialize_error_when_serialized_len_too_long() {
    struct aws_allocator * alloc = aws_default_allocator();
#define TWO_TO_THE_FIFTEENTH (1 << 15)
    uint8_t bytes[TWO_TO_THE_FIFTEENTH] = {0};
    const struct aws_string * str = aws_string_new_from_array(alloc, bytes, TWO_TO_THE_FIFTEENTH);
    TEST_ASSERT_ADDR_NOT_NULL(str);

    struct aws_hash_table enc_context;
    // only setting destroy function on value so it doesn't try to destroy same string twice
    TEST_ASSERT_INT_EQ(aws_hash_table_init(&enc_context, alloc, 10, aws_hash_string, aws_string_eq, NULL, aws_string_destroy),
                       AWS_OP_SUCCESS);

    struct aws_hash_element * elem;
    TEST_ASSERT_INT_EQ(aws_hash_table_create(&enc_context, (void *)str, &elem, NULL), AWS_OP_SUCCESS);
    elem->value = (void *)str;

    struct aws_byte_buf output;
    TEST_ASSERT_ERROR(AWS_CRYPTOSDK_ERR_LIMIT_EXCEEDED,
                      serialize_init(alloc, &output, &enc_context));

    aws_cryptosdk_enc_context_clean_up(&enc_context);
    return 0;
}

int serialize_valid_enc_context_max_length() {
    struct aws_allocator * alloc = aws_default_allocator();
    struct aws_hash_table enc_context;
    TEST_ASSERT_SUCCESS(aws_cryptosdk_enc_context_init(alloc, &enc_context));

    /* 2 bytes: key-value count
       2 bytes: key length (=UINT16_MAX - 6)
       UINT16_MAX - 6 bytes: key field
       2 bytes: value length (=0)
       0 bytes: value field (empty string)
     */
#define LONG_ARR_LEN (UINT16_MAX - 6)
    uint8_t arr[LONG_ARR_LEN] = {0};
    const struct aws_string * key = aws_string_new_from_array(alloc, arr, LONG_ARR_LEN);
    TEST_ASSERT_ADDR_NOT_NULL(key);

    int was_created = 0;
    struct aws_hash_element * elem;
    TEST_ASSERT_INT_EQ(aws_hash_table_create(&enc_context, (void *)key, &elem, &was_created), AWS_OP_SUCCESS);
    TEST_ASSERT_INT_EQ(was_created, 1);
    elem->value = (void *)empty;

    struct aws_byte_buf output;
    TEST_ASSERT_INT_EQ(serialize_init(alloc, &output, &enc_context), AWS_OP_SUCCESS);
    TEST_ASSERT_INT_EQ(output.len, UINT16_MAX);
    aws_byte_buf_clean_up(&output);
    aws_cryptosdk_enc_context_clean_up(&enc_context);
    return 0;
}

int serialize_error_when_too_many_elements() {
    struct aws_allocator * alloc = aws_default_allocator();
    struct aws_hash_table enc_context;
    TEST_ASSERT_INT_EQ(aws_hash_table_init(&enc_context, alloc, (size_t)UINT16_MAX + 10, aws_hash_string, aws_string_eq, aws_string_destroy, NULL),
                       AWS_OP_SUCCESS);

    char buf[6] = {0};
    for (size_t idx = 0; idx < (1 << 16); ++idx) {
        int was_created = 0;
        struct aws_hash_element * elem;
        snprintf(buf, sizeof(buf), "%zu", idx);
        const struct aws_string * str = aws_string_new_from_c_str(alloc, buf);
        TEST_ASSERT_INT_EQ(aws_hash_table_create(&enc_context, (void *)str, &elem, &was_created), AWS_OP_SUCCESS);
        TEST_ASSERT_INT_EQ(was_created, 1);
        elem->value = (void *)str;
    }

    struct aws_byte_buf output;
    TEST_ASSERT_ERROR(AWS_CRYPTOSDK_ERR_LIMIT_EXCEEDED,
                      serialize_init(alloc, &output, &enc_context));
    aws_cryptosdk_enc_context_clean_up(&enc_context);
    return 0;
}

struct test_case enc_context_test_cases[] = {
    { "enc_context", "get_sorted_elems_array_test", get_sorted_elems_array_test },
    { "enc_context", "serialize_empty_enc_context", serialize_empty_enc_context },
    { "enc_context", "serialize_valid_enc_context", serialize_valid_enc_context },
    { "enc_context", "serialize_valid_enc_context_unsigned_comparison", serialize_valid_enc_context_unsigned_comparison },
    { "enc_context", "serialize_error_when_element_too_long", serialize_error_when_element_too_long },
    { "enc_context", "serialize_error_when_serialized_len_too_long", serialize_error_when_serialized_len_too_long },
    { "enc_context", "serialize_valid_enc_context_max_length", serialize_valid_enc_context_max_length },
    { "enc_context", "serialize_error_when_too_many_elements", serialize_error_when_too_many_elements },
    { NULL }
};
