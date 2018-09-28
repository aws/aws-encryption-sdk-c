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

#include <aws/cryptosdk/private/cpputils.h>
#include <aws/cryptosdk/enc_context.h>
#include <aws/common/string.h>

#include "edks_utils.h"
#include "testutil.h"
#include "testing.h"

using namespace Aws::Cryptosdk::Private;
using namespace Aws::Cryptosdk::Testing;

const char *TEST_STRING = "Hello World!";

static void *s_bad_malloc(struct aws_allocator *allocator, size_t size) {
    return NULL;
}

static void s_bad_free(struct aws_allocator *allocator, void *ptr) {
}

static void *s_bad_realloc(struct aws_allocator *allocator, void *ptr, size_t oldsize, size_t newsize) {
    return NULL;
}

static struct aws_allocator default_bad_allocator = {
    s_bad_malloc, s_bad_free, s_bad_realloc
};

struct aws_allocator *t_aws_bad_allocator() {
    return &default_bad_allocator;
}

int awsStringFromCAwsByteBuf_validInputs_returnAwsString() {
    struct aws_byte_buf b = aws_byte_buf_from_c_str(TEST_STRING);
    Aws::String b_string = aws_string_from_c_aws_byte_buf(&b);
    TEST_ASSERT(b_string == TEST_STRING);
    return 0;
}

int awsUtilsByteBufferFromCAwsByteBuf_validInputs_returnAwsUtils() {
    struct aws_byte_buf b = aws_byte_buf_from_c_str(TEST_STRING);
    Aws::Utils::ByteBuffer b_util = aws_utils_byte_buffer_from_c_aws_byte_buf(&b);
    TEST_ASSERT(
        std::string(reinterpret_cast<const char *>(b_util.GetUnderlyingData()), b_util.GetLength()) == TEST_STRING);
    TEST_ASSERT_INT_EQ(b_util.GetLength(), strlen(TEST_STRING));
    return 0;
}

int awsStringFromCAwsString_validInputs_returnAwsString() {
    struct aws_allocator *allocator = aws_default_allocator();
    const struct aws_string *b = aws_string_new_from_c_str(allocator, TEST_STRING);
    Aws::String b_string = aws_string_from_c_aws_string(b);
    TEST_ASSERT(b_string == TEST_STRING);
    aws_string_destroy((void *) b);
    return 0;
}

int awsByteBufDupFromAwsUtils_validInputs_returnNewAwsByteBuf() {
    struct aws_allocator *allocator = aws_default_allocator();
    const Aws::Utils::ByteBuffer src((u_char *) TEST_STRING, strlen(TEST_STRING));
    struct aws_byte_buf dest;
    struct aws_byte_buf dest_expected = aws_byte_buf_from_c_str(TEST_STRING);
    TEST_ASSERT_SUCCESS(aws_byte_buf_dup_from_aws_utils(allocator, &dest, src));
    TEST_ASSERT(aws_byte_buf_eq(&dest, &dest_expected) == true);
    aws_byte_buf_clean_up(&dest);
    return 0;
}

int awsMapFromCAwsHashHable_hashMap_returnAwsMap() {
    const char *key1_c_chr = "key1";
    const char *key2_c_chr = "key2";
    const char *value1_c_chr = "value1";
    const char *value2_c_chr = "value2";

    struct aws_hash_table hash_table;
    struct aws_allocator *allocator = aws_default_allocator();

    const struct aws_string *key1 = aws_string_new_from_c_str(allocator, key1_c_chr);
    const struct aws_string *key2 = aws_string_new_from_c_str(allocator, key2_c_chr);
    const struct aws_string *value1 = aws_string_new_from_c_str(allocator, value1_c_chr);
    const struct aws_string *value2 = aws_string_new_from_c_str(allocator, value2_c_chr);

    struct aws_hash_element *p_elem;
    int was_created;

    TEST_ASSERT_SUCCESS(aws_cryptosdk_enc_context_init(allocator, &hash_table));

    TEST_ASSERT_SUCCESS(aws_hash_table_create(&hash_table, (void *) key1, &p_elem, &was_created));
    p_elem->value = (void *) value1;

    TEST_ASSERT_SUCCESS(aws_hash_table_create(&hash_table, (void *) key2, &p_elem, &was_created));
    p_elem->value = (void *) value2;

    Aws::Map<Aws::String, Aws::String> aws_map = aws_map_from_c_aws_hash_table(&hash_table);
    aws_cryptosdk_enc_context_clean_up(&hash_table);

    TEST_ASSERT(aws_map[key1_c_chr] == value1_c_chr);
    TEST_ASSERT(aws_map[key2_c_chr] == value2_c_chr);
    TEST_ASSERT(aws_map.size() == 2);

    return 0;
}

/**
 * Structure that initializes data for the tests
 */
struct EdksTestData {
    struct aws_allocator *allocator = aws_default_allocator();
    const char *enc_data;
    const char *data_key_id;
    const char *key_provider;
    Edks edks;
    const Aws::Utils::ByteBuffer enc;

    EdksTestData(const char *enc_data = "ENC data",
                 const char *data_key_id = "data_key_id",
                 const char *key_provider = "key-Provider")
        : enc_data(enc_data),
          data_key_id(data_key_id),
          key_provider(key_provider),
          edks(allocator),
          enc((u_char *) enc_data, strlen(enc_data)) {

    }
};

int appendKeyToEdks_appendSingleElement_elementIsAppended() {
    EdksTestData ed;
    TEST_ASSERT_SUCCESS(t_append_c_str_key_to_edks(ed.allocator,
                                                   &ed.edks.encrypted_data_keys,
                                                   &ed.enc,
                                                   ed.data_key_id,
                                                   ed.key_provider));
    TEST_ASSERT_SUCCESS(t_assert_edks_with_single_element_contains_expected_values(&ed.edks.encrypted_data_keys,
                                                                                   ed.enc_data,
                                                                                   ed.data_key_id,
                                                                                   ed.key_provider,
                                                                                   ed.allocator));

    return 0;
}

int appendKeyToEdks_allocatorThatDoesNotAllocateMemory_returnsOomError() {
    struct aws_allocator *oom_allocator = t_aws_bad_allocator();
    EdksTestData ed;
    TEST_ASSERT_ERROR(AWS_ERROR_OOM, t_append_c_str_key_to_edks(oom_allocator,
                                                                &ed.edks.encrypted_data_keys,
                                                                &ed.enc,
                                                                ed.data_key_id,
                                                                ed.key_provider));
    return 0;
}

int appendKeyToEdks_multipleElementsAppended_elementsAreAppended() {
    EdksTestData ed1;
    EdksTestData ed2("enc2", "dk2", "kp2");
    EdksTestData ed3("enc3", "dk3", "kp3");

    // We append only to ed1.edks.encrypted_data_keys to test accumulation
    TEST_ASSERT_SUCCESS(t_append_c_str_key_to_edks(ed1.allocator,
                                                   &ed1.edks.encrypted_data_keys,
                                                   &ed1.enc,
                                                   ed1.data_key_id,
                                                   ed1.key_provider));
    TEST_ASSERT_SUCCESS(t_append_c_str_key_to_edks(ed2.allocator,
                                                   &ed1.edks.encrypted_data_keys,
                                                   &ed2.enc,
                                                   ed2.data_key_id,
                                                   ed2.key_provider));
    TEST_ASSERT_SUCCESS(t_append_c_str_key_to_edks(ed3.allocator,
                                                   &ed1.edks.encrypted_data_keys,
                                                   &ed3.enc,
                                                   ed3.data_key_id,
                                                   ed3.key_provider));

    size_t num_elems = aws_array_list_length(&ed1.edks.encrypted_data_keys);
    TEST_ASSERT_INT_EQ(3, num_elems);
    struct aws_cryptosdk_edk *edk;
    TEST_ASSERT_INT_EQ(0, aws_array_list_get_at_ptr(&ed1.edks.encrypted_data_keys, (void **) &edk, 0));
    TEST_ASSERT_SUCCESS(t_assert_edk_contains_expected_values(edk,
                                                              ed1.enc_data,
                                                              ed1.data_key_id,
                                                              ed1.key_provider,
                                                              ed1.allocator));
    TEST_ASSERT_INT_EQ(0, aws_array_list_get_at_ptr(&ed1.edks.encrypted_data_keys, (void **) &edk, 1));
    TEST_ASSERT_SUCCESS(t_assert_edk_contains_expected_values(edk,
                                                              ed2.enc_data,
                                                              ed2.data_key_id,
                                                              ed2.key_provider,
                                                              ed2.allocator));
    TEST_ASSERT_INT_EQ(0, aws_array_list_get_at_ptr(&ed1.edks.encrypted_data_keys, (void **) &edk, 2));
    TEST_ASSERT_SUCCESS(t_assert_edk_contains_expected_values(edk,
                                                              ed3.enc_data,
                                                              ed3.data_key_id,
                                                              ed3.key_provider,
                                                              ed3.allocator));

    return 0;
}

int parseRegionFromKmsKeyArn_validKeyArn_returnsRegion() {
    Aws::String key_arn1 = "arn:aws:kms:us-west-1:658956600833:key/b3537ef1-d8dc-4780-9f5a-55776cbb2f7f";
    Aws::String key_arn2 = "arn:xxx:kms:us-west-2:658956600833:key/b3537ef1-d8dc-4780-9f5a-55776cbb2f7f";
    Aws::String key_arn3 = "arn::kms:us-west-3:658956600833:key/b3537ef1-d8dc-4780-9f5a-55776cbb2f7f";
    Aws::String key_arn4 = "arn::kms:us-west-4:1";
    TEST_ASSERT(parse_region_from_kms_key_arn(key_arn1) == Aws::String("us-west-1"));
    TEST_ASSERT(parse_region_from_kms_key_arn(key_arn2) == Aws::String("us-west-2"));
    TEST_ASSERT(parse_region_from_kms_key_arn(key_arn3) == Aws::String("us-west-3"));
    TEST_ASSERT(parse_region_from_kms_key_arn(key_arn4) == Aws::String("us-west-4"));
    return 0;
}

int parseRegionFromKmsKeyArn_invalidKeyArn_returnsEmpty() {
    Aws::String empty;

    TEST_ASSERT(
        parse_region_from_kms_key_arn("arN:aws:kms:us-west-2:658956600833:key/b3537ef1-d8dc-4780-9f5a-55776cbb2f7f")
            == empty);

    TEST_ASSERT(
        parse_region_from_kms_key_arn(":aws:kms:us-west-2:658956600833:key/b3537ef1-d8dc-4780-9f5a-55776cbb2f7f")
            == empty);

    TEST_ASSERT(
        parse_region_from_kms_key_arn("arn:aws:kms2:us-west-2:658956600833:key/b3537ef1-d8dc-4780-9f5a-55776cbb2f7f")
            == empty);

    TEST_ASSERT(
        parse_region_from_kms_key_arn("arn:aws:kms::658956600833:key/b3537ef1-d8dc-4780-9f5a-55776cbb2f7f")
            == empty);

    TEST_ASSERT(
        parse_region_from_kms_key_arn(":arn:aws:kms:us-west-1:658956600833:key/b3537ef1-d8dc-4780-9f5a-55776cbb2f7f")
            == empty);

    TEST_ASSERT(parse_region_from_kms_key_arn(":::us-west-2:") == empty);
    TEST_ASSERT(parse_region_from_kms_key_arn("") == empty);
    TEST_ASSERT(parse_region_from_kms_key_arn("arn:aws:kms:") == empty);
    TEST_ASSERT(parse_region_from_kms_key_arn("arn:aws:") == empty);
    TEST_ASSERT(parse_region_from_kms_key_arn("arn:") == empty);
    TEST_ASSERT(parse_region_from_kms_key_arn(":") == empty);
    TEST_ASSERT(parse_region_from_kms_key_arn("arn") == empty);

    // although we can theoretically extract region ARN still is invalid
    TEST_ASSERT(parse_region_from_kms_key_arn("arn:aws:kms:us-west-3") == empty);


    return 0;
}

int main() {
    RUN_TEST(awsStringFromCAwsByteBuf_validInputs_returnAwsString());
    RUN_TEST(awsUtilsByteBufferFromCAwsByteBuf_validInputs_returnAwsUtils());
    RUN_TEST(appendKeyToEdks_appendSingleElement_elementIsAppended());
    RUN_TEST(appendKeyToEdks_allocatorThatDoesNotAllocateMemory_returnsOomError());
    RUN_TEST(appendKeyToEdks_multipleElementsAppended_elementsAreAppended());
    RUN_TEST(awsStringFromCAwsString_validInputs_returnAwsString());
    RUN_TEST(awsMapFromCAwsHashHable_hashMap_returnAwsMap());
    RUN_TEST(awsByteBufDupFromAwsUtils_validInputs_returnNewAwsByteBuf());
    RUN_TEST(parseRegionFromKmsKeyArn_validKeyArn_returnsRegion());
    RUN_TEST(parseRegionFromKmsKeyArn_invalidKeyArn_returnsEmpty());
}
