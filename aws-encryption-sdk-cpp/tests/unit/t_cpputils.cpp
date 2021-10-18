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

#include <aws/cryptosdk/enc_ctx.h>
#include <aws/cryptosdk/private/cpputils.h>

#include "edks_utils.h"
#include "testutil.h"

using namespace Aws::Cryptosdk::Private;
using namespace Aws::Cryptosdk::Testing;

const char *TEST_STRING = "Hello World!";

int awsStringFromCAwsByteBuf_validInputs_returnAwsString() {
    struct aws_byte_buf b = aws_byte_buf_from_c_str(TEST_STRING);
    Aws::String b_string  = aws_string_from_c_aws_byte_buf(&b);
    TEST_ASSERT(b_string == TEST_STRING);
    return 0;
}

int awsUtilsByteBufferFromCAwsByteBuf_validInputs_returnAwsUtils() {
    struct aws_byte_buf b         = aws_byte_buf_from_c_str(TEST_STRING);
    Aws::Utils::ByteBuffer b_util = aws_utils_byte_buffer_from_c_aws_byte_buf(&b);
    TEST_ASSERT(
        std::string(reinterpret_cast<const char *>(b_util.GetUnderlyingData()), b_util.GetLength()) == TEST_STRING);
    TEST_ASSERT_INT_EQ(b_util.GetLength(), strlen(TEST_STRING));
    return 0;
}

int awsStringFromCAwsString_validInputs_returnAwsString() {
    struct aws_allocator *allocator = aws_default_allocator();
    struct aws_string *b            = aws_string_new_from_c_str(allocator, TEST_STRING);
    Aws::String b_string            = aws_string_from_c_aws_string(b);
    TEST_ASSERT(b_string == TEST_STRING);
    aws_string_destroy(b);
    return 0;
}

int awsByteBufDupFromAwsUtils_validInputs_returnNewAwsByteBuf() {
    struct aws_allocator *allocator = aws_default_allocator();
    const Aws::Utils::ByteBuffer src((uint8_t *)TEST_STRING, strlen(TEST_STRING));
    struct aws_byte_buf dest;
    struct aws_byte_buf dest_expected = aws_byte_buf_from_c_str(TEST_STRING);
    TEST_ASSERT_SUCCESS(aws_byte_buf_dup_from_aws_utils(allocator, &dest, src));
    TEST_ASSERT(aws_byte_buf_eq(&dest, &dest_expected) == true);
    aws_byte_buf_clean_up(&dest);
    return 0;
}

int awsMapFromCAwsHashHable_hashMap_returnAwsMap() {
    const char *key1_c_chr   = "key1";
    const char *key2_c_chr   = "key2";
    const char *value1_c_chr = "value1";
    const char *value2_c_chr = "value2";

    struct aws_hash_table hash_table;
    struct aws_allocator *allocator = aws_default_allocator();

    const struct aws_string *key1   = aws_string_new_from_c_str(allocator, key1_c_chr);
    const struct aws_string *key2   = aws_string_new_from_c_str(allocator, key2_c_chr);
    const struct aws_string *value1 = aws_string_new_from_c_str(allocator, value1_c_chr);
    const struct aws_string *value2 = aws_string_new_from_c_str(allocator, value2_c_chr);

    struct aws_hash_element *p_elem;
    int was_created;

    TEST_ASSERT_SUCCESS(aws_cryptosdk_enc_ctx_init(allocator, &hash_table));

    TEST_ASSERT_SUCCESS(aws_hash_table_create(&hash_table, (void *)key1, &p_elem, &was_created));
    p_elem->value = (void *)value1;

    TEST_ASSERT_SUCCESS(aws_hash_table_create(&hash_table, (void *)key2, &p_elem, &was_created));
    p_elem->value = (void *)value2;

    Aws::Map<Aws::String, Aws::String> aws_map = aws_map_from_c_aws_hash_table(&hash_table);
    aws_cryptosdk_enc_ctx_clean_up(&hash_table);

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

    EdksTestData(
        const char *enc_data     = "ENC data",
        const char *data_key_id  = "data_key_id",
        const char *key_provider = "key-Provider")
        : enc_data(enc_data),
          data_key_id(data_key_id),
          key_provider(key_provider),
          edks(allocator),
          enc((uint8_t *)enc_data, strlen(enc_data)) {}
};

int appendKeyToEdks_appendSingleElement_elementIsAppended() {
    EdksTestData ed;
    TEST_ASSERT_SUCCESS(t_append_c_str_key_to_edks(
        ed.allocator, &ed.edks.encrypted_data_keys, &ed.enc, ed.data_key_id, ed.key_provider));
    TEST_ASSERT_SUCCESS(t_assert_edks_with_single_element_contains_expected_values(
        &ed.edks.encrypted_data_keys, ed.enc_data, ed.data_key_id, ed.key_provider, ed.allocator));

    return 0;
}

int appendKeyToEdks_multipleElementsAppended_elementsAreAppended() {
    EdksTestData ed1;
    EdksTestData ed2("enc2", "dk2", "kp2");
    EdksTestData ed3("enc3", "dk3", "kp3");

    // We append only to ed1.edks.encrypted_data_keys to test accumulation
    TEST_ASSERT_SUCCESS(t_append_c_str_key_to_edks(
        ed1.allocator, &ed1.edks.encrypted_data_keys, &ed1.enc, ed1.data_key_id, ed1.key_provider));
    TEST_ASSERT_SUCCESS(t_append_c_str_key_to_edks(
        ed2.allocator, &ed1.edks.encrypted_data_keys, &ed2.enc, ed2.data_key_id, ed2.key_provider));
    TEST_ASSERT_SUCCESS(t_append_c_str_key_to_edks(
        ed3.allocator, &ed1.edks.encrypted_data_keys, &ed3.enc, ed3.data_key_id, ed3.key_provider));

    size_t num_elems = aws_array_list_length(&ed1.edks.encrypted_data_keys);
    TEST_ASSERT_INT_EQ(3, num_elems);
    struct aws_cryptosdk_edk *edk;
    TEST_ASSERT_INT_EQ(0, aws_array_list_get_at_ptr(&ed1.edks.encrypted_data_keys, (void **)&edk, 0));
    TEST_ASSERT_SUCCESS(
        t_assert_edk_contains_expected_values(edk, ed1.enc_data, ed1.data_key_id, ed1.key_provider, ed1.allocator));
    TEST_ASSERT_INT_EQ(0, aws_array_list_get_at_ptr(&ed1.edks.encrypted_data_keys, (void **)&edk, 1));
    TEST_ASSERT_SUCCESS(
        t_assert_edk_contains_expected_values(edk, ed2.enc_data, ed2.data_key_id, ed2.key_provider, ed2.allocator));
    TEST_ASSERT_INT_EQ(0, aws_array_list_get_at_ptr(&ed1.edks.encrypted_data_keys, (void **)&edk, 2));
    TEST_ASSERT_SUCCESS(
        t_assert_edk_contains_expected_values(edk, ed3.enc_data, ed3.data_key_id, ed3.key_provider, ed3.allocator));

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
        parse_region_from_kms_key_arn("arN:aws:kms:us-west-2:658956600833:key/b3537ef1-d8dc-4780-9f5a-55776cbb2f7f") ==
        empty);

    TEST_ASSERT(
        parse_region_from_kms_key_arn(":aws:kms:us-west-2:658956600833:key/b3537ef1-d8dc-4780-9f5a-55776cbb2f7f") ==
        empty);

    TEST_ASSERT(
        parse_region_from_kms_key_arn("arn:aws:kms2:us-west-2:658956600833:key/b3537ef1-d8dc-4780-9f5a-55776cbb2f7f") ==
        empty);

    TEST_ASSERT(
        parse_region_from_kms_key_arn("arn:aws:kms::658956600833:key/b3537ef1-d8dc-4780-9f5a-55776cbb2f7f") == empty);

    TEST_ASSERT(
        parse_region_from_kms_key_arn(":arn:aws:kms:us-west-1:658956600833:key/b3537ef1-d8dc-4780-9f5a-55776cbb2f7f") ==
        empty);

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

int isKmsMrkArn_compliance() {
    //= compliance/framework/aws-kms/aws-kms-key-arn.txt#2.8
    //= type=test
    //# This function MUST take a single AWS KMS ARN

    //= compliance/framework/aws-kms/aws-kms-key-arn.txt#2.8
    //= type=test
    //# If the input is an invalid AWS KMS ARN this function MUST error.
    TEST_ASSERT(is_kms_mrk_arn(Aws::Utils::ARN("")) == false);

    //= compliance/framework/aws-kms/aws-kms-key-arn.txt#2.8
    //= type=test
    //# If resource type is "alias", this is an AWS KMS alias ARN and MUST
    //# return false.
    TEST_ASSERT(is_kms_mrk_arn(Aws::Utils::ARN("arn:aws:kms:us-east-1:2222222222222:alias/foobar")) == false);
    //= compliance/framework/aws-kms/aws-kms-key-arn.txt#2.8
    //= type=test
    //# If resource type is "key" and resource ID starts with
    //# "mrk-", this is a AWS KMS multi-Region key ARN and MUST return true.
    TEST_ASSERT(is_kms_mrk_arn(Aws::Utils::ARN("arn:aws:kms:us-east-1:2222222222222:key/mrk-foobar")) == true);
    //= compliance/framework/aws-kms/aws-kms-key-arn.txt#2.8
    //= type=test
    //# If resource type is "key" and resource ID does not start with "mrk-",
    //# this is a (single-region) AWS KMS key ARN and MUST return false.
    TEST_ASSERT(is_kms_mrk_arn(Aws::Utils::ARN("arn:aws:kms:us-east-1:2222222222222:key/foobar")) == false);

    return 0;
}

int isKmsMrkIdentifier_compliance() {
    //= compliance/framework/aws-kms/aws-kms-key-arn.txt#2.9
    //= type=test
    //# This function MUST take a single AWS KMS identifier

    //= compliance/framework/aws-kms/aws-kms-key-arn.txt#2.9
    //= type=test
    //# If the input starts with "arn:", this MUST return the output of
    //# identifying an an AWS KMS multi-Region ARN (aws-kms-key-
    //# arn.md#identifying-an-an-aws-kms-multi-region-arn) called with this
    //# input.
    TEST_ASSERT(is_kms_mrk_identifier("") == false);
    TEST_ASSERT(is_kms_mrk_identifier("arn:aws:kms:us-east-1:2222222222222:key/mrk-foobar") == true);

    //= compliance/framework/aws-kms/aws-kms-key-arn.txt#2.9
    //= type=test
    //# If the input starts with "alias/", this an AWS KMS alias and
    //# not a multi-Region key id and MUST return false.
    TEST_ASSERT(is_kms_mrk_identifier("alias/foobar") == false);

    //= compliance/framework/aws-kms/aws-kms-key-arn.txt#2.9
    //= type=test
    //# If the input starts
    //# with "mrk-", this is a multi-Region key id and MUST return true.
    TEST_ASSERT(is_kms_mrk_identifier("mrk-foobar") == true);

    //= compliance/framework/aws-kms/aws-kms-key-arn.txt#2.9
    //= type=test
    //# If
    //# the input does not start with any of the above, this is not a multi-
    //# Region key id and MUST return false.
    TEST_ASSERT(is_kms_mrk_identifier("srk-foobar") == false);

    return 0;
}

int isValidKmsKeyArn_validArn_returnsTrue() {
    TEST_ASSERT(
        is_valid_kms_key_arn(
            Aws::Utils::ARN("arn:aws:kms:us-east-1:2222222222222:key/1234abcd-12ab-34cd-56ef-1234567890ab")) == true);
    TEST_ASSERT(
        is_valid_kms_key_arn(Aws::Utils::ARN(
            "arn:fake-partition:kms:us-east-1:2222222222222:key/1234abcd-12ab-34cd-56ef-1234567890ab")) == true);
    TEST_ASSERT(
        is_valid_kms_key_arn(
            Aws::Utils::ARN("arn:aws:kms:fake-region:2222222222222:key/1234abcd-12ab-34cd-56ef-1234567890ab")) == true);
    TEST_ASSERT(
        is_valid_kms_key_arn(
            Aws::Utils::ARN("arn:aws:kms:us-east-1:fake-account:key/1234abcd-12ab-34cd-56ef-1234567890ab")) == true);
    TEST_ASSERT(
        is_valid_kms_key_arn(
            Aws::Utils::ARN("arn:aws:kms:us-east-1:2222222222222:alias/1234abcd-12ab-34cd-56ef-1234567890ab")) == true);
    TEST_ASSERT(is_valid_kms_key_arn(Aws::Utils::ARN("arn:aws:kms:us-east-1:2222222222222:key/fake-id")) == true);
    TEST_ASSERT(
        is_valid_kms_key_arn(Aws::Utils::ARN("arn:aws:kms:us-east-1:2222222222222:key/fake-id/with-forward-slash")) ==
        true);

    return 0;
}

int isValidKmsKeyArn_compliance() {
    //= compliance/framework/aws-kms/aws-kms-key-arn.txt#2.5
    //= type=test
    //# MUST start with string "arn"
    TEST_ASSERT(is_valid_kms_key_arn(Aws::Utils::ARN("")) == false);
    TEST_ASSERT(is_valid_kms_key_arn(Aws::Utils::ARN("not-arn")) == false);

    //= compliance/framework/aws-kms/aws-kms-key-arn.txt#2.5
    //= type=test
    //# The partition MUST be a non-empty
    TEST_ASSERT(
        is_valid_kms_key_arn(
            Aws::Utils::ARN("arn::kms:us-east-1:2222222222222:key/1234abcd-12ab-34cd-56ef-1234567890ab")) == false);

    //= compliance/framework/aws-kms/aws-kms-key-arn.txt#2.5
    //= type=test
    //# The service MUST be the string "kms"
    TEST_ASSERT(
        is_valid_kms_key_arn(Aws::Utils::ARN(
            "arn:aws:fake-service:us-east-1:2222222222222:key/1234abcd-12ab-34cd-56ef-1234567890ab")) == false);

    //= compliance/framework/aws-kms/aws-kms-key-arn.txt#2.5
    //= type=test
    //# The region MUST be a non-empty string
    TEST_ASSERT(
        is_valid_kms_key_arn(Aws::Utils::ARN("arn:aws:kms::2222222222222:key/1234abcd-12ab-34cd-56ef-1234567890ab")) ==
        false);

    //= compliance/framework/aws-kms/aws-kms-key-arn.txt#2.5
    //= type=test
    //# The account MUST be a non-empty string
    TEST_ASSERT(
        is_valid_kms_key_arn(Aws::Utils::ARN("arn:aws:kms:us-east-1::key/1234abcd-12ab-34cd-56ef-1234567890ab")) ==
        false);

    //= compliance/framework/aws-kms/aws-kms-key-arn.txt#2.5
    //= type=test
    //# The resource section MUST be non-empty and MUST be split by a
    //# single "/" any additional "/" are included in the resource id
    TEST_ASSERT(is_valid_kms_key_arn(Aws::Utils::ARN("arn:aws:kms:us-east-1:2222222222222:")) == false);
    TEST_ASSERT(
        is_valid_kms_key_arn(
            Aws::Utils::ARN("arn:aws:kms:us-east-1:2222222222222:key:1234abcd-12ab-34cd-56ef-1234567890ab")) == false);
    TEST_ASSERT(is_valid_kms_key_arn(Aws::Utils::ARN("arn:aws:kms:us-east-1:2222222222222:key")) == false);

    //= compliance/framework/aws-kms/aws-kms-key-arn.txt#2.5
    //= type=test
    //# The resource type MUST be either "alias" or "key"
    TEST_ASSERT(
        is_valid_kms_key_arn(Aws::Utils::ARN(
            "arn:aws:kms:us-east-1:2222222222222:fake-resource-type/1234abcd-12ab-34cd-56ef-1234567890ab")) == false);

    //= compliance/framework/aws-kms/aws-kms-key-arn.txt#2.5
    //= type=test
    //# The resource id MUST be a non-empty string
    TEST_ASSERT(is_valid_kms_key_arn(Aws::Utils::ARN("arn:aws:kms:us-east-1:2222222222222:key/")) == false);

    return 0;
}

int isValidKmsIdentifier_validIdentifier_returnsTrue() {
    // Precondition: A KMS key ARN is a valid KMS key identifier.
    TEST_ASSERT(
        is_valid_kms_identifier("arn:aws:kms:us-east-1:2222222222222:key/1234abcd-12ab-34cd-56ef-1234567890ab"));

    TEST_ASSERT(is_valid_kms_identifier("alias/foobar"));

    TEST_ASSERT(is_valid_kms_identifier("1234abcd-12ab-34cd-56ef-1234567890ab"));

    return 0;
}

int isValidKmsIdentifier_invalidIdentifier_returnsFalse() {
    // Precondition: A non-ARN identifier cannot contain a colon.
    TEST_ASSERT(is_valid_kms_identifier("1234abcd:12ab-34cd-56ef-1234567890ab") == false);

    // Precondition: A KMS key identifier with a forward slash must be an alias
    TEST_ASSERT(is_valid_kms_identifier("1234abcd/12ab-34cd-56ef-1234567890ab") == false);

    return 0;
}

int kmsMrkMatchForDecrypt_compliance() {
    //= compliance/framework/aws-kms/aws-kms-mrk-match-for-decrypt.txt#2.5
    //= type=test
    //# The caller MUST provide:

    //= compliance/framework/aws-kms/aws-kms-mrk-match-for-decrypt.txt#2.5
    //= type=test
    //# If both identifiers are identical, this function MUST return "true".
    TEST_ASSERT(kms_mrk_match_for_decrypt("raw-key-id", "raw-key-id") == true);
    TEST_ASSERT(
        kms_mrk_match_for_decrypt(
            "arn:aws:kms:us-east-1:2222222222222:key/1234abcd-12ab-34cd-56ef-1234567890ab",
            "arn:aws:kms:us-east-1:2222222222222:key/1234abcd-12ab-34cd-56ef-1234567890ab") == true);
    TEST_ASSERT(
        kms_mrk_match_for_decrypt(
            "arn:aws:kms:us-east-1:2222222222222:key/mrk-1234abcd-12ab-34cd-56ef-1234567890ab",
            "arn:aws:kms:us-east-1:2222222222222:key/mrk-1234abcd-12ab-34cd-56ef-1234567890ab") == true);

    //= compliance/framework/aws-kms/aws-kms-mrk-match-for-decrypt.txt#2.5
    //= type=test
    //# Otherwise if either input is not identified as a multi-Region key
    //# (aws-kms-key-arn.md#identifying-an-aws-kms-multi-region-key), then
    //# this function MUST return "false".
    TEST_ASSERT(kms_mrk_match_for_decrypt("raw-key-id", "different-raw-key-id") == false);

    //= compliance/framework/aws-kms/aws-kms-mrk-match-for-decrypt.txt#2.5
    //= type=test
    //# Otherwise if both inputs are
    //# identified as a multi-Region keys (aws-kms-key-arn.md#identifying-an-
    //# aws-kms-multi-region-key), this function MUST return the result of
    //# comparing the "partition", "service", "accountId", "resourceType",
    //# and "resource" parts of both ARN inputs.
    TEST_ASSERT(
        kms_mrk_match_for_decrypt(
            "arn:aws:kms:us-east-1:2222222222222:key/mrk-1234abcd-12ab-34cd-56ef-1234567890ab",
            "arn:aws:kms:us-west-1:2222222222222:key/mrk-1234abcd-12ab-34cd-56ef-1234567890ab") == true);
    TEST_ASSERT(
        kms_mrk_match_for_decrypt(
            "arn:partition-1:kms:us-east-1:2222222222222:key/1234abcd-12ab-34cd-56ef-1234567890ab",
            "arn:partition-2:kms:us-east-1:2222222222222:key/1234abcd-12ab-34cd-56ef-1234567890ab") == false);
    TEST_ASSERT(
        kms_mrk_match_for_decrypt(
            "arn:aws:service-1:us-east-1:2222222222222:key/1234abcd-12ab-34cd-56ef-1234567890ab",
            "arn:aws:service-2:us-east-1:2222222222222:key/1234abcd-12ab-34cd-56ef-1234567890ab") == false);
    TEST_ASSERT(
        kms_mrk_match_for_decrypt(
            "arn:aws:kms:us-east-1:account-1:key/1234abcd-12ab-34cd-56ef-1234567890ab",
            "arn:aws:kms:us-east-1:account-2:key/1234abcd-12ab-34cd-56ef-1234567890ab") == false);
    TEST_ASSERT(
        kms_mrk_match_for_decrypt(
            "arn:aws:kms:us-east-1:2222222222222:resource-type-1/1234abcd-12ab-34cd-56ef-1234567890ab",
            "arn:aws:kms:us-east-1:2222222222222:resource-type-2/1234abcd-12ab-34cd-56ef-1234567890ab") == false);
    TEST_ASSERT(
        kms_mrk_match_for_decrypt(
            "arn:aws:kms:us-east-1:2222222222222:key/resource-id-1",
            "arn:aws:kms:us-east-1:2222222222222:key/resource-id-2") == false);

    return 0;
}

int findDuplicateKmsMrkIds_compliance() {
    //= compliance/framework/aws-kms/aws-kms-mrk-are-unique.txt#2.5
    //= type=test
    //# The caller MUST provide:

    //= compliance/framework/aws-kms/aws-kms-mrk-are-unique.txt#2.5
    //= type=test
    //# If the list does not contain any multi-Region keys (aws-kms-key-
    //# arn.md#identifying-an-aws-kms-multi-region-key) this function MUST
    //# exit successfully.
    Aws::Vector<Aws::String> no_mrks = { "alias/foobar",
                                         "arn:aws:kms:us-east-1:2222222222222:alias/foobar"
                                         "key-foobar",
                                         "arn:aws:kms:us-east-1:2222222222222:key/key-foobar" };
    TEST_ASSERT(find_duplicate_kms_mrk_ids(no_mrks).size() == 0);

    //= compliance/framework/aws-kms/aws-kms-mrk-are-unique.txt#2.5
    //= type=test
    //# If there are zero duplicate resource ids between the multi-region
    //# keys, this function MUST exit successfully
    Aws::Vector<Aws::String> mrks_without_duplicates = { "mrk-id-1",
                                                         "mrk-id-2",
                                                         "arn:aws:kms:us-east-1:2222222222222:key/mrk-id-3",
                                                         "arn:aws:kms:us-east-1:2222222222222:key/mrk-id-4" };
    TEST_ASSERT(find_duplicate_kms_mrk_ids(mrks_without_duplicates).size() == 0);

    //= compliance/framework/aws-kms/aws-kms-mrk-are-unique.txt#2.5
    //= type=test
    //# If any duplicate multi-region resource ids exist, this function MUST
    //# yield an error that includes all identifiers with duplicate resource
    //# ids not only the first duplicate found.
    Aws::Vector<Aws::String> mrks_with_duplicates = {
        "mrk-id-1",
        "mrk-id-foo",
        "arn:aws:kms:us-east-1:2222222222222:key/mrk-id-1",
        "arn:aws:kms:us-east-1:2222222222222:key/mrk-id-2",
        "arn:aws:kms:us-west-1:2222222222222:key/mrk-id-2",
        "arn:aws:kms:us-east-1:2222222222222:key/mrk-id-bar",
    };
    Aws::Vector<Aws::String> expected = {
        "mrk-id-1",
        "arn:aws:kms:us-east-1:2222222222222:key/mrk-id-1",
        "arn:aws:kms:us-east-1:2222222222222:key/mrk-id-2",
        "arn:aws:kms:us-west-1:2222222222222:key/mrk-id-2",
    };
    TEST_ASSERT(find_duplicate_kms_mrk_ids(mrks_with_duplicates) == expected);

    return 0;
}

int main() {
    RUN_TEST(awsStringFromCAwsByteBuf_validInputs_returnAwsString());
    RUN_TEST(awsUtilsByteBufferFromCAwsByteBuf_validInputs_returnAwsUtils());
    RUN_TEST(appendKeyToEdks_appendSingleElement_elementIsAppended());
    RUN_TEST(appendKeyToEdks_multipleElementsAppended_elementsAreAppended());
    RUN_TEST(awsStringFromCAwsString_validInputs_returnAwsString());
    RUN_TEST(awsMapFromCAwsHashHable_hashMap_returnAwsMap());
    RUN_TEST(awsByteBufDupFromAwsUtils_validInputs_returnNewAwsByteBuf());
    RUN_TEST(parseRegionFromKmsKeyArn_validKeyArn_returnsRegion());
    RUN_TEST(parseRegionFromKmsKeyArn_invalidKeyArn_returnsEmpty());
    RUN_TEST(isKmsMrkArn_compliance());
    RUN_TEST(isKmsMrkIdentifier_compliance());
    RUN_TEST(isValidKmsKeyArn_validArn_returnsTrue());
    RUN_TEST(isValidKmsKeyArn_compliance());
    RUN_TEST(isValidKmsIdentifier_validIdentifier_returnsTrue());
    RUN_TEST(isValidKmsIdentifier_invalidIdentifier_returnsFalse());
    RUN_TEST(kmsMrkMatchForDecrypt_compliance());
    RUN_TEST(findDuplicateKmsMrkIds_compliance());
}
