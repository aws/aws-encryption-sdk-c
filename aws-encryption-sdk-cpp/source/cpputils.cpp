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

#include <aws/common/byte_buf.h>
#include <aws/common/hash_table.h>
#include <aws/core/utils/ARN.h>
#include <aws/core/utils/StringUtils.h>
#include <aws/cryptosdk/error.h>
#include <aws/cryptosdk/materials.h>

namespace Aws {
namespace Cryptosdk {
namespace Private {

static const Aws::String KMS_STR = "kms";
static const Aws::String MRK_STR = "mrk-";

Aws::String aws_string_from_c_aws_byte_buf(const struct aws_byte_buf *byte_buf) {
    return Aws::String(reinterpret_cast<const char *>(byte_buf->buffer), byte_buf->len);
}

Aws::Utils::ByteBuffer aws_utils_byte_buffer_from_c_aws_byte_buf(const struct aws_byte_buf *byte_buf) {
    return Aws::Utils::ByteBuffer(byte_buf->buffer, byte_buf->len);
}

Aws::String aws_string_from_c_aws_string(const struct aws_string *c_aws_string) {
    return Aws::String(reinterpret_cast<const char *>(aws_string_bytes(c_aws_string)), c_aws_string->len);
}

int aws_byte_buf_dup_from_aws_utils(
    struct aws_allocator *allocator, struct aws_byte_buf *dest, const Aws::Utils::ByteBuffer &src) {
    struct aws_byte_buf data_key_bb = aws_byte_buf_from_array(src.GetUnderlyingData(), src.GetLength());
    return aws_byte_buf_init_copy(dest, allocator, &data_key_bb);
}

Aws::Map<Aws::String, Aws::String> aws_map_from_c_aws_hash_table(const struct aws_hash_table *hash_table) {
    Aws::Map<Aws::String, Aws::String> result;

    if (hash_table == NULL) {
        return result;
    }

    for (struct aws_hash_iter iter = aws_hash_iter_begin(hash_table); !aws_hash_iter_done(&iter);
         aws_hash_iter_next(&iter)) {
        const struct aws_string *key              = (struct aws_string *)iter.element.key;
        const struct aws_string *value            = (struct aws_string *)iter.element.value;
        result[aws_string_from_c_aws_string(key)] = aws_string_from_c_aws_string(value);
    }

    return result;
}

int append_aws_byte_buf_key_dup_to_edks(
    struct aws_allocator *allocator,
    struct aws_array_list *encrypted_data_keys,
    const struct aws_byte_buf *encrypted_data_key,
    const struct aws_byte_buf *data_key_id,
    const struct aws_byte_buf *key_provider) {
    struct aws_cryptosdk_edk edk {};
    edk.provider_id   = { 0 };
    edk.provider_info = { 0 };
    edk.ciphertext    = { 0 };

    if (aws_byte_buf_init_copy(&edk.provider_id, allocator, key_provider) != AWS_OP_SUCCESS ||
        aws_byte_buf_init_copy(&edk.provider_info, allocator, data_key_id) != AWS_OP_SUCCESS ||
        aws_byte_buf_init_copy(&edk.ciphertext, allocator, encrypted_data_key) != AWS_OP_SUCCESS ||
        aws_array_list_push_back(encrypted_data_keys, &edk) != AWS_OP_SUCCESS) {
        aws_cryptosdk_edk_clean_up(&edk);
        return AWS_OP_ERR;
    }

    return AWS_OP_SUCCESS;
}

int append_key_dup_to_edks(
    struct aws_allocator *allocator,
    struct aws_array_list *encrypted_data_keys,
    const Utils::ByteBuffer *encrypted_data_key,
    const Aws::String *data_key_id,
    const struct aws_byte_buf *key_provider) {
    // although this functions will not copy, append_aws_byte_buf_key_dup_to_edks will create a duplicate
    // of enc_data_key_byte, data_key_id_byte and key_provider before appending them
    struct aws_byte_buf enc_data_key_byte =
        aws_byte_buf_from_array(encrypted_data_key->GetUnderlyingData(), encrypted_data_key->GetLength());
    struct aws_byte_buf data_key_id_byte =
        aws_byte_buf_from_array((const uint8_t *)data_key_id->data(), data_key_id->length());

    return append_aws_byte_buf_key_dup_to_edks(
        allocator, encrypted_data_keys, &enc_data_key_byte, &data_key_id_byte, key_provider);
}
/**
 * Compares an aws_byte_buf (byte_buf_b) with a sequence of characters (char_buf_a)
 * @param char_buf_a Sequence of characters
 * @param a_idx_start Start position in char_buf_a
 * @param a_idx_end End position in char_buf_a
 * @param byte_buf_b aws_byte_buf to compare with
 * @return true if the sequence of characters in char_buf_a+idx_start matches the byte_buf_b, false otherwise
 */
inline static bool aws_byte_buf_eq_char_array(
    const char *char_buf_a, size_t a_idx_start, size_t a_idx_end, const struct aws_byte_buf &byte_buf_b) {
    if (a_idx_end == std::string::npos || a_idx_start == std::string::npos || char_buf_a == NULL) {
        return false;
    }

    const struct aws_byte_buf byte_buf_a =
        aws_byte_buf_from_array((uint8_t *)(char_buf_a + a_idx_start), a_idx_end - a_idx_start);
    return aws_byte_buf_eq(&byte_buf_a, &byte_buf_b);
}

Aws::String parse_region_from_kms_key_arn(const Aws::String &key_id) {
    static const struct aws_byte_buf arn_str = aws_byte_buf_from_c_str("arn");
    static const struct aws_byte_buf kms_str = aws_byte_buf_from_c_str("kms");
    Aws::String rv;
    size_t idx_start = 0;
    size_t idx_end   = 0;
    // first group is "arn"
    idx_end = key_id.find(':', idx_start);
    if (aws_byte_buf_eq_char_array(key_id.data(), idx_start, idx_end, arn_str) == false) {
        return rv;
    }
    idx_start = idx_end + 1;

    // second group is "aws" but can vary
    idx_end = key_id.find(':', idx_start);
    if (idx_end == std::string::npos) {
        return rv;
    }
    idx_start = idx_end + 1;

    // third group is "kms"
    idx_end = key_id.find(':', idx_start);
    if (aws_byte_buf_eq_char_array(key_id.data(), idx_start, idx_end, kms_str) == false) {
        return rv;
    }
    idx_start = idx_end + 1;

    // forth group is region
    idx_end = key_id.find(':', idx_start);
    if (idx_end == std::string::npos || idx_start >= idx_end) {
        return rv;
    }
    return Aws::String(key_id.data() + idx_start, idx_end - idx_start);
}

/**
 * Returns a vector containing the substrings before and after the first '/'
 * character in the given string, or an empty vector if the string does not
 * contain a '/' character.
 */
static Aws::Vector<Aws::String> split_arn_resource(const Aws::String &resource) {
    auto parts = Utils::StringUtils::Split(resource, '/', 2);
    if (parts.size() != 2) {
        parts.clear();
    }
    return parts;
}

/**
 * Returns true if the first string starts with the second string, or false
 * otherwise.
 */
bool starts_with(const Aws::String &s1, const Aws::String &s2) {
    return s1.size() >= s2.size() && s1.compare(0, s2.size(), s2) == 0;
}

bool is_valid_kms_key_arn(const Aws::Utils::ARN &key_arn) {
    if (!(
            //= compliance/framework/aws-kms/aws-kms-key-arn.txt#2.5
            //# MUST start with string "arn"
            bool(key_arn)
            //= compliance/framework/aws-kms/aws-kms-key-arn.txt#2.5
            //# The partition MUST be a non-empty
            && key_arn.GetPartition().size() > 0
            //= compliance/framework/aws-kms/aws-kms-key-arn.txt#2.5
            //# The service MUST be the string "kms"
            && key_arn.GetService() == "kms"
            //= compliance/framework/aws-kms/aws-kms-key-arn.txt#2.5
            //# The region MUST be a non-empty string
            && key_arn.GetRegion().size() > 0
            //= compliance/framework/aws-kms/aws-kms-key-arn.txt#2.5
            //# The account MUST be a non-empty string
            && key_arn.GetAccountId().size() > 0
            //= compliance/framework/aws-kms/aws-kms-key-arn.txt#2.5
            //# The resource section MUST be non-empty and MUST be split by a
            //# single "/" any additional "/" are included in the resource id
            && key_arn.GetResource().size() > 0)) {
        return false;
    }

    const auto resource_parts = split_arn_resource(key_arn.GetResource());
    return resource_parts.size() == 2
           //= compliance/framework/aws-kms/aws-kms-key-arn.txt#2.5
           //# The resource type MUST be either "alias" or "key"
           && (resource_parts[0] == "alias" || resource_parts[0] == "key")
           //= compliance/framework/aws-kms/aws-kms-key-arn.txt#2.5
           //# The resource id MUST be a non-empty string
           && resource_parts[1].size() > 0;
}

bool is_valid_kms_identifier(const Aws::String &ident) {
    // Precondition: A KMS key ARN is a valid KMS key identifier.
    Aws::Utils::ARN arn(ident);
    if (is_valid_kms_key_arn(arn)) {
        return true;
    }

    // Precondition: A non-ARN identifier cannot contain a colon.
    if (ident.find(':') != std::string::npos) {
        return false;
    }

    // Precondition: A KMS key identifier with a forward slash must be an alias
    if (ident.find('/') != std::string::npos) {
        return starts_with(ident, "alias/");
    }

    // Anything else must be a raw key ID
    return true;
}

//= compliance/framework/aws-kms/aws-kms-key-arn.txt#2.8
//# This function MUST take a single AWS KMS ARN
bool is_kms_mrk_arn(const Aws::Utils::ARN &key_arn) {
    //= compliance/framework/aws-kms/aws-kms-key-arn.txt#2.8
    //# If the input is an invalid AWS KMS ARN this function MUST error.
    if (!is_valid_kms_key_arn(key_arn)) {
        return false;
    }

    const auto resource_parts = split_arn_resource(key_arn.GetResource());
    //= compliance/framework/aws-kms/aws-kms-key-arn.txt#2.8
    //# If resource type is "alias", this is an AWS KMS alias ARN and MUST
    //# return false.
    if (resource_parts[0] == "alias") {
        return false;
    }
    //= compliance/framework/aws-kms/aws-kms-key-arn.txt#2.8
    //# If resource type is "key" and resource ID starts with
    //# "mrk-", this is a AWS KMS multi-Region key ARN and MUST return true.
    if (resource_parts[0] == "key") {
        return starts_with(resource_parts[1], MRK_STR);
    }
    //= compliance/framework/aws-kms/aws-kms-key-arn.txt#2.8
    //# If resource type is "key" and resource ID does not start with "mrk-",
    //# this is a (single-region) AWS KMS key ARN and MUST return false.
    return false;
}

//= compliance/framework/aws-kms/aws-kms-key-arn.txt#2.9
//# This function MUST take a single AWS KMS identifier
bool is_kms_mrk_identifier(const Aws::String &key_id) {
    static const Aws::String arn_str   = "arn:";
    static const Aws::String alias_str = "alias/";

    //= compliance/framework/aws-kms/aws-kms-key-arn.txt#2.9
    //# If the input starts with "arn:", this MUST return the output of
    //# identifying an an AWS KMS multi-Region ARN (aws-kms-key-
    //# arn.md#identifying-an-an-aws-kms-multi-region-arn) called with this
    //# input.
    if (starts_with(key_id, arn_str)) {
        Aws::Utils::ARN key_arn(key_id);
        return is_kms_mrk_arn(key_arn);
    }

    //= compliance/framework/aws-kms/aws-kms-key-arn.txt#2.9
    //# If the input starts with "alias/", this an AWS KMS alias and
    //# not a multi-Region key id and MUST return false.
    if (starts_with(key_id, alias_str)) {
        return false;
    }

    //= compliance/framework/aws-kms/aws-kms-key-arn.txt#2.9
    //# If the input starts
    //# with "mrk-", this is a multi-Region key id and MUST return true.
    if (starts_with(key_id, MRK_STR)) {
        return true;
    }

    //= compliance/framework/aws-kms/aws-kms-key-arn.txt#2.9
    //# If
    //# the input does not start with any of the above, this is not a multi-
    //# Region key id and MUST return false.
    return false;
}

//= compliance/framework/aws-kms/aws-kms-mrk-match-for-decrypt.txt#2.5
//# The caller MUST provide:
bool kms_mrk_match_for_decrypt(const Aws::String &key_id_1, const Aws::String &key_id_2) {
    //= compliance/framework/aws-kms/aws-kms-mrk-match-for-decrypt.txt#2.5
    //# If both identifiers are identical, this function MUST return "true".
    if (key_id_1 == key_id_2) return true;
    //= compliance/framework/aws-kms/aws-kms-mrk-match-for-decrypt.txt#2.5
    //# Otherwise if either input is not identified as a multi-Region key
    //# (aws-kms-key-arn.md#identifying-an-aws-kms-multi-region-key), then
    //# this function MUST return "false".
    if (!is_kms_mrk_identifier(key_id_1) || !is_kms_mrk_identifier(key_id_2)) return false;

    //= compliance/framework/aws-kms/aws-kms-mrk-match-for-decrypt.txt#2.5
    //# Otherwise if both inputs are
    //# identified as a multi-Region keys (aws-kms-key-arn.md#identifying-an-
    //# aws-kms-multi-region-key), this function MUST return the result of
    //# comparing the "partition", "service", "accountId", "resourceType",
    //# and "resource" parts of both ARN inputs.
    Aws::Utils::ARN key_arn_1(key_id_1);
    Aws::Utils::ARN key_arn_2(key_id_2);
    if (!key_arn_1 || !key_arn_2) return false;
    return (
        key_arn_1.GetPartition() == key_arn_2.GetPartition() && key_arn_1.GetService() == key_arn_2.GetService() &&
        key_arn_1.GetAccountId() == key_arn_2.GetAccountId() && key_arn_1.GetResource() == key_arn_2.GetResource());
}

//= compliance/framework/aws-kms/aws-kms-mrk-are-unique.txt#2.5
//# The caller MUST provide:
Aws::Vector<Aws::String> find_duplicate_kms_mrk_ids(const Aws::Vector<Aws::String> &key_ids) {
    Aws::Map<Aws::String, Aws::Vector<Aws::String>> mrk_resource_id_to_key_ids;
    for (auto key_id = key_ids.begin(); key_id != key_ids.end(); key_id++) {
        Aws::Utils::ARN key_arn(*key_id);
        if (is_kms_mrk_arn(key_arn)) {
            auto resource_type_and_id = split_arn_resource(key_arn.GetResource());
            mrk_resource_id_to_key_ids[resource_type_and_id[1]].push_back(*key_id);
        } else if (is_kms_mrk_identifier(*key_id)) {
            mrk_resource_id_to_key_ids[*key_id].push_back(*key_id);
        }
    }

    //= compliance/framework/aws-kms/aws-kms-mrk-are-unique.txt#2.5
    //# If the list does not contain any multi-Region keys (aws-kms-key-
    //# arn.md#identifying-an-aws-kms-multi-region-key) this function MUST
    //# exit successfully.
    Aws::Vector<Aws::String> duplicates;
    if (mrk_resource_id_to_key_ids.size() == 0) {
        return duplicates;
    }

    for (auto kv = mrk_resource_id_to_key_ids.begin(); kv != mrk_resource_id_to_key_ids.end(); kv++) {
        const auto resource_id      = kv->first;
        const auto matching_key_ids = kv->second;
        if (matching_key_ids.size() < 2) {
            continue;
        }
        for (auto duplicate = matching_key_ids.begin(); duplicate != matching_key_ids.end(); duplicate++) {
            duplicates.push_back(*duplicate);
        }
    }

    //= compliance/framework/aws-kms/aws-kms-mrk-are-unique.txt#2.5
    //# If there are zero duplicate resource ids between the multi-region
    //# keys, this function MUST exit successfully

    //= compliance/framework/aws-kms/aws-kms-mrk-are-unique.txt#2.5
    //# If any duplicate multi-region resource ids exist, this function MUST
    //# yield an error that includes all identifiers with duplicate resource
    //# ids not only the first duplicate found.
    return duplicates;
}

ListRaii::~ListRaii() {
    if (initialized) clean_up_fn(&list);
}

int ListRaii::Create(struct aws_allocator *alloc) {
    int rv = init_fn(alloc, &list);
    if (!rv) initialized = true;
    return rv;
}

}  // namespace Private
}  // namespace Cryptosdk
}  // namespace Aws
