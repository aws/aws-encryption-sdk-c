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
#include <aws/cryptosdk/error.h>
#include <aws/cryptosdk/materials.h>
#include <regex>

namespace Aws {
namespace Cryptosdk {
namespace Private {

Aws::String aws_string_from_c_aws_byte_buf(const struct aws_byte_buf *byte_buf) {
    return Aws::String(reinterpret_cast<const char *>(byte_buf->buffer), byte_buf->len);
}

Aws::Utils::ByteBuffer aws_utils_byte_buffer_from_c_aws_byte_buf(const struct aws_byte_buf *byte_buf) {
    return Aws::Utils::ByteBuffer(byte_buf->buffer, byte_buf->len);
}

Aws::String aws_string_from_c_aws_string(const struct aws_string *c_aws_string) {
    return Aws::String(reinterpret_cast<const char *>(aws_string_bytes(c_aws_string)), c_aws_string->len);
}

int aws_byte_buf_dup_from_aws_utils(struct aws_allocator *allocator,
                                    struct aws_byte_buf *dest,
                                    const Aws::Utils::ByteBuffer &src) {
    struct aws_byte_buf data_key_bb = aws_byte_buf_from_array(src.GetUnderlyingData(), src.GetLength());
    return aws_byte_buf_init_copy(allocator, dest, &data_key_bb);
}

Aws::Map<Aws::String, Aws::String> aws_map_from_c_aws_hash_table(const struct aws_hash_table *hash_table) {
    Aws::Map<Aws::String, Aws::String> result;

    if (hash_table == NULL) {
        return result;
    }

    for (struct aws_hash_iter iter = aws_hash_iter_begin(hash_table); !aws_hash_iter_done(&iter);
         aws_hash_iter_next(&iter)) {
        const struct aws_string *key = (struct aws_string *) iter.element.key;
        const struct aws_string *value = (struct aws_string *) iter.element.value;
        result[aws_string_from_c_aws_string(key)] = aws_string_from_c_aws_string(value);
    }

    return result;
}

int append_aws_byte_buf_key_dup_to_edks(struct aws_allocator *allocator,
                                        struct aws_array_list *encrypted_data_keys,
                                        const struct aws_byte_buf *encrypted_data_key,
                                        const struct aws_byte_buf *data_key_id,
                                        const struct aws_byte_buf *key_provider) {
    struct aws_cryptosdk_edk edk{};
    edk.provider_id = {0};
    edk.provider_info = {0};
    edk.enc_data_key = {0};

    if (aws_byte_buf_init_copy(allocator, &edk.provider_id, key_provider) != AWS_OP_SUCCESS
        || aws_byte_buf_init_copy(allocator, &edk.provider_info, data_key_id) != AWS_OP_SUCCESS
        || aws_byte_buf_init_copy(allocator, &edk.enc_data_key, encrypted_data_key) != AWS_OP_SUCCESS
        || aws_array_list_push_back(encrypted_data_keys, &edk) != AWS_OP_SUCCESS) {
        aws_cryptosdk_edk_clean_up(&edk);
        return AWS_OP_ERR;
    }

    return AWS_OP_SUCCESS;
}

int append_key_dup_to_edks(struct aws_allocator *allocator,
                           struct aws_array_list *encrypted_data_keys,
                           const Utils::ByteBuffer *encrypted_data_key,
                           const Aws::String *data_key_id,
                           const struct aws_byte_buf *key_provider) {
    // although this functions will not copy, append_aws_byte_buf_key_dup_to_edks will create a duplicate
    // of enc_data_key_byte, data_key_id_byte and key_provider before appending them
    struct aws_byte_buf enc_data_key_byte = aws_byte_buf_from_array(encrypted_data_key->GetUnderlyingData(),
                                                                    encrypted_data_key->GetLength());
    struct aws_byte_buf data_key_id_byte = aws_byte_buf_from_array((const uint8_t *) data_key_id->data(),
                                                                   data_key_id->length());

    return append_aws_byte_buf_key_dup_to_edks(allocator,
                                               encrypted_data_keys,
                                               &enc_data_key_byte,
                                               &data_key_id_byte,
                                               key_provider);
}
/**
 * Compares an aws_byte_buf (byte_buf_b) with a sequence of characters (char_buf_a)
 * @param char_buf_a Sequence of characters
 * @param a_idx_start Start position in char_buf_a
 * @param a_idx_end End position in char_buf_a
 * @param byte_buf_b aws_byte_buf to compare with
 * @return true if the sequence of characters in char_buf_a+idx_start matches the byte_buf_b, false otherwise
 */
inline static bool aws_byte_buf_eq_char_array(const char *char_buf_a,
                                       size_t a_idx_start,
                                       size_t a_idx_end,
                                       const struct aws_byte_buf &byte_buf_b) {
    if (a_idx_end == std::string::npos || a_idx_start == std::string::npos || char_buf_a == NULL) {
        return false;
    }

    const struct aws_byte_buf byte_buf_a = aws_byte_buf_from_array((uint8_t *)(char_buf_a + a_idx_start),
                                                            a_idx_end - a_idx_start);
    return aws_byte_buf_eq(&byte_buf_a, &byte_buf_b);
}

Aws::String parse_region_from_kms_key_arn(const Aws::String &key_id) {
    // KMS alias may use alphanumeric characters, hyphens, forward slashes, and underscores only
    std::regex arn("arn:([-a-z0-9]+):kms:([-a-z0-9]+):[0-9]+:(key|alias)/[-/_A-Za-z0-9]+");
    std::cmatch match_results;

    if (std::regex_match(key_id.c_str(), match_results, arn)) {
        Aws::String region(match_results[2].first, match_results[2].second);
        return region;
    } else {
        Aws::String empty_str;
        return empty_str;
    }
}

}  // namespace Private
}  // namespace Cryptosdk
}  // namespace Aws
