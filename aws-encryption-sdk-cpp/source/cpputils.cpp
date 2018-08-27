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

int append_aws_byte_buf_key_to_edks(struct aws_allocator *allocator,
                                    struct aws_array_list *encrypted_data_keys,
                                    const struct aws_byte_buf *encrypted_data_key,
                                    const struct aws_byte_buf *data_key_id,
                                    const aws_byte_buf *key_provider) {
    struct aws_cryptosdk_edk edk{};
    edk.provider_id = {0};
    edk.provider_info = {0};
    edk.enc_data_key = {0};

    if (aws_byte_buf_init_copy(allocator, &edk.provider_id, key_provider) != AWS_OP_SUCCESS
        || aws_byte_buf_init_copy(allocator, &edk.provider_info, data_key_id) != AWS_OP_SUCCESS
        || aws_byte_buf_init_copy(allocator, &edk.enc_data_key, encrypted_data_key) != AWS_OP_SUCCESS
        || aws_array_list_push_back(encrypted_data_keys, &edk) != AWS_OP_SUCCESS) {
        aws_byte_buf_clean_up(&edk.provider_id);
        aws_byte_buf_clean_up(&edk.provider_info);
        aws_byte_buf_clean_up(&edk.enc_data_key);
        return AWS_OP_ERR;
    }

    return AWS_OP_SUCCESS;
}

int append_key_to_edks(struct aws_allocator *allocator,
                       struct aws_array_list *encrypted_data_keys,
                       const Utils::ByteBuffer *encrypted_data_key,
                       const Aws::String *data_key_id,
                       const aws_byte_buf *key_provider) {
    struct aws_byte_buf enc_data_key_byte = aws_byte_buf_from_array(encrypted_data_key->GetUnderlyingData(),
                                                                    encrypted_data_key->GetLength());
    struct aws_byte_buf data_key_id_byte = aws_byte_buf_from_array((const uint8_t *) data_key_id->data(),
                                                                   data_key_id->length());

    return append_aws_byte_buf_key_to_edks(allocator,
                                           encrypted_data_keys,
                                           &enc_data_key_byte,
                                           &data_key_id_byte,
                                           key_provider);
}
/**
 * Compares an aws_byte_buf (byte_buf_b) with a sequence of characters (char_buf_a)
 * @param char_buf_a Sequence of characters
 * @param idx_start Start position in char_buf_a
 * @param idx_end End position in char_buf_b
 * @param byte_buf_b aws_byte_buf to compare with
 * @return true if the sequence of characters in char_buf_a+idx_start matches the byte_buf_b, false otherwise
 */
inline bool aws_byte_buf_eq_char_array(const char *char_buf_a,
                                       size_t idx_start,
                                       size_t idx_end,
                                       const aws_byte_buf &byte_buf_b) {
    if (idx_end == std::string::npos || idx_start == std::string::npos || char_buf_a == NULL) {
        return false;
    }

    const aws_byte_buf byte_buf_a = aws_byte_buf_from_array((uint8_t *)(char_buf_a + idx_start), idx_end - idx_start);
    return aws_byte_buf_eq(&byte_buf_a, &byte_buf_b);
}

Aws::String parse_region_from_kms_key_arn(const Aws::String &key_id) {
    static const aws_byte_buf arn_str = aws_byte_buf_from_c_str("arn");
    static const aws_byte_buf kms_str = aws_byte_buf_from_c_str("kms");
    Aws::String rv;
    size_t idx_start = 0;
    size_t idx_end = 0;
    // first group is "arn"
    idx_end = key_id.find(':', idx_start);
    if (aws_byte_buf_eq_char_array(key_id.data(), idx_start, idx_end, arn_str) == false) {
        return rv;
    }
    idx_start = idx_end + 1;

    // second group is "aws" but can vary
    idx_end = key_id.find(':', idx_start);
    if (idx_end == std::string::npos) { return rv; }
    idx_start = idx_end + 1;

    // third group is "kms"
    idx_end = key_id.find(':', idx_start);
    if (aws_byte_buf_eq_char_array(key_id.data(), idx_start, idx_end, kms_str) == false) {
        return rv;
    }
    idx_start = idx_end + 1;

    // forth group is region
    idx_end = key_id.find(':', idx_start);
    if (idx_end == std::string::npos || idx_start >= idx_end) { return rv; }
    return Aws::String(key_id.data() + idx_start, idx_end - idx_start);
}

}  // namespace Private
}  // namespace Cryptosdk
}  // namespace Aws
