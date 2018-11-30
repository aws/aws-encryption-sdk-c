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

#ifndef AWS_ENCRYPTION_SDK_CPPUTILS_H
#define AWS_ENCRYPTION_SDK_CPPUTILS_H

#include <aws/common/byte_buf.h>
#include <aws/common/hash_table.h>
#include <aws/common/string.h>
#include <aws/core/utils/Array.h>
#include <aws/core/utils/memory/stl/AWSMap.h>
#include <aws/core/utils/memory/stl/AWSString.h>

namespace Aws {
namespace Cryptosdk {
namespace Private {

/**
 * Creates a new Aws::String from byte_buf
 */
Aws::String aws_string_from_c_aws_byte_buf(const struct aws_byte_buf *byte_buf);

/**
 * Creates a new Aws::Utils::ByteBuffer from a byte_buff
 */
Aws::Utils::ByteBuffer aws_utils_byte_buffer_from_c_aws_byte_buf(const struct aws_byte_buf *byte_buf);

/**
 * Creates a new Aws::String from aws_string
 */
Aws::String aws_string_from_c_aws_string(const struct aws_string *c_aws_string);

/**
 * Creates a new Aws::Map<Aws::String, Aws::String> from an aws_hash_table that has aws_string as key and value
 */
Aws::Map<Aws::String, Aws::String> aws_map_from_c_aws_hash_table(const struct aws_hash_table *hash_table);

/**
 * Copies source buffer into dest and sets the correct len and capacity.
 * A new memory zone is allocated for dest->buffer. When dest is no longer needed it will have to be cleaned-up using
 * aws_byte_buf_clean_up(dest).
 * Dest capacity and len will be equal to the src len. Allocator of the dest will be identical with parameter allocator.
 * Returns AWS_OP_SUCCESS in case of success or AWS_OP_ERR when memory can't be allocated.
 */
int aws_byte_buf_dup_from_aws_utils(struct aws_allocator *allocator,
                                    struct aws_byte_buf *dest,
                                    const Aws::Utils::ByteBuffer &src);

/**
 * Appends a new key to the encrypted_data_keys.
 * Note: a new memory zone will be allocated for the inserted values in encrypted_data_keys
 * @param allocator Allocator structure. An instance of this will be passed around for anything needing memory
 *                  allocation
 * @param encrypted_data_keys[out] The new data key will be saved into this array
 * @param encrypted_data_key Encrypted Data Key
 * @param data_key_id Data Key Id
 * @param key_provider Data key Provider
 * @return AWS_OP_SUCCESS in case of success
 */
int append_key_dup_to_edks(struct aws_allocator *allocator,
                           struct aws_array_list *encrypted_data_keys,
                           const Aws::Utils::ByteBuffer *encrypted_data_key,
                           const Aws::String *data_key_id,
                           const aws_byte_buf *key_provider);


/**
 * Extracts region from a KMS Key ARN
 * E.g. From a key like:
 * arn:aws:kms:us-west-1:[numeric_values]:key/....
 * it returns us-west-1
 * If no region can be extracted it return empty string.
 */
Aws::String parse_region_from_kms_key_arn(const Aws::String &key_id);


}  // namespace Private
}  // namespace Cryptosdk
}  // namespace Aws

#endif  // AWS_ENCRYPTION_SDK_CPPUTILS_H
