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

#include <aws/cryptosdk/cpp/exports.h>

#include <aws/common/byte_buf.h>
#include <aws/common/hash_table.h>
#include <aws/common/string.h>
#include <aws/core/utils/ARN.h>
#include <aws/core/utils/Array.h>
#include <aws/core/utils/memory/stl/AWSMap.h>
#include <aws/core/utils/memory/stl/AWSString.h>

namespace Aws {
namespace Cryptosdk {
namespace Private {

/**
 * Creates a new Aws::String from byte_buf
 */
AWS_CRYPTOSDK_CPP_API
Aws::String aws_string_from_c_aws_byte_buf(const struct aws_byte_buf *byte_buf);

/**
 * Creates a new Aws::Utils::ByteBuffer from a byte_buff
 */
AWS_CRYPTOSDK_CPP_API
Aws::Utils::ByteBuffer aws_utils_byte_buffer_from_c_aws_byte_buf(const struct aws_byte_buf *byte_buf);

/**
 * Creates a new Aws::String from aws_string
 */
AWS_CRYPTOSDK_CPP_API
Aws::String aws_string_from_c_aws_string(const struct aws_string *c_aws_string);

/**
 * Creates a new Aws::Map<Aws::String, Aws::String> from an aws_hash_table that has aws_string as key and value
 */
AWS_CRYPTOSDK_CPP_API
Aws::Map<Aws::String, Aws::String> aws_map_from_c_aws_hash_table(const struct aws_hash_table *hash_table);

/**
 * Copies source buffer into dest and sets the correct len and capacity.
 * A new memory zone is allocated for dest->buffer. When dest is no longer needed it will have to be cleaned-up using
 * aws_byte_buf_clean_up(dest).
 * Dest capacity and len will be equal to the src len. Allocator of the dest will be identical with parameter allocator.
 * Returns AWS_OP_SUCCESS in case of success or AWS_OP_ERR when memory can't be allocated.
 */
AWS_CRYPTOSDK_CPP_API
int aws_byte_buf_dup_from_aws_utils(
    struct aws_allocator *allocator, struct aws_byte_buf *dest, const Aws::Utils::ByteBuffer &src);

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
AWS_CRYPTOSDK_CPP_API
int append_key_dup_to_edks(
    struct aws_allocator *allocator,
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
AWS_CRYPTOSDK_CPP_API
Aws::String parse_region_from_kms_key_arn(const Aws::String &key_id);

/**
 * Class that prevents memory leak of local array lists (even if a function throws).
 * When the object is destroyed it will clean up the lists.
 */
class AWS_CRYPTOSDK_CPP_API ListRaii {
   public:
    ListRaii(
        int (*init_fn)(struct aws_allocator *, struct aws_array_list *), void (*clean_up_fn)(struct aws_array_list *))
        : init_fn(init_fn), clean_up_fn(clean_up_fn) {}
    ~ListRaii();

    int Create(struct aws_allocator *alloc);

    struct aws_array_list list;

   private:
    int (*init_fn)(struct aws_allocator *, struct aws_array_list *);
    void (*clean_up_fn)(struct aws_array_list *);
    bool initialized;
};

/**
 * Returns true if the first string starts with the second string, or false
 * otherwise.
 */
AWS_CRYPTOSDK_CPP_API
bool starts_with(const Aws::String &s1, const Aws::String &s2);

/**
 * Returns true if the given ARN is a valid AWS KMS key ARN.
 *
 * Note that the definition of a valid KMS key ARN is more restrictive than the
 * definition of a valid ARN. In particular, KMS key ARNs have the following
 * additional constraints:
 *   - the partition must not be empty
 *   - the service must be "kms"
 *   - the region must not be empty
 *   - the account must not be empty
 *   - the resource must not be empty
 *   - the resource type must be "alias" or "key"
 *   - the resource ID must not be empty
 */
AWS_CRYPTOSDK_CPP_API
bool is_valid_kms_key_arn(const Aws::Utils::ARN &arn);

/**
 * Returns true if the given string is a valid AWS KMS key identifier.
 */
AWS_CRYPTOSDK_CPP_API
bool is_valid_kms_identifier(const Aws::String &ident);

/**
 * Returns true if the given string is a valid AWS KMS MRK key ARN.
 */
AWS_CRYPTOSDK_CPP_API
bool is_kms_mrk_arn(const Aws::Utils::ARN &key_arn);

/**
 * Returns true if the given KMS key identifier represents a multi-Region key
 * ID, or false otherwise.
 *
 * For example, returns true for
 *   - "arn:aws:kms:us-east-1:2222222222222:key/mrk-4321abcd12ab34cd56ef1234567890ab"
 *   - "mrk-4321abcd12ab34cd56ef1234567890ab"
 *
 * but returns false for
 *   - "arn:aws:kms:us-east-1:2222222222222:key/1234abcd-12ab-34cd-56ef-1234567890ab"
 *   - "arn:aws:kms:us-west-2:111122223333:alias/test-key"
 *   - "1234abcd-12ab-34cd-56ef-1234567890ab"
 *   - "alias/test-key"
 */
AWS_CRYPTOSDK_CPP_API
bool is_kms_mrk_identifier(const Aws::String &key_id);

/**
 * Returns true if the given KMS key identifiers are identical or both are MRK
 * identifiers that differ only by region, or returns false otherwise.
 */
AWS_CRYPTOSDK_CPP_API
bool kms_mrk_match_for_decrypt(const Aws::String &key_id_1, const Aws::String &key_id_2);

/**
 * Returns a vector of all input key IDs representing AWS KMS MRKs that share a
 * resource ID with another input MRK ID. If there are no such key IDs, returns
 * an empty vector.
 */
AWS_CRYPTOSDK_CPP_API
Aws::Vector<Aws::String> find_duplicate_kms_mrk_ids(const Aws::Vector<Aws::String> &key_ids);

}  // namespace Private
}  // namespace Cryptosdk
}  // namespace Aws

#endif  // AWS_ENCRYPTION_SDK_CPPUTILS_H
