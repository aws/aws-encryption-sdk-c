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

#ifndef AWS_ENCRYPTION_SDK_EDKS_UTILS_H
#define AWS_ENCRYPTION_SDK_EDKS_UTILS_H

#include <aws/cryptosdk/materials.h>
#include <aws/cryptosdk/private/cpputils.h>

#include "testing.h"

namespace Aws {
namespace Cryptosdk {
namespace Testing {

using std::string;
using Aws::Cryptosdk::Private::append_key_dup_to_edks;


/**
 * Class that initializes and deinitializes a list that stores encrypted_data_keys
 */
class Edks {
  public:
    Edks(struct aws_allocator *allocator) {
        aws_cryptosdk_edk_list_init(allocator, &encrypted_data_keys);
    }
    ~Edks() {
        aws_cryptosdk_edk_list_clean_up(&encrypted_data_keys);

    }

    struct aws_array_list encrypted_data_keys;
};


/**
 * Assets that an edk structure has the expected values for expected_ct, expected_key_id, expected_provider_id
 */
int t_assert_edk_contains_expected_values(const struct aws_cryptosdk_edk *edk,
                                          const char *expected_ct,
                                          const char *expected_key_id,
                                          const char *expected_provider_id,
                                          struct aws_allocator *allocator) {
    TEST_ASSERT(string(expected_ct) == string((char *)edk->enc_data_key.buffer, edk->enc_data_key.len));
    TEST_ASSERT(string(expected_key_id) == string((char *)edk->provider_info.buffer, edk->provider_info.len));
    TEST_ASSERT(string(expected_provider_id) == string((char *)edk->provider_id.buffer, edk->provider_id.len));
    TEST_ASSERT_ADDR_EQ(allocator, edk->enc_data_key.allocator);
    return 0;
}

/**
 * Assets that an edks list has a single element with the expected values for expected_ct, expected_key_id,
 * expected_provider_id
 */
int t_assert_edks_with_single_element_contains_expected_values(const struct aws_array_list *encrypted_data_keys,
                                                               const char *expected_ct,
                                                               const char *expected_key_id,
                                                               const char *expected_provider_id,
                                                               struct aws_allocator *allocator) {
    TEST_ASSERT_INT_EQ(1, aws_array_list_length(encrypted_data_keys));
    struct aws_cryptosdk_edk *edk;
    TEST_ASSERT_INT_EQ(0, aws_array_list_get_at_ptr(encrypted_data_keys, (void **) &edk, 0));
    return t_assert_edk_contains_expected_values(edk, expected_ct, expected_key_id, expected_provider_id, allocator);
}

/**
 * Assets that an encrypted_data_keys_a has the same elements as encrypted_data_keys_b
 */
int t_assert_edks_equals(const struct aws_array_list *encrypted_data_keys_a,
                         const struct aws_array_list *encrypted_data_keys_b) {
    TEST_ASSERT_INT_EQ(aws_array_list_length(encrypted_data_keys_a), aws_array_list_length(encrypted_data_keys_b));

    for (size_t idx = 0; idx < aws_array_list_length(encrypted_data_keys_a); idx++) {
        struct aws_cryptosdk_edk *edk_a;
        struct aws_cryptosdk_edk *edk_b;
        TEST_ASSERT_SUCCESS(aws_array_list_get_at_ptr(encrypted_data_keys_a, (void **) &edk_a, idx));
        TEST_ASSERT_SUCCESS(aws_array_list_get_at_ptr(encrypted_data_keys_b, (void **) &edk_b, idx));
        TEST_ASSERT(aws_cryptosdk_edk_eq(edk_a, edk_b) == true);
    }
    return AWS_OP_SUCCESS;
}


/**
 * Appends a new key to the encrypted_data_keys.
 * Same as append_key_to_edks() with the only difference that data_key_id and key_provider is a c_str
 */
int t_append_c_str_key_to_edks(struct aws_allocator *allocator,
                               struct aws_array_list *encrypted_data_keys,
                               const Aws::Utils::ByteBuffer *enc_data_key,
                               const char *data_key_id,
                               const char *key_provider) {
    aws_byte_buf key_provider_bb = aws_byte_buf_from_c_str(key_provider);
    Aws::String data_key_id_str(data_key_id);
    return append_key_dup_to_edks(allocator,
                                  encrypted_data_keys,
                                  enc_data_key,
                                  &data_key_id_str,
                                  &key_provider_bb);
}

}  // namespace Testing
}  // namespace Cryptosdk
}  // namespace Aws

#endif //AWS_ENCRYPTION_SDK_EDKS_UTILS_H
