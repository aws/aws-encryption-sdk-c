/*
 * Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License").
 * You may not use this file except in compliance with the License.
 * A copy of the License is located at
 *
 *  http://aws.amazon.com/apache2.0
 *
 * or in the "license" file accompanying this file. This file is distributed
 * on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
 * express or implied. See the License for the specific language governing
 * permissions and limitations under the License.
 */

#include <aws/cryptosdk/cipher.h>
#include <aws/cryptosdk/private/cipher.h>
#include <aws/cryptosdk/private/hkdf.h>

#include <make_common_data_structures.h>

int aws_cryptosdk_hkdf(
    struct aws_byte_buf *okm,
    enum aws_cryptosdk_sha_version which_sha,
    const struct aws_byte_buf *salt,
    const struct aws_byte_buf *ikm,
    const struct aws_byte_buf *info);

void aws_cryptosdk_hkdf_harness() {
    /* arguments */

    struct aws_byte_buf okm;
    enum aws_cryptosdk_alg_id alg_id;
    enum aws_cryptosdk_sha_version which_sha = aws_cryptosdk_which_sha(alg_id);

    struct aws_byte_buf salt;
    struct aws_byte_buf ikm;
    struct aws_byte_buf info;

    __CPROVER_assume(aws_byte_buf_is_bounded(&okm, MAX_BUFFER_SIZE));
    ensure_byte_buf_has_allocated_buffer_member(&okm);
    __CPROVER_assume(aws_byte_buf_is_valid(&okm));

    __CPROVER_assume(aws_byte_buf_is_bounded(&salt, MAX_BUFFER_SIZE));
    ensure_byte_buf_has_allocated_buffer_member(&salt);
    __CPROVER_assume(aws_byte_buf_is_valid(&salt));

    __CPROVER_assume(aws_byte_buf_is_bounded(&ikm, MAX_BUFFER_SIZE));
    ensure_byte_buf_has_allocated_buffer_member(&ikm);
    __CPROVER_assume(aws_byte_buf_is_valid(&ikm));

    __CPROVER_assume(aws_byte_buf_is_bounded(&info, MAX_BUFFER_SIZE));
    ensure_byte_buf_has_allocated_buffer_member(&info);
    __CPROVER_assume(aws_byte_buf_is_valid(&info));

    /* save current state of the data structure */
    struct aws_byte_buf old_salt = salt;
    struct store_byte_from_buffer old_byte_from_salt;
    save_byte_from_array(salt.buffer, salt.len, &old_byte_from_salt);

    struct aws_byte_buf old_ikm = ikm;
    struct store_byte_from_buffer old_byte_from_ikm;
    save_byte_from_array(ikm.buffer, ikm.len, &old_byte_from_ikm);

    struct aws_byte_buf old_info = info;
    struct store_byte_from_buffer old_byte_from_info;
    save_byte_from_array(info.buffer, info.len, &old_byte_from_info);

    aws_cryptosdk_hkdf(&okm, which_sha, &salt, &ikm, &info);

    /* assertions */
    assert(aws_byte_buf_is_valid(&salt));
    assert(aws_byte_buf_is_valid(&ikm));
    assert(aws_byte_buf_is_valid(&info));

    assert_byte_buf_equivalence(&salt, &old_salt, &old_byte_from_salt);
    assert_byte_buf_equivalence(&ikm, &old_ikm, &old_byte_from_ikm);
    assert_byte_buf_equivalence(&info, &old_info, &old_byte_from_info);

    assert(aws_byte_buf_is_valid(&okm));
}
