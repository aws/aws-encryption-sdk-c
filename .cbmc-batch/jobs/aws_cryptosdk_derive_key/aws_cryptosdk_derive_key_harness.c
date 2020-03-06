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
#include <make_common_data_structures.h>

#define MSG_ID_LEN 16

void aws_cryptosdk_derive_key_harness() {
    /* arguments */
    enum aws_cryptosdk_alg_id alg_id;
    struct aws_cryptosdk_alg_properties *props = aws_cryptosdk_alg_props(alg_id);

    struct content_key *content_key = malloc(sizeof(content_key));
    struct data_key *data_key       = malloc(sizeof(data_key));
    uint8_t message_id;

    /* assumptions */
    __CPROVER_assume(props);
    __CPROVER_assume(AWS_MEM_IS_WRITABLE(content_key->keybuf, sizeof(content_key->keybuf)));
    __CPROVER_assume(AWS_MEM_IS_READABLE(message_id, MSG_ID_LEN));

    aws_cryptosdk_derive_key(props, content_key, data_key, &message_id);
}
