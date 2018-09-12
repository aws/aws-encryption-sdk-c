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
#ifndef AWS_CRYPTOSDK_PRIVATE_RAW_RSA_KEYRING_H
#define AWS_CRYPTOSDK_PRIVATE_RAW_RSA_KEYRING_H

#include <aws/cryptosdk/raw_rsa_keyring.h>

struct raw_rsa_keyring {
    const struct aws_cryptosdk_keyring_vt *vt;
    struct aws_allocator *alloc;
    const struct aws_string *master_key_id;
    const struct aws_string *provider_id;
    const struct aws_string * rsa_key_pem;
    enum aws_cryptosdk_rsa_padding_mode rsa_padding_mode;
};

#endif  // AWS_CRYPTOSDK_PRIVATE_RAW_RSA_KEYRING_H
