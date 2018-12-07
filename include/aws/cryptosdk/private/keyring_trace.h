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
#ifndef AWS_CRYPTOSDK_PRIVATE_KEYRING_TRACE_H
#define AWS_CRYPTOSDK_PRIVATE_KEYRING_TRACE_H

#include <aws/cryptosdk/keyring_trace.h>

/**
 * Deallocate memory from a keyring trace record.
 */
void aws_cryptosdk_keyring_trace_record_clean_up(struct aws_cryptosdk_keyring_trace_record * record);

/**
 * Make a deep copy of a keyring trace record.
 */
int aws_cryptosdk_keyring_trace_record_init_clone(struct aws_allocator *alloc,
                                                  struct aws_cryptosdk_keyring_trace_record *dest,
                                                  const struct aws_cryptosdk_keyring_trace_record *src);

#endif // AWS_CRYPTOSDK_PRIVATE_KEYRING_TRACE_H
