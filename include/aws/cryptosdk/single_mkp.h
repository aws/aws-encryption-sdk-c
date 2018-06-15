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
#ifndef AWS_CRYPTOSDK_SINGLE_MKP_H
#define AWS_CRYPTOSDK_SINGLE_MKP_H

#include <aws/cryptosdk/materials.h>

/**
 * A Master Key Provider (MKP) that has a single Master Key (MK).
 * Use after instantiating a MK, as a connector between the MK and CMM.
 *
 * This MKP's get_master_keys method always appends the pointer to the master key
 * with which it was initialized to the list of master keys. The only way it can
 * fail is if there is a problem with the array list itself.
 *
 * This MKP's decrypt_data_key method simply delegates the call to the decrypt_data_key
 * method of its MK.
 *
 * On success allocates a MKP and returns its address. Be sure to deallocate it later
 * by caling aws_cryptosdk_mkp_destroy on the MKP pointer returned by this function.
 *
 * On failure returns NULL and sets and internal AWS error code.
 */
struct aws_cryptosdk_mkp * aws_cryptosdk_single_mkp_new(struct aws_allocator * alloc,
                                                        struct aws_cryptosdk_mk * mk);

#endif // AWS_CRYPTOSDK_SINGLE_MKP_H
