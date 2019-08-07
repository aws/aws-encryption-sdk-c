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

#include <aws/common/array_list.h>
#include <aws/cryptosdk/private/keyring_trace.h>
#include <make_common_data_structures.h>
#include <proof_helpers/make_common_data_structures.h>

void aws_cryptosdk_keyring_trace_record_clean_up_harness() {
    /* data structure */
    struct aws_cryptosdk_keyring_trace_record record; /* Precondition: record is non-null */

    aws_cryptosdk_keyring_trace_record_clean_up(&record);
    assert(record.flags == 0);
    assert(record.wrapping_key_name == NULL);
    assert(record.wrapping_key_namespace == NULL);


}
