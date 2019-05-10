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

#include <aws/cryptosdk/version.h>
#include "testing.h"

static int print_version_info() {
    printf("\nMajor.Minor.Patch: %d.%d.%d\n", AWS_CRYPTOSDK_VERSION_MAJOR,
           AWS_CRYPTOSDK_VERSION_MINOR, AWS_CRYPTOSDK_VERSION_PATCH);
    printf("Version string: %s\n", AWS_CRYPTOSDK_VERSION_STR);
    return 0;
}

#include <aws/cryptosdk/private/config.h>

static int print_user_agent_string() {
    printf("\nUser agent string: %s\n", AWS_CRYPTOSDK_PRIVATE_VERSION_UA);
    return 0;
}

struct test_case version_test_cases[] = {
    { "version", "print_version_info", print_version_info },
    { "version", "print_user_agent_string", print_user_agent_string },
    { NULL }
};
