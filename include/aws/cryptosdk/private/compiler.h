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

#ifndef AWS_CRYPTOSDK_PRIVATE_COMPILER_H
#define AWS_CRYPTOSDK_PRIVATE_COMPILER_H

#include <aws/cryptosdk/private/config.h>

#ifdef AWS_CRYPTOSDK_P_HAVE_BUILTIN_EXPECT
#    define aws_cryptosdk_unlikely(x) (__builtin_expect((x), 0))
#    define aws_cryptosdk_likely(x) (__builtin_expect(!!(x), 1))
#else
#    define aws_cryptosdk_unlikely(x) (x)
#    define aws_cryptosdk_likely(x) (x)
#endif

#endif  // AWS_CRYPTOSDK_PRIVATE_COMPILER_H
