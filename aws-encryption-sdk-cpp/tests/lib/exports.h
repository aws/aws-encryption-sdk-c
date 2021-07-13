#ifndef AWS_ENCRYPTION_SDK_CPP_TESTLIB_EXPORTS_H
#define AWS_ENCRYPTION_SDK_CPP_TESTLIB_EXPORTS_H

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

#if defined(_MSC_VER) && !defined(AWS_ENCRYPTION_SDK_FORCE_STATIC) && defined(AWS_ENCRYPTION_SDK_SHARED)
#    ifdef IN_TESTLIB_CPP_BUILD
#        define TESTLIB_CPP_API __declspec(dllexport)
#    else
#        define TESTLIB_CPP_API __declspec(dllimport)
#    endif
#else
#    define TESTLIB_CPP_API
#endif

#endif
