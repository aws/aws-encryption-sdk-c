#ifndef AWS_CRYPTOSDK_EXPORTS_H
#define AWS_CRYPTOSDK_EXPORTS_H
/*
 * Copyright 2010-2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
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

#ifdef AWS_ENCRYPTION_SDK_FORCE_STATIC
/*
 * We build a static library for unit tests in order to access some non-exported
 * internal functions for testing.
 */
#    undef AWS_ENCRYPTION_SDK_SHARED
#endif

#if defined(WIN32)
#    ifdef AWS_ENCRYPTION_SDK_SHARED
#        ifdef AWS_ENCRYPTION_SDK_EXPORTS
#            define AWS_CRYPTOSDK_API __declspec(dllexport)
#        else
#            define AWS_CRYPTOSDK_API __declspec(dllimport)
#        endif /* AWS_CRYPTOSDK_EXPORTS */
#    else
#        define AWS_CRYPTOSDK_API
#    endif  // USE_IMPORT_EXPORT

#else /* defined (WIN32) */

#    if ((__GNUC__ >= 4) || defined(__clang__)) && defined(AWS_ENCRYPTION_SDK_EXPORTS)
#        define AWS_CRYPTOSDK_API __attribute__((visibility("default")))
#    else
#        define AWS_CRYPTOSDK_API
#    endif /* __GNUC__ >= 4 || defined(__clang__) */

#endif /* defined (WIN32) */

/*
 * We'd like for certain functions to be inlinable in consuming code,
 * but we also need them to be exported for use by foreign function interfaces
 * (i.e. linking from other languages). To accomplish this, we define
 * this macro to be 'static inline' when normally importing headers, but
 * we have one file (codegen.c) which redefines this to be AWS_CRYPTOSDK_API
 * so the code gets generated and included in the final shared library.
 */
#ifndef AWS_CRYPTOSDK_STATIC_INLINE
#    define AWS_CRYPTOSDK_STATIC_INLINE static inline
#endif

/*
 * AWS_CRYPTOSDK_TEST_STATIC allows otherwise-static methods to be marked as exposed
 * to unit tests (but not integration tests) only.
 */
#ifndef AWS_CRYPTOSDK_TEST_STATIC
#    define AWS_CRYPTOSDK_TEST_STATIC static
#endif

#endif /* AWS_CRYPTOSDK_EXPORTS_H */
