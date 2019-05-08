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

#ifndef AWS_CRYPTOSDK_VERSION_H
#define AWS_CRYPTOSDK_VERSION_H

#include <aws/cryptosdk/private/config.h>

/*! \mainpage The AWS Encryption SDK for C
 *
 * The AWS Encryption SDK for C is a client-side encryption library designed to make it easy for
 * everyone to encrypt and decrypt data using industry standards and best practices. It uses a
 * data format compatible with the AWS Encryption SDKs in other languages. For more information on
 * the AWS Encryption SDKs in all languages, see the
 * <a href="https://docs.aws.amazon.com/encryption-sdk/latest/developer-guide/introduction.html">Developer Guide</a>.
 *
 * Source code and installation instructions are available in
 * <a href="https://github.com/awslabs/aws-encryption-sdk-c">the GitHub repository</a>.
 *
 * This API documentation was generated from the v$(MAJOR).$(MINOR).$(PATCH) source code.
 *
 * <b>License</b>
 *
 * This library is licensed under the Apache 2.0 License.
 */

/**
 * @defgroup versioning Version constants
 *
 * This section defines version macros that can be used to query the current version of the Encryption SDK.
 * For prerelease builds, the version constants will generally contain the anticipated version of the upcoming
 * release; if a git working copy is detected at build time, we will include that revision in the version
 * strings, but not in the numeric version constants.
 *
 * @{
 */

#ifndef AWS_CRYPTOSDK_PRIVATE_GITVERSION
#    define AWS_CRYPTOSDK_PRIVATE_GITVERSION ""
#endif

#ifndef AWS_CRYPTOSDK_DOXYGEN  // undocumented private helpers
#    define AWS_CRYPTOSDK_PRIVATE_QUOTEARG(a) #    a
#    define AWS_CRYPTOSDK_PRIVATE_EXPANDQUOTE(a) AWS_CRYPTOSDK_PRIVATE_QUOTEARG(a)
#endif

/**
 * A string constant containing version information in a human-readable form.
 */
#define AWS_CRYPTOSDK_VERSION_STR                                                                             \
    AWS_CRYPTOSDK_PRIVATE_EXPANDQUOTE(AWS_CRYPTOSDK_VERSION_MAJOR)                                            \
    "." AWS_CRYPTOSDK_PRIVATE_EXPANDQUOTE(AWS_CRYPTOSDK_VERSION_MINOR) "." AWS_CRYPTOSDK_PRIVATE_EXPANDQUOTE( \
        AWS_CRYPTOSDK_VERSION_PATCH) AWS_CRYPTOSDK_PRIVATE_GITVERSION

/**
 * A string constant containing version information in a form suitable for a user-agent string.
 */
#define AWS_CRYPTOSDK_VERSION_UA "aws-encryption-sdk-c/" AWS_CRYPTOSDK_VERSION_STR

/** @} */  // doxygen group versioning

#endif
