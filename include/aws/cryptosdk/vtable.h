#ifndef AWS_CRYPTOSDK_VTABLE_H
#define AWS_CRYPTOSDK_VTABLE_H
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

#include <aws/cryptosdk/exports.h>

/**
 * If 'vt->member' falls within vt->vt_size bytes of vt, and vt->member is non-NULL,
 * returns vt->member. Otherwise, returns fallback.
 *
 * Note: This macro evaluates vt multiple times.
 *
 * Note: This is is an unstable, internal API. Do not depend on it in your applications.
 */
#define AWS_CRYPTOSDK_PRIVATE_VT_GET(vt, member, fallback) \
    (((ptrdiff_t)&((vt)->member) - (ptrdiff_t)(vt)) + sizeof((vt)->member) <= (vt)->vt_size \
      ? (vt)->member \
      : (fallback))
/**
 * If 'vt->member' falls within vt->vt_size bytes of vt, and vt->member is non-NULL,
 * returns vt->member. Otherwise, returns NULL.
 *
 * Note: This macro evaluates vt multiple times.
 *
 * Note: This is is an unstable, internal API. Do not depend on it in your applications.
 */
#define AWS_CRYPTOSDK_PRIVATE_VT_GET_NULL(vt, member) AWS_CRYPTOSDK_PRIVATE_VT_GET(vt, member, NULL)

#endif
