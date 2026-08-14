/*
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef ESDK_TEST_SERVER_SERVER_H
#define ESDK_TEST_SERVER_SERVER_H

#include <memory>

#include "bridge.h"
#include "http.h"

namespace esdk_test_server {

/**
 * The rpcv2Cbor dispatch: routes POST /service/ESDKTestServer/operation/{Op},
 * validates the smithy-protocol and content-type headers, decodes the CBOR
 * request, invokes the bridge, and encodes the CBOR response or one of the two
 * modeled errors. Every outcome is a modeled response; nothing escapes as a
 * bare HTTP error.
 */
http::Handler make_dispatch(std::shared_ptr<Bridge> bridge);

}  // namespace esdk_test_server

#endif  // ESDK_TEST_SERVER_SERVER_H
