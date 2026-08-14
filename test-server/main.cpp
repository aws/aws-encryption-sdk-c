/*
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */
#include <cstdio>
#include <cstdlib>
#include <memory>
#include <string>

#include <aws/cryptosdk/error.h>

#include "bridge.h"
#include "http.h"
#include "server.h"

namespace {

const uint16_t DEFAULT_PORT = 8096;

/** Port resolution order: first CLI argument, ESDK_TESTSERVER_PORT, default. */
uint16_t resolve_port(int argc, char **argv) {
    const char *configured = nullptr;
    if (argc > 1) {
        configured = argv[1];
    } else {
        configured = std::getenv("ESDK_TESTSERVER_PORT");
    }
    if (!configured) return DEFAULT_PORT;
    char *end          = nullptr;
    unsigned long port = std::strtoul(configured, &end, 10);
    if (end == configured || *end != '\0' || port == 0 || port > 65535) return DEFAULT_PORT;
    return static_cast<uint16_t>(port);
}

}  // namespace

int main(int argc, char **argv) {
    aws_cryptosdk_load_error_strings();

    uint16_t port = resolve_port(argc, argv);

    esdk_test_server::http::Server server;
    std::string error;
    if (!server.bind(port, &error)) {
        std::fprintf(stderr, "failed to bind: %s\n", error.c_str());
        return 1;
    }

    std::fprintf(stderr, "listening at http://127.0.0.1:%u\n", server.port());
    auto bridge = std::make_shared<esdk_test_server::Bridge>();
    server.serve_forever(esdk_test_server::make_dispatch(bridge));
    return 0;
}
