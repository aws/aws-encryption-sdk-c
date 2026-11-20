/*
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */
#include "server.h"

#include <string>

namespace esdk_test_server {

namespace {

const char *const NAMESPACE            = "aws.cryptography.esdk.testserver";
const char *const SMITHY_PROTOCOL      = "rpc-v2-cbor";
const char *const CBOR_CONTENT_TYPE    = "application/cbor";
const char *const EXPECTED_SERVICE     = "ESDKTestServer";
const char *const SERVICE_PATH_PREFIX  = "/service/";
const char *const OPERATION_PATH_INFIX = "/operation/";

http::Response cbor_response(int status, const cbor::Value &body) {
    http::Response response;
    response.status = status;
    response.headers.emplace_back("smithy-protocol", SMITHY_PROTOCOL);
    response.headers.emplace_back("Content-Type", CBOR_CONTENT_TYPE);
    response.body = cbor::encode(body);
    return response;
}

/** Modeled errors ride as a 400 CBOR map carrying the __type discriminator. */
http::Response error_response(OpError::Kind kind, const std::string &message) {
    const char *shape = kind == OpError::Kind::Esdk ? "ESDKClientError" : "GenericServerError";
    return cbor_response(
        400,
        cbor::Value::make_map(
            { { cbor::Value::make_text("__type"), cbor::Value::make_text(std::string(NAMESPACE) + "#" + shape) },
              { cbor::Value::make_text("message"), cbor::Value::make_text(message) } }));
}

http::Response generic_error(const std::string &message) {
    return error_response(OpError::Kind::Generic, message);
}

/** Splits /service/{service}/operation/{operation}; false when malformed. */
bool parse_path(const std::string &path, std::string *service, std::string *operation) {
    const std::string prefix(SERVICE_PATH_PREFIX);
    if (path.compare(0, prefix.size(), prefix) != 0) return false;
    size_t infix = path.find(OPERATION_PATH_INFIX, prefix.size());
    if (infix == std::string::npos) return false;
    *service   = path.substr(prefix.size(), infix - prefix.size());
    *operation = path.substr(infix + std::string(OPERATION_PATH_INFIX).size());
    return !service->empty() && !operation->empty() && operation->find('/') == std::string::npos;
}

http::Response dispatch(const std::shared_ptr<Bridge> &bridge, const http::Request &request) {
    if (request.method != "POST") {
        return generic_error("only POST is supported, got " + request.method);
    }
    std::string service, operation;
    if (!parse_path(request.path, &service, &operation)) {
        return generic_error("unknown request path: " + request.path);
    }
    if (service != EXPECTED_SERVICE) {
        return generic_error("unknown service: " + service + "; expected " + EXPECTED_SERVICE);
    }
    const std::string *protocol = request.header("smithy-protocol");
    if (!protocol || *protocol != SMITHY_PROTOCOL) {
        return generic_error("missing or invalid smithy-protocol header; expected rpc-v2-cbor");
    }
    const std::string *content_type = request.header("content-type");
    if (!content_type || *content_type != CBOR_CONTENT_TYPE) {
        return generic_error("missing or invalid content-type; expected application/cbor");
    }

    cbor::Value body;
    try {
        body = cbor::decode(request.body.data(), request.body.size());
    } catch (const cbor::Error &error) {
        return generic_error(std::string("failed to decode CBOR request: ") + error.what());
    }

    try {
        if (operation == "CreateClient") return cbor_response(200, bridge->create_client(body));
        if (operation == "Encrypt") return cbor_response(200, bridge->encrypt(body, false));
        if (operation == "Decrypt") return cbor_response(200, bridge->decrypt(body, false));
        if (operation == "EncryptStream") return cbor_response(200, bridge->encrypt(body, true));
        if (operation == "DecryptStream") return cbor_response(200, bridge->decrypt(body, true));
        return generic_error("unknown operation: " + operation);
    } catch (const OpError &error) {
        return error_response(error.kind(), error.what());
    } catch (const cbor::Error &error) {
        return generic_error(std::string("invalid request: ") + error.what());
    } catch (const std::exception &error) {
        return generic_error(std::string("unexpected server error: ") + error.what());
    }
}

}  // namespace

http::Handler make_dispatch(std::shared_ptr<Bridge> bridge) {
    return [bridge](const http::Request &request) { return dispatch(bridge, request); };
}

}  // namespace esdk_test_server
