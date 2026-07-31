/*
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef ESDK_TEST_SERVER_BRIDGE_H
#define ESDK_TEST_SERVER_BRIDGE_H

#include <exception>
#include <memory>
#include <mutex>
#include <string>
#include <unordered_map>

#include "cbor.h"

namespace esdk_test_server {

/**
 * A failed operation, categorized as one of the two modeled TestServer errors:
 * Generic maps to GenericServerError (framework/configuration failures);
 * Esdk maps to ESDKClientError (failures from the AWS Encryption SDK itself).
 */
class OpError : public std::exception {
   public:
    enum class Kind { Generic, Esdk };

    OpError(Kind kind, std::string message) : kind_(kind), message_(std::move(message)) {}

    Kind kind() const {
        return kind_;
    }

    const char *what() const noexcept override {
        return message_.c_str();
    }

   private:
    Kind kind_;
    std::string message_;
};

struct ClientEntry;

/**
 * Translates modeled ESDKClientConfigs into AWS Encryption SDK for C keyrings,
 * CMMs, and sessions, and keeps the clientId registry. Thread safe.
 */
class Bridge {
   public:
    Bridge();
    ~Bridge();

    /** Handles CreateClient: builds and registers a client, returns its response. */
    cbor::Value create_client(const cbor::Value &request);

    /** Handles Encrypt (blob) and EncryptStream (drives the streaming API). */
    cbor::Value encrypt(const cbor::Value &request, bool streaming);

    /** Handles Decrypt (blob) and DecryptStream (drives the streaming API). */
    cbor::Value decrypt(const cbor::Value &request, bool streaming);

   private:
    std::shared_ptr<ClientEntry> resolve(const cbor::Value &request);

    std::mutex mutex_;
    std::unordered_map<std::string, std::shared_ptr<ClientEntry>> clients_;
};

}  // namespace esdk_test_server

#endif  // ESDK_TEST_SERVER_BRIDGE_H
