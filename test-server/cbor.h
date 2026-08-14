/*
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef ESDK_TEST_SERVER_CBOR_H
#define ESDK_TEST_SERVER_CBOR_H

#include <cstdint>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

namespace esdk_test_server {
namespace cbor {

/**
 * Raised on malformed CBOR input and on type-mismatched member access. The
 * message is forwarded to the caller as a modeled GenericServerError.
 */
class Error : public std::runtime_error {
   public:
    explicit Error(const std::string &message) : std::runtime_error(message) {}
};

/**
 * One CBOR data item. A tagged struct rather than a union so C++11 suffices;
 * only the members selected by `kind` are meaningful.
 */
struct Value {
    enum class Kind { Unsigned, Negative, Bytes, Text, Array, Map, Bool, Null, Float };

    Kind kind = Kind::Null;

    uint64_t unsigned_value = 0;
    /** Negative integers represent -1 - negative_offset. */
    uint64_t negative_offset = 0;
    bool bool_value          = false;
    double float_value       = 0.0;
    std::vector<uint8_t> bytes;
    std::string text;
    std::vector<Value> array;
    std::vector<std::pair<Value, Value>> map;

    static Value make_unsigned(uint64_t v);
    static Value make_int(int64_t v);
    static Value make_bytes(std::vector<uint8_t> v);
    static Value make_text(std::string v);
    static Value make_bool(bool v);
    static Value make_null();
    static Value make_array(std::vector<Value> v);
    static Value make_map(std::vector<std::pair<Value, Value>> v);

    bool is_null() const {
        return kind == Kind::Null;
    }

    /** Typed accessors; `what` names the member in the thrown Error. */
    int64_t as_int64(const char *what) const;
    const std::string &as_text(const char *what) const;
    const std::vector<uint8_t> &as_bytes(const char *what) const;
    const std::vector<Value> &as_array(const char *what) const;
    const std::vector<std::pair<Value, Value>> &as_map(const char *what) const;

    /**
     * Looks up a text key in a Map value. Returns nullptr when the key is
     * absent or its value is null (absent and explicit-null members are
     * equivalent on the wire).
     */
    const Value *find(const std::string &key) const;
};

/**
 * Decodes exactly one CBOR data item spanning the whole input. Accepts
 * definite- and indefinite-length strings, arrays, and maps, tags (the tag
 * number is dropped), and half/single/double-precision floats.
 */
Value decode(const uint8_t *data, size_t len);

/** Encodes a data item with definite lengths throughout. */
std::vector<uint8_t> encode(const Value &value);

}  // namespace cbor
}  // namespace esdk_test_server

#endif  // ESDK_TEST_SERVER_CBOR_H
