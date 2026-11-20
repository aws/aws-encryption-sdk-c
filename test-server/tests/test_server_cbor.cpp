/*
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */
#include <cstdint>
#include <cstdio>
#include <string>
#include <vector>

#include "cbor.h"

using esdk_test_server::cbor::Error;
using esdk_test_server::cbor::Value;

#define CHECK(cond)                                                                   \
    do {                                                                              \
        if (!(cond)) {                                                                \
            std::fprintf(stderr, "FAILED: %s at %s:%d\n", #cond, __FILE__, __LINE__); \
            return 1;                                                                 \
        }                                                                             \
    } while (0)

namespace {

Value round_trip(const Value &value) {
    std::vector<uint8_t> encoded = esdk_test_server::cbor::encode(value);
    return esdk_test_server::cbor::decode(encoded.data(), encoded.size());
}

Value decode_bytes(const std::vector<uint8_t> &bytes) {
    return esdk_test_server::cbor::decode(bytes.data(), bytes.size());
}

bool decode_fails(const std::vector<uint8_t> &bytes) {
    try {
        decode_bytes(bytes);
        return false;
    } catch (const Error &) {
        return true;
    }
}

int test_integer_round_trips() {
    const int64_t cases[] = { 0,   1,   23,   24,     255,          256,          65535,     65536,         -1,
                              -24, -25, -256, -65536, 4294967295LL, 4294967296LL, INT64_MAX, INT64_MIN + 1, INT64_MIN };
    for (int64_t expected : cases) {
        Value decoded = round_trip(Value::make_int(expected));
        CHECK(decoded.as_int64("case") == expected);
    }
    Value big = round_trip(Value::make_unsigned(UINT64_MAX));
    CHECK(big.kind == Value::Kind::Unsigned && big.unsigned_value == UINT64_MAX);
    return 0;
}

int test_string_and_bytes_round_trips() {
    Value text = round_trip(Value::make_text("hello \xE6\x97\xA5"));
    CHECK(text.as_text("t") == "hello \xE6\x97\xA5");
    CHECK(round_trip(Value::make_text("")).as_text("t").empty());

    std::vector<uint8_t> payload;
    for (int i = 0; i < 300; i++) payload.push_back(static_cast<uint8_t>(i));
    Value bytes = round_trip(Value::make_bytes(payload));
    CHECK(bytes.as_bytes("b") == payload);
    CHECK(round_trip(Value::make_bytes({})).as_bytes("b").empty());
    return 0;
}

int test_container_round_trips() {
    std::vector<Value> items;
    items.push_back(Value::make_int(-5));
    items.push_back(Value::make_bool(true));
    items.push_back(Value::make_null());
    items.push_back(Value::make_array({ Value::make_text("nested") }));
    Value array = round_trip(Value::make_array(items));
    CHECK(array.as_array("a").size() == 4);
    CHECK(array.array[0].as_int64("a0") == -5);
    CHECK(array.array[1].bool_value);
    CHECK(array.array[2].is_null());
    CHECK(array.array[3].array[0].as_text("a3") == "nested");

    Value map = round_trip(Value::make_map(
        { { Value::make_text("k"), Value::make_text("v") }, { Value::make_text("n"), Value::make_int(7) } }));
    CHECK(map.find("k") != nullptr && map.find("k")->as_text("k") == "v");
    CHECK(map.find("n")->as_int64("n") == 7);
    CHECK(map.find("absent") == nullptr);
    return 0;
}

int test_null_member_is_absent() {
    Value map = Value::make_map({ { Value::make_text("k"), Value::make_null() } });
    CHECK(map.find("k") == nullptr);
    return 0;
}

int test_known_encodings() {
    CHECK(esdk_test_server::cbor::encode(Value::make_unsigned(24)) == (std::vector<uint8_t>{ 0x18, 0x18 }));
    CHECK(esdk_test_server::cbor::encode(Value::make_int(-1)) == (std::vector<uint8_t>{ 0x20 }));
    CHECK(esdk_test_server::cbor::encode(Value::make_bool(false)) == (std::vector<uint8_t>{ 0xF4 }));
    CHECK(esdk_test_server::cbor::encode(Value::make_null()) == (std::vector<uint8_t>{ 0xF6 }));
    CHECK(esdk_test_server::cbor::encode(Value::make_text("ab")) == (std::vector<uint8_t>{ 0x62, 0x61, 0x62 }));
    return 0;
}

int test_indefinite_length_decoding() {
    // 0x7F "ab" "c" 0xFF: indefinite text in two chunks.
    Value text = decode_bytes({ 0x7F, 0x62, 'a', 'b', 0x61, 'c', 0xFF });
    CHECK(text.as_text("t") == "abc");

    // 0x5F <2 bytes> <1 byte> 0xFF: indefinite byte string.
    Value bytes = decode_bytes({ 0x5F, 0x42, 0x01, 0x02, 0x41, 0x03, 0xFF });
    CHECK(bytes.as_bytes("b") == (std::vector<uint8_t>{ 0x01, 0x02, 0x03 }));

    // 0x9F 1 2 0xFF: indefinite array.
    Value array = decode_bytes({ 0x9F, 0x01, 0x02, 0xFF });
    CHECK(array.as_array("a").size() == 2 && array.array[1].as_int64("a1") == 2);

    // 0xBF "a" 1 0xFF: indefinite map.
    Value map = decode_bytes({ 0xBF, 0x61, 'a', 0x01, 0xFF });
    CHECK(map.find("a")->as_int64("a") == 1);
    return 0;
}

int test_tags_and_floats() {
    // Tag 0 wrapping a text string decodes to the inner text.
    Value tagged = decode_bytes({ 0xC0, 0x62, 'h', 'i' });
    CHECK(tagged.as_text("t") == "hi");

    // Half, single, and double precision 1.0.
    CHECK(decode_bytes({ 0xF9, 0x3C, 0x00 }).float_value == 1.0);
    CHECK(decode_bytes({ 0xFA, 0x3F, 0x80, 0x00, 0x00 }).float_value == 1.0);
    CHECK(decode_bytes({ 0xFB, 0x3F, 0xF0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }).float_value == 1.0);
    return 0;
}

int test_malformed_inputs_rejected() {
    CHECK(decode_fails({}));                         // empty input
    CHECK(decode_fails({ 0x62, 'a' }));              // truncated text
    CHECK(decode_fails({ 0x19, 0x01 }));             // truncated argument
    CHECK(decode_fails({ 0x01, 0x01 }));             // trailing bytes
    CHECK(decode_fails({ 0x9F, 0x01 }));             // unterminated indefinite array
    CHECK(decode_fails({ 0x1C }));                   // reserved additional info
    CHECK(decode_fails({ 0x7F, 0x41, 'a', 0xFF }));  // wrong chunk major in indefinite text
    CHECK(decode_fails({ 0xBF, 0x61, 'a', 0xFF }));  // map key without value

    std::vector<uint8_t> deep(40, 0x81);  // nesting beyond the depth limit
    deep.push_back(0x01);
    CHECK(decode_fails(deep));
    return 0;
}

int test_type_mismatch_reporting() {
    Value number = Value::make_int(3);
    try {
        number.as_text("frameLength");
        return 1;
    } catch (const Error &error) {
        CHECK(std::string(error.what()).find("frameLength") != std::string::npos);
    }
    return 0;
}

}  // namespace

int main() {
    int failures = 0;
    failures += test_integer_round_trips();
    failures += test_string_and_bytes_round_trips();
    failures += test_container_round_trips();
    failures += test_null_member_is_absent();
    failures += test_known_encodings();
    failures += test_indefinite_length_decoding();
    failures += test_tags_and_floats();
    failures += test_malformed_inputs_rejected();
    failures += test_type_mismatch_reporting();
    if (failures) {
        std::fprintf(stderr, "%d CBOR test(s) failed\n", failures);
        return 1;
    }
    std::printf("all CBOR tests passed\n");
    return 0;
}
