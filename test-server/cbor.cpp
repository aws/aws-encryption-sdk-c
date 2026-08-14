/*
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */
#include "cbor.h"

#include <cmath>
#include <cstring>
#include <limits>

namespace esdk_test_server {
namespace cbor {

Value Value::make_unsigned(uint64_t v) {
    Value value;
    value.kind           = Kind::Unsigned;
    value.unsigned_value = v;
    return value;
}

Value Value::make_int(int64_t v) {
    if (v >= 0) return make_unsigned(static_cast<uint64_t>(v));
    Value value;
    value.kind            = Kind::Negative;
    value.negative_offset = static_cast<uint64_t>(-(v + 1));
    return value;
}

Value Value::make_bytes(std::vector<uint8_t> v) {
    Value value;
    value.kind  = Kind::Bytes;
    value.bytes = std::move(v);
    return value;
}

Value Value::make_text(std::string v) {
    Value value;
    value.kind = Kind::Text;
    value.text = std::move(v);
    return value;
}

Value Value::make_bool(bool v) {
    Value value;
    value.kind       = Kind::Bool;
    value.bool_value = v;
    return value;
}

Value Value::make_null() {
    return Value();
}

Value Value::make_array(std::vector<Value> v) {
    Value value;
    value.kind  = Kind::Array;
    value.array = std::move(v);
    return value;
}

Value Value::make_map(std::vector<std::pair<Value, Value>> v) {
    Value value;
    value.kind = Kind::Map;
    value.map  = std::move(v);
    return value;
}

int64_t Value::as_int64(const char *what) const {
    if (kind == Kind::Unsigned) {
        if (unsigned_value > static_cast<uint64_t>(std::numeric_limits<int64_t>::max())) {
            throw Error(std::string(what) + " is out of range");
        }
        return static_cast<int64_t>(unsigned_value);
    }
    if (kind == Kind::Negative) {
        if (negative_offset > static_cast<uint64_t>(std::numeric_limits<int64_t>::max())) {
            throw Error(std::string(what) + " is out of range");
        }
        return -1 - static_cast<int64_t>(negative_offset);
    }
    throw Error(std::string(what) + " must be an integer");
}

const std::string &Value::as_text(const char *what) const {
    if (kind != Kind::Text) throw Error(std::string(what) + " must be a text string");
    return text;
}

const std::vector<uint8_t> &Value::as_bytes(const char *what) const {
    if (kind != Kind::Bytes) throw Error(std::string(what) + " must be a byte string");
    return bytes;
}

const std::vector<Value> &Value::as_array(const char *what) const {
    if (kind != Kind::Array) throw Error(std::string(what) + " must be an array");
    return array;
}

const std::vector<std::pair<Value, Value>> &Value::as_map(const char *what) const {
    if (kind != Kind::Map) throw Error(std::string(what) + " must be a map");
    return map;
}

const Value *Value::find(const std::string &key) const {
    if (kind != Kind::Map) return nullptr;
    for (const auto &entry : map) {
        if (entry.first.kind == Kind::Text && entry.first.text == key) {
            return entry.second.is_null() ? nullptr : &entry.second;
        }
    }
    return nullptr;
}

namespace {

const size_t MAX_DEPTH = 32;

class Decoder {
   public:
    Decoder(const uint8_t *data, size_t len) : data_(data), len_(len) {}

    Value decode_all() {
        Value value = decode_item(0);
        if (pos_ != len_) throw Error("trailing bytes after CBOR item");
        return value;
    }

   private:
    uint8_t read_byte() {
        if (pos_ >= len_) throw Error("truncated CBOR item");
        return data_[pos_++];
    }

    uint64_t read_big_endian(size_t width) {
        if (len_ - pos_ < width) throw Error("truncated CBOR item");
        uint64_t v = 0;
        for (size_t i = 0; i < width; i++) v = (v << 8) | data_[pos_++];
        return v;
    }

    /**
     * Reads the argument for additional info `info`. Returns UINT64_MAX with
     * *indefinite set for additional info 31.
     */
    uint64_t read_argument(uint8_t info, bool *indefinite) {
        *indefinite = false;
        if (info < 24) return info;
        switch (info) {
            case 24: return read_big_endian(1);
            case 25: return read_big_endian(2);
            case 26: return read_big_endian(4);
            case 27: return read_big_endian(8);
            case 31: *indefinite = true; return 0;
            default: throw Error("reserved CBOR additional info");
        }
    }

    bool at_break() {
        if (pos_ >= len_) throw Error("truncated CBOR item");
        if (data_[pos_] != 0xFF) return false;
        pos_++;
        return true;
    }

    size_t checked_length(uint64_t length) {
        if (length > len_ - pos_) throw Error("CBOR length exceeds input");
        return static_cast<size_t>(length);
    }

    /** Definite chunks of an indefinite-length string must share `major`. */
    void append_chunks(uint8_t major, std::string *text, std::vector<uint8_t> *bytes) {
        while (!at_break()) {
            uint8_t initial = read_byte();
            if ((initial >> 5) != major || (initial & 0x1F) == 31) {
                throw Error("invalid chunk in indefinite-length CBOR string");
            }
            bool indefinite = false;
            size_t length   = checked_length(read_argument(initial & 0x1F, &indefinite));
            if (text) text->append(reinterpret_cast<const char *>(data_ + pos_), length);
            if (bytes) bytes->insert(bytes->end(), data_ + pos_, data_ + pos_ + length);
            pos_ += length;
        }
    }

    static double decode_half(uint16_t half) {
        unsigned exponent = (half >> 10) & 0x1F;
        unsigned mantissa = half & 0x3FF;
        double value;
        if (exponent == 0) {
            value = std::ldexp(mantissa, -24);
        } else if (exponent != 31) {
            value = std::ldexp(mantissa + 1024, static_cast<int>(exponent) - 25);
        } else {
            value = mantissa == 0 ? std::numeric_limits<double>::infinity() : std::numeric_limits<double>::quiet_NaN();
        }
        return (half & 0x8000) ? -value : value;
    }

    Value decode_item(size_t depth) {
        if (depth > MAX_DEPTH) throw Error("CBOR nesting too deep");
        uint8_t initial = read_byte();
        uint8_t major   = initial >> 5;
        uint8_t info    = initial & 0x1F;
        bool indefinite = false;

        switch (major) {
            case 0: return Value::make_unsigned(read_argument(info, &indefinite));
            case 1: {
                Value value;
                value.kind            = Value::Kind::Negative;
                value.negative_offset = read_argument(info, &indefinite);
                return value;
            }
            case 2: {
                Value value;
                value.kind = Value::Kind::Bytes;
                if (info == 31) {
                    append_chunks(2, nullptr, &value.bytes);
                } else {
                    size_t length = checked_length(read_argument(info, &indefinite));
                    value.bytes.assign(data_ + pos_, data_ + pos_ + length);
                    pos_ += length;
                }
                return value;
            }
            case 3: {
                Value value;
                value.kind = Value::Kind::Text;
                if (info == 31) {
                    append_chunks(3, &value.text, nullptr);
                } else {
                    size_t length = checked_length(read_argument(info, &indefinite));
                    value.text.assign(reinterpret_cast<const char *>(data_ + pos_), length);
                    pos_ += length;
                }
                return value;
            }
            case 4: {
                Value value;
                value.kind = Value::Kind::Array;
                if (info == 31) {
                    while (!at_break()) value.array.push_back(decode_item(depth + 1));
                } else {
                    uint64_t count = read_argument(info, &indefinite);
                    for (uint64_t i = 0; i < count; i++) value.array.push_back(decode_item(depth + 1));
                }
                return value;
            }
            case 5: {
                Value value;
                value.kind = Value::Kind::Map;
                if (info == 31) {
                    while (!at_break()) {
                        Value key = decode_item(depth + 1);
                        Value val = decode_item(depth + 1);
                        value.map.emplace_back(std::move(key), std::move(val));
                    }
                } else {
                    uint64_t count = read_argument(info, &indefinite);
                    for (uint64_t i = 0; i < count; i++) {
                        Value key = decode_item(depth + 1);
                        Value val = decode_item(depth + 1);
                        value.map.emplace_back(std::move(key), std::move(val));
                    }
                }
                return value;
            }
            case 6:
                // Tag numbers carry no information the model needs; unwrap.
                read_argument(info, &indefinite);
                if (indefinite) throw Error("indefinite-length CBOR tag");
                return decode_item(depth + 1);
            default: {
                switch (info) {
                    case 20: return Value::make_bool(false);
                    case 21: return Value::make_bool(true);
                    case 22:
                    case 23: return Value::make_null();
                    case 25: {
                        Value value;
                        value.kind        = Value::Kind::Float;
                        value.float_value = decode_half(static_cast<uint16_t>(read_big_endian(2)));
                        return value;
                    }
                    case 26: {
                        uint32_t raw = static_cast<uint32_t>(read_big_endian(4));
                        float single;
                        std::memcpy(&single, &raw, sizeof(single));
                        Value value;
                        value.kind        = Value::Kind::Float;
                        value.float_value = single;
                        return value;
                    }
                    case 27: {
                        uint64_t raw = read_big_endian(8);
                        Value value;
                        value.kind = Value::Kind::Float;
                        std::memcpy(&value.float_value, &raw, sizeof(value.float_value));
                        return value;
                    }
                    default: throw Error("unsupported CBOR simple value");
                }
            }
        }
    }

    const uint8_t *data_;
    size_t len_;
    size_t pos_ = 0;
};

void encode_header(uint8_t major, uint64_t argument, std::vector<uint8_t> *out) {
    uint8_t type = static_cast<uint8_t>(major << 5);
    if (argument < 24) {
        out->push_back(type | static_cast<uint8_t>(argument));
        return;
    }
    size_t width;
    uint8_t info;
    if (argument <= 0xFF) {
        width = 1;
        info  = 24;
    } else if (argument <= 0xFFFF) {
        width = 2;
        info  = 25;
    } else if (argument <= 0xFFFFFFFFULL) {
        width = 4;
        info  = 26;
    } else {
        width = 8;
        info  = 27;
    }
    out->push_back(type | info);
    for (size_t i = width; i > 0; i--) {
        out->push_back(static_cast<uint8_t>((argument >> ((i - 1) * 8)) & 0xFF));
    }
}

void encode_item(const Value &value, std::vector<uint8_t> *out) {
    switch (value.kind) {
        case Value::Kind::Unsigned: encode_header(0, value.unsigned_value, out); return;
        case Value::Kind::Negative: encode_header(1, value.negative_offset, out); return;
        case Value::Kind::Bytes:
            encode_header(2, value.bytes.size(), out);
            out->insert(out->end(), value.bytes.begin(), value.bytes.end());
            return;
        case Value::Kind::Text:
            encode_header(3, value.text.size(), out);
            out->insert(out->end(), value.text.begin(), value.text.end());
            return;
        case Value::Kind::Array:
            encode_header(4, value.array.size(), out);
            for (const auto &item : value.array) encode_item(item, out);
            return;
        case Value::Kind::Map:
            encode_header(5, value.map.size(), out);
            for (const auto &entry : value.map) {
                encode_item(entry.first, out);
                encode_item(entry.second, out);
            }
            return;
        case Value::Kind::Bool: out->push_back(value.bool_value ? 0xF5 : 0xF4); return;
        case Value::Kind::Null: out->push_back(0xF6); return;
        case Value::Kind::Float: {
            uint64_t raw;
            std::memcpy(&raw, &value.float_value, sizeof(raw));
            out->push_back(0xFB);
            for (size_t i = 8; i > 0; i--) {
                out->push_back(static_cast<uint8_t>((raw >> ((i - 1) * 8)) & 0xFF));
            }
            return;
        }
    }
}

}  // namespace

Value decode(const uint8_t *data, size_t len) {
    return Decoder(data, len).decode_all();
}

std::vector<uint8_t> encode(const Value &value) {
    std::vector<uint8_t> out;
    encode_item(value, &out);
    return out;
}

}  // namespace cbor
}  // namespace esdk_test_server
