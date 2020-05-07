// Copyright 2017 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/chromium_components_cbor/values.h"

#include <new>
#include <utility>

#include "glog/logging.h"
#include "third_party/chromium_components_cbor/constants.h"

namespace cbor {

Value::Value() noexcept : type_(Type::NONE) {}

Value::Value(Value&& that) noexcept {
  InternalMoveConstructFrom(std::move(that));
}

Value::Value(Type type) : type_(type) {
  // Initialize with the default value.
  switch (type_) {
    case Type::UNSIGNED:
    case Type::NEGATIVE:
      integer_value_ = 0;
      return;
    case Type::BYTE_STRING:
      new (&bytestring_value_) BinaryValue();
      return;
    case Type::STRING:
      new (&string_value_) std::string();
      return;
    case Type::ARRAY:
      new (&array_value_) ArrayValue();
      return;
    case Type::MAP:
      new (&map_value_) MapValue();
      return;
    case Type::TAG:
      LOG(ERROR) << constants::kUnsupportedMajorType;
      DCHECK(false);
      return;
    case Type::SIMPLE_VALUE:
      simple_value_ = Value::SimpleValue::UNDEFINED;
      return;
    case Type::NONE:
      return;
  }
  DCHECK(false);
}

Value::Value(SimpleValue in_simple)
    : type_(Type::SIMPLE_VALUE), simple_value_(in_simple) {
  CHECK(static_cast<int>(in_simple) >= 20 && static_cast<int>(in_simple) <= 23);
}

Value::Value(bool boolean_value) : type_(Type::SIMPLE_VALUE) {
  simple_value_ = boolean_value ? Value::SimpleValue::TRUE_VALUE
                                : Value::SimpleValue::FALSE_VALUE;
}

Value::Value(int integer_value) : Value(static_cast<int64_t>(integer_value)) {}

Value::Value(int64_t integer_value) : integer_value_(integer_value) {
  type_ = integer_value >= 0 ? Type::UNSIGNED : Type::NEGATIVE;
}

Value::Value(const BinaryValue& in_bytes)
    : type_(Type::BYTE_STRING),
      bytestring_value_(in_bytes.begin(), in_bytes.end()) {}

Value::Value(BinaryValue&& in_bytes) noexcept
    : type_(Type::BYTE_STRING), bytestring_value_(std::move(in_bytes)) {}

Value::Value(const char* in_string, Type type)
    : Value(std::string(in_string), type) {}

Value::Value(std::string&& in_string, Type type) noexcept : type_(type) {
  switch (type_) {
    case Type::STRING:
      // Removing a UTF-8 check here so we can test bad strings.
      new (&string_value_) std::string();
      string_value_ = std::move(in_string);
      break;
    case Type::BYTE_STRING:
      new (&bytestring_value_) BinaryValue();
      bytestring_value_ = BinaryValue(in_string.begin(), in_string.end());
      break;
    default:
      DCHECK(false);
  }
}

Value::Value(const std::string& in_string, Type type) : type_(type) {
  switch (type_) {
    case Type::STRING:
      new (&string_value_) std::string();
      string_value_ = in_string;
      break;
    case Type::BYTE_STRING:
      new (&bytestring_value_) BinaryValue();
      bytestring_value_ = BinaryValue(in_string.begin(), in_string.end());
      break;
    default:
      DCHECK(false);
  }
}

Value::Value(const ArrayValue& in_array) : type_(Type::ARRAY), array_value_() {
  array_value_.reserve(in_array.size());
  for (const auto& val : in_array)
    array_value_.emplace_back(val.Clone());
}

Value::Value(ArrayValue&& in_array) noexcept
    : type_(Type::ARRAY), array_value_(std::move(in_array)) {}

Value::Value(const MapValue& in_map) : type_(Type::MAP), map_value_() {
  for (const auto& it : in_map)
    map_value_.emplace_hint(map_value_.end(), it.first.Clone(),
                            it.second.Clone());
}

Value::Value(MapValue&& in_map) noexcept
    : type_(Type::MAP), map_value_(std::move(in_map)) {}

Value& Value::operator=(Value&& that) noexcept {
  InternalCleanup();
  InternalMoveConstructFrom(std::move(that));

  return *this;
}

Value::~Value() {
  InternalCleanup();
}

Value Value::Clone() const {
  switch (type_) {
    case Type::NONE:
      return Value();
    case Type::UNSIGNED:
    case Type::NEGATIVE:
      return Value(integer_value_);
    case Type::BYTE_STRING:
      return Value(bytestring_value_);
    case Type::STRING:
      return Value(string_value_);
    case Type::ARRAY:
      return Value(array_value_);
    case Type::MAP:
      return Value(map_value_);
    case Type::TAG:
      LOG(ERROR) << constants::kUnsupportedMajorType;
      DCHECK(false);
      return Value();
    case Type::SIMPLE_VALUE:
      return Value(simple_value_);
  }

  DCHECK(false);
  return Value();
}

Value::SimpleValue Value::GetSimpleValue() const {
  CHECK(is_simple());
  return simple_value_;
}

bool Value::GetBool() const {
  CHECK(is_bool());
  return simple_value_ == SimpleValue::TRUE_VALUE;
}

const int64_t& Value::GetInteger() const {
  CHECK(is_integer());
  return integer_value_;
}

const int64_t& Value::GetUnsigned() const {
  CHECK(is_unsigned());
  CHECK_GE(integer_value_, 0);
  return integer_value_;
}

const int64_t& Value::GetNegative() const {
  CHECK(is_negative());
  CHECK_LT(integer_value_, 0);
  return integer_value_;
}

const std::string& Value::GetString() const {
  CHECK(is_string());
  return string_value_;
}

const Value::BinaryValue& Value::GetBytestring() const {
  CHECK(is_bytestring());
  return bytestring_value_;
}

std::string Value::GetBytestringAsString() const {
  CHECK(is_bytestring());
  const auto& bytestring_value = GetBytestring();
  return std::string(reinterpret_cast<const char*>(bytestring_value.data()),
                     bytestring_value.size());
}

const Value::ArrayValue& Value::GetArray() const {
  CHECK(is_array());
  return array_value_;
}

const Value::MapValue& Value::GetMap() const {
  CHECK(is_map());
  return map_value_;
}

void Value::InternalMoveConstructFrom(Value&& that) {
  type_ = that.type_;

  switch (type_) {
    case Type::UNSIGNED:
    case Type::NEGATIVE:
      integer_value_ = that.integer_value_;
      return;
    case Type::BYTE_STRING:
      new (&bytestring_value_) BinaryValue(std::move(that.bytestring_value_));
      return;
    case Type::STRING:
      new (&string_value_) std::string(std::move(that.string_value_));
      return;
    case Type::ARRAY:
      new (&array_value_) ArrayValue(std::move(that.array_value_));
      return;
    case Type::MAP:
      new (&map_value_) MapValue(std::move(that.map_value_));
      return;
    case Type::TAG:
      LOG(ERROR) << constants::kUnsupportedMajorType;
      DCHECK(false);
      return;
    case Type::SIMPLE_VALUE:
      simple_value_ = that.simple_value_;
      return;
    case Type::NONE:
      return;
  }
  DCHECK(false);
}

void Value::InternalCleanup() {
  switch (type_) {
    case Type::BYTE_STRING:
      bytestring_value_.~BinaryValue();
      break;
    case Type::STRING:
      string_value_.~basic_string();
      break;
    case Type::ARRAY:
      array_value_.~ArrayValue();
      break;
    case Type::MAP:
      map_value_.~MapValue();
      break;
    case Type::TAG:
      LOG(ERROR) << constants::kUnsupportedMajorType;
      DCHECK(false);
      break;
    case Type::NONE:
    case Type::UNSIGNED:
    case Type::NEGATIVE:
    case Type::SIMPLE_VALUE:
      break;
  }
  type_ = Type::NONE;
}

}  // namespace cbor
