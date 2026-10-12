// Small, strict JSON parser (RFC 8259). Never throws on bad input.
#pragma once

#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace neden::json {

class Value {
 public:
  enum class Type { Null, Bool, Number, String, Array, Object };
  using Array = std::vector<Value>;
  using Member = std::pair<std::string, Value>;
  using Object = std::vector<Member>;  // insertion order; with duplicate keys find() returns the last

  Value() = default;
  static Value boolean(bool b);
  static Value number(double d);
  static Value string(std::string s);
  static Value array(Array a);
  static Value object(Object o);

  Type type() const { return type_; }
  bool is_null() const { return type_ == Type::Null; }
  bool is_bool() const { return type_ == Type::Bool; }
  bool is_number() const { return type_ == Type::Number; }
  bool is_string() const { return type_ == Type::String; }
  bool is_array() const { return type_ == Type::Array; }
  bool is_object() const { return type_ == Type::Object; }

  // Accessors return a neutral value when the type does not match.
  bool as_bool() const { return type_ == Type::Bool && bool_; }
  double as_number() const { return type_ == Type::Number ? number_ : 0.0; }
  const std::string& as_string() const;
  const Array& as_array() const;
  const Object& as_object() const;

  // Object member lookup; nullptr if not an object or key absent.
  const Value* find(std::string_view key) const;

 private:
  Type type_ = Type::Null;
  bool bool_ = false;
  double number_ = 0.0;
  std::string string_;
  Array array_;
  Object object_;
};

inline constexpr int kMaxDepth = 64;

// Parses a complete document (trailing non-whitespace is an error).
// On failure returns nullopt and sets *error to "line L, column C: message".
std::optional<Value> parse(std::string_view text, std::string* error = nullptr);

}  // namespace neden::json
