#include "kb/json.h"

#include <cmath>
#include <cstdlib>
#include <exception>
#include <string>

namespace neden::json {

namespace {
const std::string kEmptyString;
const Value::Array kEmptyArray;
const Value::Object kEmptyObject;
}  // namespace

Value Value::boolean(bool b) {
  Value v;
  v.type_ = Type::Bool;
  v.bool_ = b;
  return v;
}
Value Value::number(double d) {
  Value v;
  v.type_ = Type::Number;
  v.number_ = d;
  return v;
}
Value Value::string(std::string s) {
  Value v;
  v.type_ = Type::String;
  v.string_ = std::move(s);
  return v;
}
Value Value::array(Array a) {
  Value v;
  v.type_ = Type::Array;
  v.array_ = std::move(a);
  return v;
}
Value Value::object(Object o) {
  Value v;
  v.type_ = Type::Object;
  v.object_ = std::move(o);
  return v;
}

const std::string& Value::as_string() const { return type_ == Type::String ? string_ : kEmptyString; }
const Value::Array& Value::as_array() const { return type_ == Type::Array ? array_ : kEmptyArray; }
const Value::Object& Value::as_object() const { return type_ == Type::Object ? object_ : kEmptyObject; }

const Value* Value::find(std::string_view key) const {
  if (type_ != Type::Object) return nullptr;
  for (auto it = object_.rbegin(); it != object_.rend(); ++it) {
    if (it->first == key) return &it->second;
  }
  return nullptr;
}

namespace {

class Parser {
 public:
  explicit Parser(std::string_view text) : s_(text) {}

  std::optional<Value> run(std::string* error) {
    if (s_.substr(0, 3) == "\xEF\xBB\xBF") pos_ = 3;  // skip UTF-8 BOM
    Value v;
    skip_ws();
    if (!parse_value(v, 0)) return fail(error);
    skip_ws();
    if (pos_ != s_.size()) {
      err("unexpected trailing characters");
      return fail(error);
    }
    return v;
  }

 private:
  std::optional<Value> fail(std::string* error) {
    if (error) *error = error_;
    return std::nullopt;
  }

  // Records the first error only; always returns false for convenient `return err(...)`.
  bool err(const char* msg) {
    if (!error_.empty()) return false;
    std::size_t line = 1, col = 1;
    for (std::size_t i = 0; i < pos_ && i < s_.size(); ++i) {
      if (s_[i] == '\n') {
        ++line;
        col = 1;
      } else if ((static_cast<unsigned char>(s_[i]) & 0xC0) != 0x80) {
        ++col;  // count code points, not UTF-8 continuation bytes
      }
    }
    error_ = "line " + std::to_string(line) + ", column " + std::to_string(col) + ": " + msg;
    return false;
  }

  bool eof() const { return pos_ >= s_.size(); }
  char peek() const { return s_[pos_]; }

  void skip_ws() {
    while (!eof() && (peek() == ' ' || peek() == '\t' || peek() == '\n' || peek() == '\r')) ++pos_;
  }

  bool literal(std::string_view word) {
    if (s_.substr(pos_, word.size()) != word) return err("invalid literal");
    pos_ += word.size();
    return true;
  }

  bool parse_value(Value& out, int depth) {
    if (depth > kMaxDepth) return err("nesting too deep");
    if (eof()) return err("unexpected end of input");
    switch (peek()) {
      case 'n':
        if (!literal("null")) return false;
        out = Value();
        return true;
      case 't':
        if (!literal("true")) return false;
        out = Value::boolean(true);
        return true;
      case 'f':
        if (!literal("false")) return false;
        out = Value::boolean(false);
        return true;
      case '"': {
        std::string str;
        if (!parse_string(str)) return false;
        out = Value::string(std::move(str));
        return true;
      }
      case '[':
        return parse_array(out, depth);
      case '{':
        return parse_object(out, depth);
      default:
        return parse_number(out);
    }
  }

  std::size_t digits() {
    std::size_t n = 0;
    while (!eof() && peek() >= '0' && peek() <= '9') {
      ++pos_;
      ++n;
    }
    return n;
  }

  bool parse_number(Value& out) {
    const std::size_t start = pos_;
    if (!eof() && peek() == '-') ++pos_;
    if (eof()) return err("invalid number");
    if (peek() == '0') {
      ++pos_;
    } else if (digits() == 0) {
      return err("invalid number");
    }
    if (!eof() && peek() == '.') {
      ++pos_;
      if (digits() == 0) return err("invalid number: digits expected after '.'");
    }
    if (!eof() && (peek() == 'e' || peek() == 'E')) {
      ++pos_;
      if (!eof() && (peek() == '+' || peek() == '-')) ++pos_;
      if (digits() == 0) return err("invalid number: digits expected in exponent");
    }
    const std::string text(s_.substr(start, pos_ - start));
    const double d = std::strtod(text.c_str(), nullptr);
    if (!std::isfinite(d)) {
      pos_ = start;
      return err("number out of range");
    }
    out = Value::number(d);
    return true;
  }

  bool hex4(unsigned& cp) {
    if (pos_ + 4 > s_.size()) return err("truncated \\u escape");
    cp = 0;
    for (int i = 0; i < 4; ++i) {
      const char c = s_[pos_ + static_cast<std::size_t>(i)];
      unsigned d;
      if (c >= '0' && c <= '9') d = static_cast<unsigned>(c - '0');
      else if (c >= 'a' && c <= 'f') d = static_cast<unsigned>(c - 'a' + 10);
      else if (c >= 'A' && c <= 'F') d = static_cast<unsigned>(c - 'A' + 10);
      else return err("invalid hex digit in \\u escape");
      cp = cp * 16 + d;
    }
    pos_ += 4;
    return true;
  }

  static void append_utf8(std::string& out, unsigned cp) {
    if (cp < 0x80) {
      out += static_cast<char>(cp);
    } else if (cp < 0x800) {
      out += static_cast<char>(0xC0 | (cp >> 6));
      out += static_cast<char>(0x80 | (cp & 0x3F));
    } else if (cp < 0x10000) {
      out += static_cast<char>(0xE0 | (cp >> 12));
      out += static_cast<char>(0x80 | ((cp >> 6) & 0x3F));
      out += static_cast<char>(0x80 | (cp & 0x3F));
    } else {
      out += static_cast<char>(0xF0 | (cp >> 18));
      out += static_cast<char>(0x80 | ((cp >> 12) & 0x3F));
      out += static_cast<char>(0x80 | ((cp >> 6) & 0x3F));
      out += static_cast<char>(0x80 | (cp & 0x3F));
    }
  }

  bool parse_string(std::string& out) {
    ++pos_;  // opening quote
    while (true) {
      if (eof()) return err("unterminated string");
      const unsigned char c = static_cast<unsigned char>(peek());
      if (c == '"') {
        ++pos_;
        return true;
      }
      if (c < 0x20) return err("control character in string");
      ++pos_;
      if (c != '\\') {
        out += static_cast<char>(c);
        continue;
      }
      if (eof()) return err("unterminated escape");
      const char e = peek();
      ++pos_;
      switch (e) {
        case '"': out += '"'; break;
        case '\\': out += '\\'; break;
        case '/': out += '/'; break;
        case 'b': out += '\b'; break;
        case 'f': out += '\f'; break;
        case 'n': out += '\n'; break;
        case 'r': out += '\r'; break;
        case 't': out += '\t'; break;
        case 'u': {
          unsigned cp;
          if (!hex4(cp)) return false;
          if (cp >= 0xD800 && cp <= 0xDBFF) {
            if (s_.substr(pos_, 2) != "\\u") return err("high surrogate without low surrogate");
            pos_ += 2;
            unsigned lo;
            if (!hex4(lo)) return false;
            if (lo < 0xDC00 || lo > 0xDFFF) return err("invalid low surrogate");
            cp = 0x10000 + ((cp - 0xD800) << 10) + (lo - 0xDC00);
          } else if (cp >= 0xDC00 && cp <= 0xDFFF) {
            return err("unpaired low surrogate");
          }
          append_utf8(out, cp);
          break;
        }
        default:
          --pos_;
          return err("invalid escape sequence");
      }
    }
  }

  bool parse_array(Value& out, int depth) {
    ++pos_;
    Value::Array items;
    skip_ws();
    if (!eof() && peek() == ']') {
      ++pos_;
      out = Value::array(std::move(items));
      return true;
    }
    while (true) {
      skip_ws();
      Value item;
      if (!parse_value(item, depth + 1)) return false;
      items.push_back(std::move(item));
      skip_ws();
      if (eof()) return err("unterminated array");
      if (peek() == ',') {
        ++pos_;
        continue;
      }
      if (peek() == ']') {
        ++pos_;
        out = Value::array(std::move(items));
        return true;
      }
      return err("expected ',' or ']'");
    }
  }

  bool parse_object(Value& out, int depth) {
    ++pos_;
    Value::Object members;
    skip_ws();
    if (!eof() && peek() == '}') {
      ++pos_;
      out = Value::object(std::move(members));
      return true;
    }
    while (true) {
      skip_ws();
      if (eof() || peek() != '"') return err("expected string key");
      std::string key;
      if (!parse_string(key)) return false;
      skip_ws();
      if (eof() || peek() != ':') return err("expected ':'");
      ++pos_;
      skip_ws();
      Value v;
      if (!parse_value(v, depth + 1)) return false;
      members.emplace_back(std::move(key), std::move(v));
      skip_ws();
      if (eof()) return err("unterminated object");
      if (peek() == ',') {
        ++pos_;
        continue;
      }
      if (peek() == '}') {
        ++pos_;
        out = Value::object(std::move(members));
        return true;
      }
      return err("expected ',' or '}'");
    }
  }

  std::string_view s_;
  std::size_t pos_ = 0;
  std::string error_;
};

}  // namespace

std::optional<Value> parse(std::string_view text, std::string* error) {
  try {
    return Parser(text).run(error);
  } catch (const std::exception& e) {  // e.g. bad_alloc
    if (error) *error = std::string("internal error: ") + e.what();
    return std::nullopt;
  }
}

}  // namespace neden::json
