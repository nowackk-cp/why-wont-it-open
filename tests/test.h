// Minimal self-contained test framework; no external dependencies.
//
//   TEST(parses_imports) { CHECK(x == 1); REQUIRE(ptr != nullptr); }
#pragma once

#include <cstdio>
#include <functional>
#include <string>
#include <vector>

namespace neden_test {

struct TestCase {
  const char* name;
  std::function<void()> fn;
};

inline std::vector<TestCase>& registry() {
  static std::vector<TestCase> tests;
  return tests;
}

inline int& failures() {
  static int count = 0;
  return count;
}

struct Registrar {
  Registrar(const char* name, std::function<void()> fn) { registry().push_back({name, std::move(fn)}); }
};

struct RequireFailed {};

}  // namespace neden_test

#define NEDEN_TEST_CONCAT2(a, b) a##b
#define NEDEN_TEST_CONCAT(a, b) NEDEN_TEST_CONCAT2(a, b)

#define TEST(name)                                                                   \
  static void name();                                                                \
  static ::neden_test::Registrar NEDEN_TEST_CONCAT(registrar_, name)(#name, &name); \
  static void name()

#define CHECK(expr)                                                                  \
  do {                                                                               \
    if (!(expr)) {                                                                   \
      std::fprintf(stderr, "%s:%d: CHECK failed: %s\n", __FILE__, __LINE__, #expr);  \
      ++::neden_test::failures();                                                    \
    }                                                                                \
  } while (0)

#define REQUIRE(expr)                                                                \
  do {                                                                               \
    if (!(expr)) {                                                                   \
      std::fprintf(stderr, "%s:%d: REQUIRE failed: %s\n", __FILE__, __LINE__, #expr); \
      ++::neden_test::failures();                                                    \
      throw ::neden_test::RequireFailed{};                                           \
    }                                                                                \
  } while (0)
