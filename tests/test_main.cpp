// Minimal self-contained test runner; no external dependencies.
#include <cstdio>
#include <string_view>

#include "neden/version.h"

namespace {

int g_failures = 0;

#define CHECK(expr)                                                     \
  do {                                                                  \
    if (!(expr)) {                                                      \
      std::fprintf(stderr, "%s:%d: CHECK failed: %s\n", __FILE__, __LINE__, #expr); \
      ++g_failures;                                                     \
    }                                                                   \
  } while (0)

void test_version() {
  CHECK(!neden::version().empty());
  CHECK(neden::version().find('.') != std::string_view::npos);
}

}  // namespace

int main() {
  test_version();
  if (g_failures != 0) {
    std::fprintf(stderr, "%d check(s) failed\n", g_failures);
    return 1;
  }
  std::puts("all tests passed");
  return 0;
}
