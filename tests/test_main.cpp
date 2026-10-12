#include <cstring>

#include "test.h"

int main(int argc, char** argv) {
  const char* filter = argc > 1 ? argv[1] : nullptr;
  int run = 0;
  for (const auto& t : neden_test::registry()) {
    if (filter && !std::strstr(t.name, filter)) continue;
    ++run;
    const int before = neden_test::failures();
    try {
      t.fn();
    } catch (const neden_test::RequireFailed&) {
    } catch (const std::exception& e) {
      std::fprintf(stderr, "%s: unexpected exception: %s\n", t.name, e.what());
      ++neden_test::failures();
    }
    std::printf("[%s] %s\n", neden_test::failures() == before ? " ok " : "FAIL", t.name);
  }
  if (neden_test::failures() != 0) {
    std::fprintf(stderr, "%d check(s) failed\n", neden_test::failures());
    return 1;
  }
  std::printf("%d test(s) passed\n", run);
  return 0;
}
