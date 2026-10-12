#include <cstdio>
#include <string_view>

#include "neden/version.h"

namespace {

void print_usage() {
  std::puts(
      "Usage:\n"
      "  neden --version\n"
      "  neden info <file.exe>          (planned, M1)\n"
      "  neden check <file.exe> [--json] (planned, M2)");
}

}  // namespace

int main(int argc, char** argv) {
  if (argc < 2) {
    print_usage();
    return 1;
  }
  const std::string_view cmd = argv[1];
  if (cmd == "--version" || cmd == "-v") {
    std::printf("neden %.*s\n", static_cast<int>(neden::version().size()), neden::version().data());
    return 0;
  }
  print_usage();
  return 1;
}
