// libFuzzer entry point for the PE parser.
#include <cstddef>
#include <cstdint>
#include <span>

#include "neden/pe.h"

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
  (void)neden::pe::parse(std::span<const std::uint8_t>(data, size));
  return 0;
}
