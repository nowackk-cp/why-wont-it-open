# Usage: cmake -DIN=<file> -DOUT=<file.cpp> -P embed.cmake
# Writes the bytes of IN as a char array, avoiding MSVC string literal limits.
file(READ "${IN}" hex HEX)
string(LENGTH "${hex}" hex_len)
math(EXPR size "${hex_len} / 2")
string(REGEX REPLACE "([0-9a-f][0-9a-f])" "0x\\1," bytes "${hex}")
string(REGEX REPLACE "((0x[0-9a-f][0-9a-f],)(0x[0-9a-f][0-9a-f],)(0x[0-9a-f][0-9a-f],)(0x[0-9a-f][0-9a-f],)(0x[0-9a-f][0-9a-f],)(0x[0-9a-f][0-9a-f],)(0x[0-9a-f][0-9a-f],)(0x[0-9a-f][0-9a-f],))" "\\1\n" bytes "${bytes}")
file(WRITE "${OUT}" "// Generated from runtimes.json. Do not edit.\n#include <cstddef>\nnamespace neden::kb::detail {\nextern const unsigned char kEmbeddedKb[] = {\n${bytes}0x00};\nextern const std::size_t kEmbeddedKbSize = ${size};\n}  // namespace neden::kb::detail\n")
