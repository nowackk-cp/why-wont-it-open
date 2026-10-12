// Small text helpers shared by the core library.
#pragma once

#include <string>
#include <string_view>

namespace neden::util {

std::string to_lower_ascii(std::string_view s);
bool iequals(std::string_view a, std::string_view b);
std::string wide_to_utf8(std::wstring_view s);
std::wstring utf8_to_wide(std::string_view s);

}  // namespace neden::util
