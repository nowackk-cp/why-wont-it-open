#include <algorithm>

#include "neden/env.h"
#include "util/text.h"

namespace neden::env {

FakeEnvironment::FakeEnvironment() {
  known = {"kernel32.dll", "user32.dll", "gdi32.dll", "advapi32.dll", "ntdll.dll", "ole32.dll", "shell32.dll"};
}

std::wstring FakeEnvironment::key(const fs::path& p) {
  std::wstring s = p.lexically_normal().wstring();
  for (wchar_t& c : s) {
    if (c == L'/') c = L'\\';
    if (c >= L'A' && c <= L'Z') c = static_cast<wchar_t>(c - L'A' + L'a');
  }
  while (s.size() > 3 && s.back() == L'\\') s.pop_back();
  return s;
}

void FakeEnvironment::add_file(const fs::path& p, std::vector<std::uint8_t> bytes) {
  const std::wstring k = key(p);
  for (auto& [name, data] : files_) {
    if (name == k) {
      data = std::move(bytes);
      return;
    }
  }
  files_.emplace_back(k, std::move(bytes));
}

bool FakeEnvironment::file_exists(const fs::path& p) const {
  const std::wstring k = key(p);
  return std::any_of(files_.begin(), files_.end(), [&](const auto& f) { return f.first == k; });
}

bool FakeEnvironment::dir_exists(const fs::path& p) const {
  const std::wstring k = key(p) + L"\\";
  return std::any_of(files_.begin(), files_.end(), [&](const auto& f) { return f.first.starts_with(k); });
}

std::optional<std::vector<std::uint8_t>> FakeEnvironment::read_file(const fs::path& p, std::uint64_t max_bytes) const {
  const std::wstring k = key(p);
  for (const auto& [name, data] : files_) {
    if (name == k) {
      const auto n = static_cast<std::size_t>(std::min<std::uint64_t>(data.size(), max_bytes));
      return std::vector<std::uint8_t>(data.begin(), data.begin() + static_cast<std::ptrdiff_t>(n));
    }
  }
  return std::nullopt;
}

std::vector<std::string> FakeEnvironment::list_dir(const fs::path& dir, const std::string& prefix) const {
  const std::wstring k = key(dir) + L"\\";
  const std::wstring want = key(util::utf8_to_wide(prefix));
  std::vector<std::string> names;
  for (const auto& [name, data] : files_) {
    if (!name.starts_with(k)) continue;
    std::wstring rest = name.substr(k.size());
    rest = rest.substr(0, rest.find(L'\\'));  // immediate child (file or directory)
    if (!rest.starts_with(want)) continue;
    const std::string child = util::wide_to_utf8(rest);
    if (std::find(names.begin(), names.end(), child) == names.end()) names.push_back(child);
  }
  return names;
}

std::optional<std::string> FakeEnvironment::resolve_api_set(const std::string& name) const {
  const std::string lower = util::to_lower_ascii(name);
  for (const auto& [prefix, host] : api_sets) {
    if (lower.starts_with(util::to_lower_ascii(prefix))) return host;
  }
  return std::nullopt;
}

}  // namespace neden::env
