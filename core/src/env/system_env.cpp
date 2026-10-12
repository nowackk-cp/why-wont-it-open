// Environment backed by the real machine.
//
// The tool ships as a 32-bit exe, so on 64-bit Windows it runs under WOW64 and
// sees a redirected file system and registry. All file access goes through
// physical(), which maps the native System32 to "Sysnative", and registry
// reads use KEY_WOW64_64KEY.
#include <windows.h>
#include <winternl.h>

#include <algorithm>
#include <cctype>
#include <cstring>
#include <cwctype>

#include "neden/env.h"
#include "util/text.h"

namespace neden::env {

namespace {

using util::to_lower_ascii;
using util::wide_to_utf8;

bool is_wow64_process() {
  BOOL wow64 = FALSE;
  return IsWow64Process(GetCurrentProcess(), &wow64) && wow64;
}

OsInfo query_os() {
  OsInfo info;
#ifdef _WIN64
  info.is_64bit = true;
#else
  info.is_64bit = is_wow64_process();
#endif
  using IsWow64Process2Fn = BOOL(WINAPI*)(HANDLE, USHORT*, USHORT*);
  auto* is_wow64_2 = reinterpret_cast<IsWow64Process2Fn>(
      reinterpret_cast<void*>(GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "IsWow64Process2")));
  USHORT process_machine = 0, native_machine = 0;
  if (is_wow64_2 && is_wow64_2(GetCurrentProcess(), &process_machine, &native_machine)) {
    info.is_arm64 = native_machine == 0xAA64;
    info.is_64bit = native_machine == 0x8664 || native_machine == 0xAA64;
  }

  using RtlGetVersionFn = LONG(WINAPI*)(OSVERSIONINFOW*);
  auto* rtl_get_version = reinterpret_cast<RtlGetVersionFn>(
      reinterpret_cast<void*>(GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "RtlGetVersion")));
  OSVERSIONINFOW v{};
  v.dwOSVersionInfoSize = sizeof(v);
  if (rtl_get_version && rtl_get_version(&v) == 0) {
    info.major = v.dwMajorVersion;
    info.minor = v.dwMinorVersion;
    info.build = v.dwBuildNumber;
  }
  return info;
}

std::wstring get_env(const wchar_t* name) {
  const DWORD n = GetEnvironmentVariableW(name, nullptr, 0);
  if (n == 0) return {};
  std::wstring s(n, L'\0');
  const DWORD written = GetEnvironmentVariableW(name, s.data(), n);
  s.resize(written);
  return s;
}

std::wstring expand(const std::wstring& s) {
  const DWORD n = ExpandEnvironmentStringsW(s.c_str(), nullptr, 0);
  if (n == 0) return s;
  std::wstring out(n, L'\0');
  const DWORD written = ExpandEnvironmentStringsW(s.c_str(), out.data(), n);
  if (written == 0) return s;
  out.resize(written - 1);
  return out;
}

bool starts_with_ci(const std::wstring& s, const std::wstring& prefix) {
  if (s.size() < prefix.size()) return false;
  return CompareStringOrdinal(s.c_str(), static_cast<int>(prefix.size()), prefix.c_str(),
                              static_cast<int>(prefix.size()), TRUE) == CSTR_EQUAL;
}

// --- API set schema (version 6, Windows 10+) -------------------------------

struct ApiSetNamespace {
  ULONG version, size, flags, count, entry_offset, hash_offset, hash_factor;
};
struct ApiSetNamespaceEntry {
  ULONG flags, name_offset, name_length, hashed_length, value_offset, value_count;
};
struct ApiSetValueEntry {
  ULONG flags, name_offset, name_length, value_offset, value_length;
};

const ApiSetNamespace* api_set_map() {
  const auto* peb = reinterpret_cast<const std::uint8_t*>(NtCurrentTeb()->ProcessEnvironmentBlock);
#ifdef _WIN64
  constexpr std::size_t kApiSetMapOffset = 0x68;
#else
  constexpr std::size_t kApiSetMapOffset = 0x38;
#endif
  const ApiSetNamespace* map = nullptr;
  std::memcpy(&map, peb + kApiSetMapOffset, sizeof(map));
  if (!map || map->version != 6) return nullptr;
  return map;
}

std::wstring api_set_string(const ApiSetNamespace* map, ULONG offset, ULONG length_bytes) {
  const auto* base = reinterpret_cast<const std::uint8_t*>(map);
  return std::wstring(reinterpret_cast<const wchar_t*>(base + offset), length_bytes / sizeof(wchar_t));
}

class SystemEnvironment final : public Environment {
 public:
  SystemEnvironment() : os_(query_os()), wow64_(is_wow64_process()) {
    wchar_t buf[MAX_PATH];
    const UINT n = GetSystemWindowsDirectoryW(buf, MAX_PATH);
    windows_ = (n > 0 && n < MAX_PATH) ? fs::path(buf) : fs::path(L"C:\\Windows");
  }

  OsInfo os() const override { return os_; }
  fs::path windows_dir() const override { return windows_; }
  fs::path system_dir() const override { return windows_ / L"System32"; }
  fs::path syswow64_dir() const override { return os_.is_64bit ? windows_ / L"SysWOW64" : fs::path(); }

  std::vector<fs::path> path_dirs() const override {
    std::vector<fs::path> dirs;
    const std::wstring path = get_env(L"PATH");
    std::size_t start = 0;
    while (start <= path.size()) {
      std::size_t end = path.find(L';', start);
      if (end == std::wstring::npos) end = path.size();
      std::wstring item = path.substr(start, end - start);
      item.erase(std::remove(item.begin(), item.end(), L'"'), item.end());
      while (!item.empty() && std::iswspace(item.back())) item.pop_back();
      while (!item.empty() && std::iswspace(item.front())) item.erase(item.begin());
      if (!item.empty()) dirs.emplace_back(expand(item));
      start = end + 1;
    }
    return dirs;
  }

  bool file_exists(const fs::path& p) const override {
    const DWORD attrs = GetFileAttributesW(physical(p).c_str());
    return attrs != INVALID_FILE_ATTRIBUTES && !(attrs & FILE_ATTRIBUTE_DIRECTORY);
  }

  bool dir_exists(const fs::path& p) const override {
    const DWORD attrs = GetFileAttributesW(physical(p).c_str());
    return attrs != INVALID_FILE_ATTRIBUTES && (attrs & FILE_ATTRIBUTE_DIRECTORY);
  }

  std::optional<std::vector<std::uint8_t>> read_file(const fs::path& p, std::uint64_t max_bytes) const override {
    HANDLE h = CreateFileW(physical(p).c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                           nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL | FILE_FLAG_SEQUENTIAL_SCAN, nullptr);
    if (h == INVALID_HANDLE_VALUE) return std::nullopt;
    LARGE_INTEGER size{};
    if (!GetFileSizeEx(h, &size)) {
      CloseHandle(h);
      return std::nullopt;
    }
    const std::uint64_t to_read = std::min<std::uint64_t>(static_cast<std::uint64_t>(size.QuadPart), max_bytes);
    std::vector<std::uint8_t> data(static_cast<std::size_t>(to_read));
    std::uint64_t done = 0;
    while (done < to_read) {
      const DWORD chunk = static_cast<DWORD>(std::min<std::uint64_t>(to_read - done, 1u << 24));
      DWORD got = 0;
      if (!ReadFile(h, data.data() + done, chunk, &got, nullptr) || got == 0) break;
      done += got;
    }
    CloseHandle(h);
    data.resize(static_cast<std::size_t>(done));
    return data;
  }

  std::vector<std::string> list_dir(const fs::path& dir, const std::string& prefix) const override {
    std::vector<std::string> names;
    const fs::path pattern = physical(dir) / (util::utf8_to_wide(prefix) + L"*");
    WIN32_FIND_DATAW fd;
    HANDLE h = FindFirstFileExW(pattern.c_str(), FindExInfoBasic, &fd, FindExSearchNameMatch, nullptr, 0);
    if (h == INVALID_HANDLE_VALUE) return names;
    do {
      const std::wstring name = fd.cFileName;
      if (name != L"." && name != L"..") names.push_back(wide_to_utf8(name));
    } while (FindNextFileW(h, &fd));
    FindClose(h);
    return names;
  }

  std::vector<std::string> known_dlls() const override {
    std::vector<std::string> dlls;
    HKEY key;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Control\\Session Manager\\KnownDLLs", 0,
                      KEY_READ | KEY_WOW64_64KEY, &key) != ERROR_SUCCESS) {
      return dlls;
    }
    for (DWORD i = 0;; ++i) {
      wchar_t name[256];
      wchar_t data[512];
      DWORD name_len = 256, data_len = sizeof(data), type = 0;
      const LSTATUS st =
          RegEnumValueW(key, i, name, &name_len, nullptr, &type, reinterpret_cast<BYTE*>(data), &data_len);
      if (st == ERROR_NO_MORE_ITEMS) break;
      if (st != ERROR_SUCCESS || type != REG_SZ) continue;
      std::wstring value(data, data_len / sizeof(wchar_t));
      while (!value.empty() && value.back() == L'\0') value.pop_back();
      std::string lower = to_lower_ascii(wide_to_utf8(value));
      if (lower.size() > 4 && lower.ends_with(".dll")) dlls.push_back(std::move(lower));
    }
    RegCloseKey(key);
    return dlls;
  }

  std::optional<std::string> resolve_api_set(const std::string& name) const override {
    const ApiSetNamespace* map = api_set_map();
    if (!map) return std::nullopt;
    std::wstring query = util::utf8_to_wide(to_lower_ascii(name));
    if (query.size() > 4 && query.ends_with(L".dll")) query.resize(query.size() - 4);

    const auto* base = reinterpret_cast<const std::uint8_t*>(map);
    const auto* entries = reinterpret_cast<const ApiSetNamespaceEntry*>(base + map->entry_offset);
    for (ULONG i = 0; i < map->count; ++i) {
      const ApiSetNamespaceEntry& e = entries[i];
      // hashed_length covers the name up to (not including) the last hyphen,
      // so "api-ms-win-core-file-l1-2-0" matches any "-l1-2-x" request.
      const std::wstring hashed = api_set_string(map, e.name_offset, e.hashed_length);
      if (query.size() < hashed.size() ||
          CompareStringOrdinal(query.c_str(), static_cast<int>(hashed.size()), hashed.c_str(),
                               static_cast<int>(hashed.size()), TRUE) != CSTR_EQUAL) {
        continue;
      }
      // The request must not continue past the last hyphen into another set name.
      if (query.size() > hashed.size() && query[hashed.size()] != L'-') continue;
      if (e.value_count == 0) return std::string();
      const auto* values = reinterpret_cast<const ApiSetValueEntry*>(base + e.value_offset);
      // The default host is the entry without an importing-module name.
      const ApiSetValueEntry* chosen = &values[e.value_count - 1];
      for (ULONG v = 0; v < e.value_count; ++v) {
        if (values[v].name_length == 0) {
          chosen = &values[v];
          break;
        }
      }
      if (chosen->value_length == 0) return std::string();
      return to_lower_ascii(wide_to_utf8(api_set_string(map, chosen->value_offset, chosen->value_length)));
    }
    return std::nullopt;
  }

  bool netfx35_installed() const override {
    return read_dword(L"SOFTWARE\\Microsoft\\NET Framework Setup\\NDP\\v3.5", L"Install").value_or(0) == 1;
  }

  bool netfx4_installed() const override {
    return read_dword(L"SOFTWARE\\Microsoft\\NET Framework Setup\\NDP\\v4\\Full", L"Release").has_value();
  }

  std::vector<DotnetFramework> dotnet_frameworks() const override {
    std::vector<DotnetFramework> result;
    const std::wstring pf64 = get_env(L"ProgramW6432");
    const std::wstring pf86 = get_env(L"ProgramFiles(x86)");
    const std::wstring pf = get_env(L"ProgramFiles");
    struct Root {
      std::wstring dir;
      const char* arch;
    };
    std::vector<Root> roots;
    if (os_.is_64bit) {
      if (!pf64.empty()) {
        if (os_.is_arm64) {
          roots.push_back({pf64 + L"\\dotnet", "arm64"});
          roots.push_back({pf64 + L"\\dotnet\\x64", "x64"});
        } else {
          roots.push_back({pf64 + L"\\dotnet", "x64"});
        }
      }
      if (!pf86.empty()) roots.push_back({pf86 + L"\\dotnet", "x86"});
    } else if (!pf.empty()) {
      roots.push_back({pf + L"\\dotnet", "x86"});
    }
    for (const auto& root : roots) {
      const fs::path shared = fs::path(root.dir) / L"shared";
      for (const std::string& fw : list_dir(shared, "")) {
        for (const std::string& ver : list_dir(shared / util::utf8_to_wide(fw), "")) {
          if (!ver.empty() && std::isdigit(static_cast<unsigned char>(ver[0]))) {
            result.push_back({fw, ver, root.arch});
          }
        }
      }
    }
    return result;
  }

 private:
  // Maps the native System32 to Sysnative when we are a WOW64 process.
  fs::path physical(const fs::path& p) const {
    if (!wow64_) return p;
    const std::wstring sys32 = (windows_ / L"System32").wstring();
    const std::wstring s = p.wstring();
    if (starts_with_ci(s, sys32) && (s.size() == sys32.size() || s[sys32.size()] == L'\\')) {
      return fs::path((windows_ / L"Sysnative").wstring() + s.substr(sys32.size()));
    }
    return p;
  }

  static std::optional<DWORD> read_dword(const wchar_t* subkey, const wchar_t* value) {
    DWORD data = 0, size = sizeof(data);
    if (RegGetValueW(HKEY_LOCAL_MACHINE, subkey, value, RRF_RT_REG_DWORD | RRF_SUBKEY_WOW6464KEY, nullptr, &data,
                     &size) != ERROR_SUCCESS) {
      return std::nullopt;
    }
    return data;
  }

  OsInfo os_;
  bool wow64_;
  fs::path windows_;
};

}  // namespace

std::unique_ptr<Environment> make_system_environment() { return std::make_unique<SystemEnvironment>(); }

}  // namespace neden::env
