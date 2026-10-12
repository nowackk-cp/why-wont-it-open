#include "shell_menu.h"

#include <windows.h>
#include <shlobj.h>

#include <string>

#include "strings.h"

namespace gui {
namespace {

constexpr const wchar_t* kTypes[] = {L".exe", L".dll"};

std::wstring key_for(const wchar_t* ext) {
  return std::wstring(L"Software\Classes\SystemFileAssociations\\") + ext + L"\shell\WhyWontItOpen";
}

bool set_string(HKEY key, const wchar_t* name, const std::wstring& value) {
  return RegSetValueExW(key, name, 0, REG_SZ, reinterpret_cast<const BYTE*>(value.c_str()),
                        static_cast<DWORD>((value.size() + 1) * sizeof(wchar_t))) == ERROR_SUCCESS;
}

}  // namespace

bool register_shell_menu() {
  wchar_t exe[MAX_PATH];
  const DWORD n = GetModuleFileNameW(nullptr, exe, MAX_PATH);
  if (n == 0 || n >= MAX_PATH) return false;
  const std::wstring label = language() == neden::diagnose::Lang::Tr ? L"Neden açılmıyor?" : L"Why won't it open?";
  bool ok = true;
  for (const wchar_t* ext : kTypes) {
    HKEY verb = nullptr, command = nullptr;
    const std::wstring base = key_for(ext);
    if (RegCreateKeyExW(HKEY_CURRENT_USER, base.c_str(), 0, nullptr, 0, KEY_WRITE, nullptr, &verb, nullptr) !=
        ERROR_SUCCESS) {
      ok = false;
      continue;
    }
    ok &= set_string(verb, L"MUIVerb", label);
    ok &= set_string(verb, L"Icon", std::wstring(L"\"") + exe + L"\",0");
    RegCloseKey(verb);
    if (RegCreateKeyExW(HKEY_CURRENT_USER, (base + L"\command").c_str(), 0, nullptr, 0, KEY_WRITE, nullptr, &command,
                        nullptr) != ERROR_SUCCESS) {
      ok = false;
      continue;
    }
    ok &= set_string(command, nullptr, std::wstring(L"\"") + exe + L"\" \"%1\"");
    RegCloseKey(command);
  }
  SHChangeNotify(SHCNE_ASSOCCHANGED, SHCNF_IDLIST, nullptr, nullptr);
  return ok;
}

bool unregister_shell_menu() {
  bool ok = true;
  for (const wchar_t* ext : kTypes) {
    const LSTATUS st = RegDeleteTreeW(HKEY_CURRENT_USER, key_for(ext).c_str());
    ok &= st == ERROR_SUCCESS || st == ERROR_FILE_NOT_FOUND;
  }
  SHChangeNotify(SHCNE_ASSOCCHANGED, SHCNF_IDLIST, nullptr, nullptr);
  return ok;
}

}  // namespace gui
