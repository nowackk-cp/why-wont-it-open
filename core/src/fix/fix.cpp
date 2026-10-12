// One-click fixes: winget install, or a verified download of an official installer.
#include "neden/fix.h"

#include <windows.h>
#include <shellapi.h>
#include <softpub.h>
#include <wincrypt.h>
#include <wintrust.h>
#include <winhttp.h>

#include <algorithm>
#include <cstdio>
#include <cstring>
#include <random>
#include <string_view>
#include <system_error>
#include <vector>

#include "neden/version.h"
#include "util/text.h"

namespace neden::fix {

namespace fs = std::filesystem;

namespace {

constexpr std::uint64_t kMaxDownloadBytes = 500ull * 1024 * 1024;
constexpr int kMaxRedirects = 10;

std::string fmt_hex(const char* prefix, std::uint32_t code, const char* suffix = "") {
  char buf[96];
  std::snprintf(buf, sizeof(buf), "%s0x%08X%s", prefix, code, suffix);
  return buf;
}

Outcome failure(std::string msg, std::uint32_t code = 0) {
  Outcome o;
  o.ok = false;
  o.exit_code = code;
  o.message = std::move(msg);
  return o;
}

// Hosts (exact or any subdomain) that may serve official installers.
// microsoft.com covers download.microsoft.com, download.visualstudio.microsoft.com
// and builds.dotnet.microsoft.com (the targets the aka.ms links redirect to).
constexpr std::string_view kAllowedHosts[] = {"microsoft.com", "aka.ms", "nvidia.com"};

bool host_allowed(const std::string& host) {
  for (std::string_view d : kAllowedHosts) {
    if (host == d) return true;
    if (host.size() > d.size() && host.compare(host.size() - d.size(), d.size(), d) == 0 &&
        host[host.size() - d.size() - 1] == '.') {
      return true;
    }
  }
  return false;
}

struct ParsedUrl {
  std::string host;  // lower-case
  std::string path;  // starts with '/', includes query
};

bool parse_https_url(const std::string& url, ParsedUrl* out) {
  if (url.empty() || url.size() > 2048) return false;
  for (unsigned char c : url) {
    if (c <= 0x20 || c >= 0x7F || c == '\\') return false;
  }
  constexpr std::string_view kScheme = "https://";
  if (url.size() <= kScheme.size() || !util::iequals(std::string_view(url).substr(0, kScheme.size()), kScheme)) {
    return false;
  }
  const size_t auth_begin = kScheme.size();
  size_t auth_end = url.find_first_of("/?#", auth_begin);
  if (auth_end == std::string::npos) auth_end = url.size();
  std::string authority = url.substr(auth_begin, auth_end - auth_begin);
  if (authority.empty() || authority.find('@') != std::string::npos) return false;

  std::string host = authority;
  const size_t colon = authority.find(':');
  if (colon != std::string::npos) {
    if (authority.substr(colon + 1) != "443") return false;  // default port only
    host = authority.substr(0, colon);
  }
  if (host.empty() || host.front() == '.' || host.back() == '.' || host.find("..") != std::string::npos) return false;
  for (char c : host) {
    const bool ok = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-' || c == '.';
    if (!ok) return false;
  }
  host = util::to_lower_ascii(host);
  if (!host_allowed(host)) return false;

  if (out) {
    out->host = host;
    std::string rest = url.substr(auth_end);
    const size_t frag = rest.find('#');
    if (frag != std::string::npos) rest.resize(frag);
    if (rest.empty() || rest[0] == '?') rest.insert(rest.begin(), '/');
    out->path = rest;
  }
  return true;
}

// ---- file system helpers ---------------------------------------------------

void remove_with_retry(const fs::path& file, const fs::path& dir) {
  std::error_code ec;
  for (int i = 0; i < 20; ++i) {
    if (!file.empty()) fs::remove(file, ec);
    if (!file.empty() && fs::exists(file, ec)) {
      Sleep(250);
      continue;
    }
    break;
  }
  if (!dir.empty()) {
    for (int i = 0; i < 20; ++i) {
      fs::remove_all(dir, ec);
      if (!fs::exists(dir, ec)) break;
      Sleep(250);
    }
  }
}

bool make_unique_dir(fs::path* out) {
  wchar_t tmp[MAX_PATH + 2];
  const DWORD n = GetTempPathW(MAX_PATH + 1, tmp);
  if (n == 0 || n > MAX_PATH) return false;
  std::random_device rd;
  for (int i = 0; i < 16; ++i) {
    wchar_t name[48];
    swprintf(name, 48, L"neden-%08x%08x", rd(), rd());
    fs::path p = fs::path(tmp) / name;
    if (CreateDirectoryW(p.c_str(), nullptr)) {
      *out = p;
      return true;
    }
    if (GetLastError() != ERROR_ALREADY_EXISTS) return false;
  }
  return false;
}

std::string url_file_name(const std::string& url) {
  size_t end = url.find_first_of("?#");
  if (end == std::string::npos) end = url.size();
  const size_t scheme = url.find("://");
  const size_t start_search = scheme == std::string::npos ? 0 : scheme + 3;
  const size_t slash = url.rfind('/', end == 0 ? 0 : end - 1);
  std::string name = (slash == std::string::npos || slash < start_search) ? std::string() : url.substr(slash + 1, end - slash - 1);
  std::string clean;
  for (char c : name) {
    const bool ok = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '.' ||
                    c == '-' || c == '_';
    if (ok) clean.push_back(c);
  }
  while (!clean.empty() && clean.front() == '.') clean.erase(clean.begin());
  if (clean.size() > 100) clean.resize(100);
  return clean;
}

bool has_installer_ext(const std::string& name) {
  if (name.size() < 5) return false;
  const std::string ext = util::to_lower_ascii(name.substr(name.size() - 4));
  return ext == ".exe" || ext == ".msi";
}

// ---- WinHTTP download ------------------------------------------------------

struct Handle {
  HINTERNET h = nullptr;
  Handle() = default;
  explicit Handle(HINTERNET x) : h(x) {}
  Handle(const Handle&) = delete;
  Handle& operator=(const Handle&) = delete;
  ~Handle() {
    if (h) WinHttpCloseHandle(h);
  }
};

std::string query_header(HINTERNET req, DWORD what) {
  DWORD len = 0;
  WinHttpQueryHeaders(req, what, WINHTTP_HEADER_NAME_BY_INDEX, WINHTTP_NO_OUTPUT_BUFFER, &len, WINHTTP_NO_HEADER_INDEX);
  if (GetLastError() != ERROR_INSUFFICIENT_BUFFER || len == 0) return {};
  std::wstring w(len / sizeof(wchar_t) + 1, L'\0');
  if (!WinHttpQueryHeaders(req, what, WINHTTP_HEADER_NAME_BY_INDEX, w.data(), &len, WINHTTP_NO_HEADER_INDEX)) return {};
  w.resize(len / sizeof(wchar_t));
  return util::wide_to_utf8(w);
}

// Resolves a Location header against the current URL.
std::string resolve_location(const std::string& base, const ParsedUrl& base_parsed, const std::string& loc) {
  if (loc.empty()) return {};
  if (loc.size() >= 2 && loc[0] == '/' && loc[1] == '/') return "https:" + loc;
  if (loc[0] == '/') return "https://" + base_parsed.host + loc;
  if (loc.find("://") != std::string::npos) return loc;
  std::string path = base_parsed.path;
  const size_t q = path.find('?');
  if (q != std::string::npos) path.resize(q);
  const size_t slash = path.rfind('/');
  (void)base;
  return "https://" + base_parsed.host + path.substr(0, slash + 1) + loc;
}

Outcome download_file(const std::string& start_url, const Progress& progress, fs::path* out_file) {
  const std::wstring agent = L"WhyWontItOpen/" + util::utf8_to_wide(std::string(neden::version()));
  Handle session(WinHttpOpen(agent.c_str(), WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY, WINHTTP_NO_PROXY_NAME,
                             WINHTTP_NO_PROXY_BYPASS, 0));
  if (!session.h) return failure("could not initialise WinHTTP (error " + std::to_string(GetLastError()) + ")");
  DWORD protocols = WINHTTP_FLAG_SECURE_PROTOCOL_TLS1_2;
#ifdef WINHTTP_FLAG_SECURE_PROTOCOL_TLS1_3
  protocols |= WINHTTP_FLAG_SECURE_PROTOCOL_TLS1_3;
#endif
  WinHttpSetOption(session.h, WINHTTP_OPTION_SECURE_PROTOCOLS, &protocols, sizeof(protocols));
  WinHttpSetTimeouts(session.h, 15000, 15000, 30000, 30000);

  std::string url = start_url;
  for (int hop = 0; hop <= kMaxRedirects; ++hop) {
    ParsedUrl pu;
    if (!parse_https_url(url, &pu)) {
      return failure("refusing to download from a host that is not on the allow-list: " + url);
    }
    const std::wstring whost = util::utf8_to_wide(pu.host);
    const std::wstring wpath = util::utf8_to_wide(pu.path);

    Handle conn(WinHttpConnect(session.h, whost.c_str(), INTERNET_DEFAULT_HTTPS_PORT, 0));
    if (!conn.h) return failure("could not connect to " + pu.host);
    Handle req(WinHttpOpenRequest(conn.h, L"GET", wpath.c_str(), nullptr, WINHTTP_NO_REFERER,
                                  WINHTTP_DEFAULT_ACCEPT_TYPES, WINHTTP_FLAG_SECURE));
    if (!req.h) return failure("could not create the HTTP request");
    DWORD policy = WINHTTP_OPTION_REDIRECT_POLICY_NEVER;
    WinHttpSetOption(req.h, WINHTTP_OPTION_REDIRECT_POLICY, &policy, sizeof(policy));

    if (!WinHttpSendRequest(req.h, WINHTTP_NO_ADDITIONAL_HEADERS, 0, WINHTTP_NO_REQUEST_DATA, 0, 0, 0) ||
        !WinHttpReceiveResponse(req.h, nullptr)) {
      return failure("download failed: network error " + std::to_string(GetLastError()) + " contacting " + pu.host);
    }
    DWORD status = 0;
    DWORD sz = sizeof(status);
    if (!WinHttpQueryHeaders(req.h, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
                             WINHTTP_HEADER_NAME_BY_INDEX, &status, &sz, WINHTTP_NO_HEADER_INDEX)) {
      return failure("download failed: no HTTP status");
    }

    if (status == 301 || status == 302 || status == 303 || status == 307 || status == 308) {
      if (hop == kMaxRedirects) return failure("download failed: too many redirects");
      const std::string loc = query_header(req.h, WINHTTP_QUERY_LOCATION);
      url = resolve_location(url, pu, loc);
      if (url.empty()) return failure("download failed: redirect without a target");
      continue;  // next loop iteration re-checks the allow-list
    }
    if (status != 200) return failure("download failed: HTTP status " + std::to_string(status));

    // Pick the file name (final URL first, then the original one).
    std::string name = url_file_name(url);
    if (!has_installer_ext(name)) name = url_file_name(start_url);
    if (!has_installer_ext(name)) {
      return failure("refusing to download: the file is not an .exe or .msi installer");
    }

    std::uint64_t total = 0;
    {
      const std::string cl = query_header(req.h, WINHTTP_QUERY_CONTENT_LENGTH);
      if (!cl.empty()) total = std::strtoull(cl.c_str(), nullptr, 10);
    }
    if (total > kMaxDownloadBytes) return failure("refusing to download: file is larger than 500 MB");

    fs::path dir;
    if (!make_unique_dir(&dir)) return failure("could not create a temporary folder");
    const fs::path file = dir / util::utf8_to_wide(name);
    HANDLE hf = CreateFileW(file.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (hf == INVALID_HANDLE_VALUE) {
      remove_with_retry({}, dir);
      return failure("could not create the download file");
    }

    std::uint64_t received = 0;
    std::vector<char> buf(64 * 1024);
    std::string err;
    for (;;) {
      DWORD got = 0;
      if (!WinHttpReadData(req.h, buf.data(), static_cast<DWORD>(buf.size()), &got)) {
        err = "download interrupted (network error " + std::to_string(GetLastError()) + ")";
        break;
      }
      if (got == 0) break;
      received += got;
      if (received > kMaxDownloadBytes) {
        err = "download aborted: file is larger than 500 MB";
        break;
      }
      DWORD written = 0;
      if (!WriteFile(hf, buf.data(), got, &written, nullptr) || written != got) {
        err = "could not write the download to disk";
        break;
      }
      if (progress && !progress(received, total)) {
        err = "cancelled";
        break;
      }
    }
    CloseHandle(hf);
    if (err.empty() && total != 0 && received != total) err = "download incomplete";
    if (!err.empty()) {
      remove_with_retry(file, dir);
      return failure(err);
    }
    if (progress) progress(received, total ? total : received);
    *out_file = file;
    Outcome ok;
    ok.ok = true;
    ok.message = "downloaded";
    return ok;
  }
  return failure("download failed: too many redirects");
}

}  // namespace

// ---- winget ----------------------------------------------------------------

bool winget_available() {
  wchar_t found[MAX_PATH];
  if (SearchPathW(nullptr, L"winget.exe", nullptr, MAX_PATH, found, nullptr) != 0) return true;
  wchar_t base[MAX_PATH];
  const DWORD n = GetEnvironmentVariableW(L"LOCALAPPDATA", base, MAX_PATH);
  if (n == 0 || n >= MAX_PATH) return false;
  const fs::path p = fs::path(base) / L"Microsoft" / L"WindowsApps" / L"winget.exe";
  // App execution aliases are reparse points; attributes are enough.
  return GetFileAttributesW(p.c_str()) != INVALID_FILE_ATTRIBUTES;
}

bool is_valid_winget_id(const std::string& id) {
  if (id.empty() || id.size() > 128) return false;
  for (char c : id) {
    const bool ok = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '.' ||
                    c == '+' || c == '-' || c == '_';
    if (!ok) return false;
  }
  return true;
}

Outcome install_with_winget(const std::string& winget_id) {
  try {
    if (!is_valid_winget_id(winget_id)) return failure("invalid winget package id");

    std::wstring exe;
    wchar_t found[MAX_PATH];
    if (SearchPathW(nullptr, L"winget.exe", nullptr, MAX_PATH, found, nullptr) != 0) {
      exe = found;
    } else {
      wchar_t base[MAX_PATH];
      const DWORD n = GetEnvironmentVariableW(L"LOCALAPPDATA", base, MAX_PATH);
      if (n > 0 && n < MAX_PATH) {
        const fs::path p = fs::path(base) / L"Microsoft" / L"WindowsApps" / L"winget.exe";
        if (GetFileAttributesW(p.c_str()) != INVALID_FILE_ATTRIBUTES) exe = p.wstring();
      }
    }
    if (exe.empty()) return failure("winget is not available on this computer");

    std::wstring cmd = L"\"" + exe + L"\" install --id " + util::utf8_to_wide(winget_id) +
                       L" --exact --source winget";
    STARTUPINFOW si{};
    si.cb = sizeof(si);
    PROCESS_INFORMATION pi{};
    if (!CreateProcessW(nullptr, cmd.data(), nullptr, nullptr, FALSE, CREATE_NEW_CONSOLE, nullptr, nullptr, &si, &pi)) {
      return failure("could not start winget (error " + std::to_string(GetLastError()) + ")");
    }
    CloseHandle(pi.hThread);
    WaitForSingleObject(pi.hProcess, INFINITE);
    DWORD code = 0;
    GetExitCodeProcess(pi.hProcess, &code);
    CloseHandle(pi.hProcess);

    Outcome o;
    o.exit_code = code;
    if (code == 0) {
      o.ok = true;
      o.message = "installed with winget";
    } else if (code == 0x8A15002Bu || code == 0x8A150061u) {
      o.ok = true;
      o.message = "already installed or no applicable update (winget " + fmt_hex("", code) + ")";
    } else {
      o.ok = false;
      o.message = fmt_hex("winget exited with ", code);
    }
    return o;
  } catch (...) {
    return failure("unexpected error while running winget");
  }
}

// ---- URL allow-list --------------------------------------------------------

bool is_allowed_url(const std::string& url) {
  try {
    return parse_https_url(url, nullptr);
  } catch (...) {
    return false;
  }
}

// ---- signature -------------------------------------------------------------

SignatureInfo verify_signature(const fs::path& file) {
  SignatureInfo info;
  try {
    WINTRUST_FILE_INFO fi{};
    fi.cbStruct = sizeof(fi);
    const std::wstring path = file.wstring();
    fi.pcwszFilePath = path.c_str();

    WINTRUST_DATA wd{};
    wd.cbStruct = sizeof(wd);
    wd.dwUIChoice = WTD_UI_NONE;
    wd.fdwRevocationChecks = WTD_REVOKE_WHOLECHAIN;
    wd.dwUnionChoice = WTD_CHOICE_FILE;
    wd.pFile = &fi;
    wd.dwStateAction = WTD_STATEACTION_VERIFY;
    wd.dwProvFlags = WTD_REVOCATION_CHECK_CHAIN;

    GUID action = WINTRUST_ACTION_GENERIC_VERIFY_V2;
    const LONG status = WinVerifyTrust(nullptr, &action, &wd);
    info.status = static_cast<std::uint32_t>(status);
    info.valid = status == ERROR_SUCCESS;

    if (wd.hWVTStateData) {
      CRYPT_PROVIDER_DATA* pd = WTHelperProvDataFromStateData(wd.hWVTStateData);
      if (pd) {
        CRYPT_PROVIDER_SGNR* sg = WTHelperGetProvSignerFromChain(pd, 0, FALSE, 0);
        if (sg && sg->csCertChain > 0 && sg->pasCertChain && sg->pasCertChain[0].pCert) {
          const CERT_CONTEXT* leaf = sg->pasCertChain[0].pCert;
          const DWORD n = CertGetNameStringW(leaf, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, nullptr, nullptr, 0);
          if (n > 1) {
            std::wstring name(n, L'\0');
            CertGetNameStringW(leaf, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, nullptr, name.data(), n);
            name.resize(n - 1);
            info.signer = util::wide_to_utf8(name);
          }
        }
      }
    }
    wd.dwStateAction = WTD_STATEACTION_CLOSE;
    WinVerifyTrust(nullptr, &action, &wd);
  } catch (...) {
    info.valid = false;
  }
  return info;
}

// ---- download, verify, run -------------------------------------------------

Outcome download_and_verify(const std::string& url, const std::string& expected_signer, const Progress& progress,
                            fs::path* out) {
  try {
    if (expected_signer.empty()) return failure("no expected signer is known for this download; refusing to run it");
    if (!is_allowed_url(url)) return failure("refusing to download from a host that is not on the allow-list: " + url);

    fs::path file;
    Outcome dl = download_file(url, progress, &file);
    if (!dl.ok) return dl;

    const SignatureInfo sig = verify_signature(file);
    if (!sig.valid) {
      remove_with_retry(file, file.parent_path());
      return failure("signature invalid (" + fmt_hex("status ", sig.status, ")") + "; the file was deleted", sig.status);
    }
    if (!util::iequals(sig.signer, expected_signer)) {
      remove_with_retry(file, file.parent_path());
      return failure("signed by " + sig.signer + ", expected " + expected_signer + "; the file was deleted");
    }
    if (out) *out = file;
    Outcome ok;
    ok.ok = true;
    ok.message = "downloaded; signature valid, signed by " + sig.signer;
    return ok;
  } catch (...) {
    return failure("unexpected error while downloading");
  }
}

Outcome download_verify_run(const std::string& url, const std::string& expected_signer, const Progress& progress) {
  fs::path file;
  try {
    Outcome v = download_and_verify(url, expected_signer, progress, &file);
    if (!v.ok) return v;

    const bool is_msi = util::to_lower_ascii(file.extension().string()) == ".msi";
    std::wstring params;
    SHELLEXECUTEINFOW sei{};
    sei.cbSize = sizeof(sei);
    sei.fMask = SEE_MASK_NOCLOSEPROCESS | SEE_MASK_NOASYNC;
    sei.lpVerb = L"open";
    sei.nShow = SW_SHOWNORMAL;
    const std::wstring wfile = file.wstring();
    const std::wstring wdir = file.parent_path().wstring();
    if (is_msi) {
      params = L"/i \"" + wfile + L"\"";
      sei.lpFile = L"msiexec.exe";
      sei.lpParameters = params.c_str();
    } else {
      sei.lpFile = wfile.c_str();
    }
    sei.lpDirectory = wdir.c_str();

    Outcome o;
    if (!ShellExecuteExW(&sei)) {
      const DWORD err = GetLastError();
      remove_with_retry(file, file.parent_path());
      if (err == ERROR_CANCELLED) return failure("cancelled: the administrator prompt was declined", err);
      return failure("could not start the installer (error " + std::to_string(err) + ")", err);
    }
    DWORD code = 0;
    if (sei.hProcess) {
      WaitForSingleObject(sei.hProcess, INFINITE);
      GetExitCodeProcess(sei.hProcess, &code);
      CloseHandle(sei.hProcess);
    }
    remove_with_retry(file, file.parent_path());

    o.exit_code = code;
    if (code == 0) {
      o.ok = true;
      o.message = "installed";
    } else if (code == 1638) {
      o.ok = true;
      o.message = "a newer version is already installed";
    } else if (code == 3010) {
      o.ok = true;
      o.message = "installed; a restart is required to finish";
    } else if (code == 1602 || code == 1223) {
      o.message = "cancelled by the user";
    } else {
      o.message = "installer exited with code " + std::to_string(code) + " (" + fmt_hex("", code) + ")";
    }
    return o;
  } catch (...) {
    if (!file.empty()) {
      try {
        remove_with_retry(file, file.parent_path());
      } catch (...) {
      }
    }
    return failure("unexpected error while running the installer");
  }
}

}  // namespace neden::fix
