#include "fix_command.h"

#include <windows.h>

#include <cstdio>
#include <iostream>
#include <string>

#include "neden/diagnose.h"
#include "neden/env.h"
#include "neden/fix.h"
#include "neden/kb.h"

namespace {

std::string to_utf8(const std::wstring& w) {
  if (w.empty()) return {};
  const int n = WideCharToMultiByte(CP_UTF8, 0, w.data(), static_cast<int>(w.size()), nullptr, 0, nullptr, nullptr);
  if (n <= 0) return {};
  std::string out(static_cast<size_t>(n), '\0');
  WideCharToMultiByte(CP_UTF8, 0, w.data(), static_cast<int>(w.size()), out.data(), n, nullptr, nullptr);
  return out;
}

bool confirm() {
  std::fputs("Proceed? [y/N] ", stdout);
  std::fflush(stdout);
  std::string line;
  if (!std::getline(std::cin, line)) return false;
  return !line.empty() && (line[0] == 'y' || line[0] == 'Y');
}

}  // namespace

int run_fix_command(const std::vector<std::wstring>& args) {
  namespace diag = neden::diagnose;
  namespace fix = neden::fix;

  bool yes = false;
  std::wstring file;
  for (const std::wstring& a : args) {
    if (a == L"--yes" || a == L"-y") {
      yes = true;
    } else if (!a.empty() && a[0] == L'-') {
      std::fprintf(stderr, "Unknown option: %s\n", to_utf8(a).c_str());
      return 2;
    } else if (file.empty()) {
      file = a;
    } else {
      std::fputs("Usage: neden fix <file.exe> [--yes]\n", stderr);
      return 2;
    }
  }
  if (file.empty()) {
    std::fputs("Usage: neden fix <file.exe> [--yes]\n", stderr);
    return 2;
  }

  const auto env = neden::env::make_system_environment();
  const auto& kb = neden::kb::KnowledgeBase::embedded();
  const diag::Report report = diag::diagnose(file, *env, kb, diag::default_lang());

  int fixable = 0;
  int failed = 0;
  for (const diag::Finding& f : report.findings) {
    if (!f.fix || (f.fix->winget_id.empty() && f.fix->url.empty())) continue;
    ++fixable;
    const diag::Fix& fx = *f.fix;
    std::printf("\n%s\n", f.title.c_str());

    const bool use_winget = !fx.winget_id.empty() && fix::winget_available();
    std::string signer;
    if (!use_winget) {
      if (fx.url.empty()) {
        std::printf("  winget is not available and there is no direct download; see: %s\n", fx.info_url.c_str());
        ++failed;
        continue;
      }
      if (const auto* pkg = kb.find_package(fx.package_id)) signer = pkg->signer;
    }
    const std::string name = fx.package_name.empty() ? fx.package_id : fx.package_name;
    if (use_winget) {
      std::printf("  Planned action: winget install --id %s --exact --source winget (%s)\n", fx.winget_id.c_str(),
                  name.c_str());
    } else {
      std::printf("  Planned action: download %s\n    from %s\n    and run it if it is signed by \"%s\"\n",
                  name.c_str(), fx.url.c_str(), signer.c_str());
    }
    if (!yes && !confirm()) {
      std::puts("  Skipped.");
      continue;
    }

    fix::Outcome o;
    if (use_winget) {
      std::puts("  A winget window opens; accept the license prompts there if asked.");
      o = fix::install_with_winget(fx.winget_id);
    } else {
      int last_pct = -1;
      o = fix::download_verify_run(fx.url, signer, [&](std::uint64_t got, std::uint64_t total) {
        if (total > 0) {
          const int pct = static_cast<int>(got * 100 / total);
          if (pct != last_pct) {
            std::printf("\r  Downloading... %d%%", pct);
            std::fflush(stdout);
            last_pct = pct;
          }
        }
        return true;
      });
      if (last_pct >= 0) std::puts("");
    }
    std::printf("  %s: %s\n", o.ok ? "Done" : "Failed", o.message.c_str());
    if (!o.ok) ++failed;
  }

  if (fixable == 0) std::puts("Nothing to fix automatically.");
  return failed ? 1 : 0;
}
