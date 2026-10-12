#include <windows.h>

#include <cstdio>
#include <filesystem>
#include <string>

#include "neden/fix.h"
#include "neden/kb.h"
#include "pe_builder.h"
#include "test.h"

namespace fix = neden::fix;
namespace fs = std::filesystem;

TEST(fix_url_allowed_positive) {
  CHECK(fix::is_allowed_url("https://aka.ms/vc14/vc_redist.x86.exe"));
  CHECK(fix::is_allowed_url("https://microsoft.com/"));
  CHECK(fix::is_allowed_url("https://www.microsoft.com/en-us/download/details.aspx?id=35"));
  CHECK(fix::is_allowed_url("https://download.microsoft.com/download/a/b/c/setup.exe"));
  CHECK(fix::is_allowed_url("https://download.visualstudio.microsoft.com/download/pr/x/VC_redist.x86.exe"));
  CHECK(fix::is_allowed_url("https://builds.dotnet.microsoft.com/dotnet/x/y.exe"));
  CHECK(fix::is_allowed_url("https://dotnet.microsoft.com/download/dotnet/8.0"));
  CHECK(fix::is_allowed_url("https://www.nvidia.com/en-us/drivers/physx/"));
  CHECK(fix::is_allowed_url("https://nvidia.com/x"));
  CHECK(fix::is_allowed_url("HTTPS://Download.Microsoft.COM/x.exe"));
  CHECK(fix::is_allowed_url("https://download.microsoft.com:443/x.exe"));
  CHECK(fix::is_allowed_url("https://aka.ms"));
}

TEST(fix_url_allowed_negative) {
  CHECK(!fix::is_allowed_url(""));
  CHECK(!fix::is_allowed_url("https://"));
  CHECK(!fix::is_allowed_url("http://download.microsoft.com/x.exe"));
  CHECK(!fix::is_allowed_url("ftp://download.microsoft.com/x.exe"));
  CHECK(!fix::is_allowed_url("//download.microsoft.com/x.exe"));
  CHECK(!fix::is_allowed_url("download.microsoft.com/x.exe"));
  CHECK(!fix::is_allowed_url("https://microsoft.com.evil.com/x.exe"));
  CHECK(!fix::is_allowed_url("https://evilmicrosoft.com/x.exe"));
  CHECK(!fix::is_allowed_url("https://notaka.ms/x.exe"));
  CHECK(!fix::is_allowed_url("https://aka.ms.evil.com/x.exe"));
  CHECK(!fix::is_allowed_url("https://user@microsoft.com/x.exe"));
  CHECK(!fix::is_allowed_url("https://user:pw@microsoft.com/x.exe"));
  CHECK(!fix::is_allowed_url("https://microsoft.com@evil.com/x.exe"));
  CHECK(!fix::is_allowed_url("https://evil.com#@microsoft.com/"));
  CHECK(!fix::is_allowed_url("https://evil.com/@microsoft.com/"));
  CHECK(!fix::is_allowed_url("https://evil.com?.microsoft.com/"));
  CHECK(!fix::is_allowed_url("https://evil.com\\@microsoft.com/"));
  CHECK(!fix::is_allowed_url("https://microsoft.com:8443/x.exe"));
  CHECK(!fix::is_allowed_url("https://microsoft.com:80/x.exe"));
  CHECK(!fix::is_allowed_url("https://microsoft.com:/x.exe"));
  CHECK(!fix::is_allowed_url("https://microsoft.com./x.exe"));
  CHECK(!fix::is_allowed_url("https://.microsoft.com/x.exe"));
  CHECK(!fix::is_allowed_url("https://a..microsoft.com/x.exe"));
  CHECK(!fix::is_allowed_url("https://[::1]/x.exe"));
  CHECK(!fix::is_allowed_url("https://127.0.0.1/x.exe"));
  CHECK(!fix::is_allowed_url("https://localhost/x.exe"));
  CHECK(!fix::is_allowed_url("https://azureedge.net/x.exe"));
  CHECK(!fix::is_allowed_url("https://github.com/x.exe"));
  CHECK(!fix::is_allowed_url("https://microsoft.com /x.exe"));
  CHECK(!fix::is_allowed_url("https://micro\xC5\x9Foft.com/x.exe"));
  CHECK(!fix::is_allowed_url(std::string("https://microsoft.com\0.evil.com/", 32)));
  CHECK(!fix::is_allowed_url(" https://microsoft.com/"));
}

TEST(fix_url_all_kb_urls_allowed) {
  const auto& kb = neden::kb::KnowledgeBase::embedded();
  REQUIRE(!kb.packages().empty());
  int count = 0;
  for (const auto& [id, pkg] : kb.packages()) {
    for (const auto& [arch, url] : pkg.url) {
      if (!fix::is_allowed_url(url)) std::fprintf(stderr, "not allowed: %s (%s)\n", url.c_str(), id.c_str());
      CHECK(fix::is_allowed_url(url));
      ++count;
    }
    if (!pkg.info_url.empty()) CHECK(fix::is_allowed_url(pkg.info_url));
  }
  CHECK(count > 0);
}

TEST(fix_winget_id_validation) {
  CHECK(fix::is_valid_winget_id("Microsoft.VCRedist.2015+.x86"));
  CHECK(fix::is_valid_winget_id("Microsoft.DotNet.DesktopRuntime.8"));
  CHECK(fix::is_valid_winget_id("a_b-c.D1"));
  CHECK(!fix::is_valid_winget_id(""));
  CHECK(!fix::is_valid_winget_id("a b"));
  CHECK(!fix::is_valid_winget_id("a&calc"));
  CHECK(!fix::is_valid_winget_id("a|b"));
  CHECK(!fix::is_valid_winget_id("a\"b"));
  CHECK(!fix::is_valid_winget_id("a;b"));
  CHECK(!fix::is_valid_winget_id("a%b"));
  CHECK(!fix::is_valid_winget_id("a\nb"));
  CHECK(!fix::is_valid_winget_id("a^b"));
  CHECK(!fix::is_valid_winget_id(std::string(129, 'a')));
  CHECK(fix::is_valid_winget_id(std::string(128, 'a')));
  CHECK(!fix::install_with_winget("x & calc").ok);
  CHECK(!fix::install_with_winget("").ok);
}

TEST(fix_all_kb_winget_ids_valid) {
  for (const auto& [id, pkg] : neden::kb::KnowledgeBase::embedded().packages()) {
    for (const auto& [arch, w] : pkg.winget) CHECK(fix::is_valid_winget_id(w));
  }
}

TEST(fix_verify_signature_signed_microsoft_file) {
  // Files with an embedded (not catalog-only) Microsoft signature.
  const wchar_t* candidates[] = {
      L"C:\\Program Files (x86)\\Microsoft Visual Studio\\Installer\\vswhere.exe",
      L"C:\\Program Files\\Microsoft Visual Studio\\Installer\\vswhere.exe",
  };
  bool tested = false;
  for (const wchar_t* c : candidates) {
    std::error_code ec;
    if (!fs::exists(c, ec)) continue;
    const auto sig = fix::verify_signature(c);
    CHECK(sig.valid);
    CHECK(sig.signer == "Microsoft Corporation");
    tested = true;
    break;
  }
  if (!tested) std::puts("note: no signed Microsoft sample file found; signature positive test skipped");
}

TEST(fix_verify_signature_unsigned_file) {
  neden_test::PeBuilder b;
  const fs::path p = fs::temp_directory_path() / L"neden-test-unsigned.exe";
  REQUIRE(neden_test::write_file(p, b.build()));
  const auto sig = fix::verify_signature(p);
  CHECK(!sig.valid);
  CHECK(sig.signer.empty());
  CHECK(sig.status != 0);
  std::error_code ec;
  fs::remove(p, ec);
}

TEST(fix_verify_signature_missing_file) {
  const auto sig = fix::verify_signature(L"C:\\definitely\\not\\here.exe");
  CHECK(!sig.valid);
}

TEST(fix_download_rejects_before_network) {
  // Rejected without any network access.
  CHECK(!fix::download_verify_run("http://download.microsoft.com/x.exe", "Microsoft Corporation").ok);
  CHECK(!fix::download_verify_run("https://evil.example.com/x.exe", "Microsoft Corporation").ok);
  CHECK(!fix::download_verify_run("https://aka.ms/x.exe", "").ok);
  fs::path out;
  CHECK(!fix::download_and_verify("https://microsoft.com.evil.com/x.exe", "Microsoft Corporation", {}, &out).ok);
  CHECK(out.empty());
}

// Real network round trip; opt-in with NEDEN_NETWORK_TESTS=1. Downloads and
// verifies the official VC++ x86 redistributable but never runs it.
TEST(fix_network_download_and_verify) {
  char flag[8] = {};
  if (GetEnvironmentVariableA("NEDEN_NETWORK_TESTS", flag, sizeof(flag)) == 0 || flag[0] != '1') return;
  std::filesystem::path file;
  const auto ok = neden::fix::download_and_verify("https://aka.ms/vc14/vc_redist.x86.exe", "Microsoft Corporation", {},
                                                  &file);
  CHECK(ok.ok);
  if (!ok.ok) std::fprintf(stderr, "  %s\n", ok.message.c_str());
  CHECK(std::filesystem::exists(file));
  std::error_code ec;
  std::filesystem::remove_all(file.parent_path(), ec);

  const auto wrong = neden::fix::download_and_verify("https://aka.ms/vc14/vc_redist.x86.exe", "Contoso Ltd", {}, &file);
  CHECK(!wrong.ok);
  CHECK(wrong.message.find("Contoso") != std::string::npos);
}
