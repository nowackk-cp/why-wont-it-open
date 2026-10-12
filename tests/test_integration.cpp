// Integration tests: real binaries built by the MSVC linker (tests/samples),
// arranged into scenario folders and analysed on the real machine.
#include <windows.h>

#include <filesystem>
#include <random>

#include "neden/diagnose.h"
#include "neden/env.h"
#include "neden/kb.h"
#include "test.h"

namespace fs = std::filesystem;
using neden::diagnose::Lang;
using neden::diagnose::Report;

namespace {

// A temporary folder that is removed again at the end of the test.
struct Scenario {
  fs::path dir;

  Scenario() {
    std::random_device rd;
    dir = fs::temp_directory_path() / ("neden-it-" + std::to_string(rd()));
    fs::create_directories(dir);
    fs::copy_file(NEDEN_SAMPLE_APP, dir / "app.exe");
  }
  ~Scenario() {
    std::error_code ec;
    fs::remove_all(dir, ec);
  }

  Report check() const {
    const auto env = neden::env::make_system_environment();
    return neden::diagnose::diagnose(dir / "app.exe", *env, neden::kb::KnowledgeBase::embedded(), Lang::En);
  }
};

bool has_rule(const Report& r, std::string_view rule) {
  for (const auto& f : r.findings) {
    if (f.rule == rule) return true;
  }
  return false;
}

// A native 64-bit system DLL (seen through Sysnative from this 32-bit test).
fs::path native_64bit_dll() {
  wchar_t windir[MAX_PATH];
  if (!GetWindowsDirectoryW(windir, MAX_PATH)) return {};
  const fs::path p = fs::path(windir) / "Sysnative" / "version.dll";
  return fs::exists(p) ? p : fs::path();
}

}  // namespace

TEST(integration_app_with_its_dll_is_clean) {
  Scenario s;
  fs::copy_file(NEDEN_FAKEDEP_FULL, s.dir / "fakedep.dll");
  const Report r = s.check();
  CHECK(!r.has_errors());
  CHECK(r.program_arch == "x86");
}

TEST(integration_missing_program_dll) {
  Scenario s;
  const Report r = s.check();
  CHECK(r.has_errors());
  CHECK(has_rule(r, "missing-program-file"));
}

TEST(integration_old_dll_lacks_entry_point) {
  Scenario s;
  fs::copy_file(NEDEN_FAKEDEP_OLD, s.dir / "fakedep.dll");
  const Report r = s.check();
  CHECK(has_rule(r, "missing-export"));
  const auto* m = r.resolution.find("fakedep.dll");
  REQUIRE(m != nullptr);
  REQUIRE(m->missing_functions.size() == 1);
  CHECK(m->missing_functions[0].function == "fakedep_run");
}

TEST(integration_wrong_architecture_dll) {
  const fs::path x64 = native_64bit_dll();
  if (x64.empty()) {
    std::puts("  (skipped: not 64-bit Windows)");
    return;
  }
  Scenario s;
  fs::copy_file(x64, s.dir / "fakedep.dll");
  const Report r = s.check();
  CHECK(has_rule(r, "wrong-arch"));
}

TEST(integration_damaged_dll) {
  Scenario s;
  {
    std::FILE* f = nullptr;
    _wfopen_s(&f, (s.dir / "fakedep.dll").c_str(), L"wb");
    REQUIRE(f != nullptr);
    std::fputs("this is not a dll", f);
    std::fclose(f);
  }
  CHECK(has_rule(s.check(), "corrupt-dll"));
}

TEST(integration_dynamic_crt_program_on_this_machine) {
  // Whatever this machine has installed, the analysis must not crash, and if
  // the VC++ runtime is reported missing it must be the x86 package.
  const auto env = neden::env::make_system_environment();
  const Report r =
      neden::diagnose::diagnose(NEDEN_SAMPLE_CRT, *env, neden::kb::KnowledgeBase::embedded(), Lang::En);
  REQUIRE(r.resolution.target.ok());
  CHECK(r.resolution.find("vcruntime140.dll") != nullptr);
  for (const auto& f : r.findings) {
    if (f.rule == "missing-runtime" && f.fix) CHECK(f.fix->arch == "x86");
  }
}
