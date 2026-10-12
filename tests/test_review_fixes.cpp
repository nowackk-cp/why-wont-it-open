// Regression tests for the findings of the code review: parser caps, resolver edge cases, 16-bit detection,
// platform rules, .NET roll-forward, clean failure on exceptions and the download file lock.
#include <windows.h>

#include <algorithm>
#include <new>
#include <string>

#include "neden/diagnose.h"
#include "neden/env.h"
#include "neden/fix.h"
#include "neden/kb.h"
#include "neden/pe.h"
#include "neden/resolve.h"
#include "pe_builder.h"
#include "test.h"

using neden::diagnose::Finding;
using neden::diagnose::Lang;
using neden::diagnose::Report;
using neden::diagnose::Severity;
using neden::env::FakeEnvironment;
using neden::pe::Machine;
using neden_test::PeBuilder;

namespace {

const std::filesystem::path kApp = "C:\\Games\\MyGame";
const std::filesystem::path kExe = kApp / "game.exe";
const std::filesystem::path kSys32 = "C:\\Windows\\System32";
const std::filesystem::path kWow = "C:\\Windows\\SysWOW64";

std::vector<std::uint8_t> exe_bytes(Machine m, neden_test::DllImports imports, neden_test::DllImports delay = {},
                                    const std::string& manifest = {}) {
  PeBuilder b;
  b.machine = m;
  b.imports = std::move(imports);
  b.delay_imports = std::move(delay);
  b.manifest = manifest;
  return b.build();
}

std::vector<std::uint8_t> dll_bytes(Machine m, const std::string& name, std::vector<std::string> exports,
                                    neden_test::DllImports imports = {}) {
  PeBuilder b;
  b.machine = m;
  b.dll = true;
  b.export_name = name;
  b.exports = std::move(exports);
  b.imports = std::move(imports);
  return b.build();
}

FakeEnvironment machine64() {
  FakeEnvironment env;
  env.add_file(kWow / "kernel32.dll", dll_bytes(Machine::I386, "KERNEL32.dll", {"ExitProcess", "GetTickCount"}));
  env.add_file(kSys32 / "kernel32.dll", dll_bytes(Machine::AMD64, "KERNEL32.dll", {"ExitProcess", "GetTickCount"}));
  return env;
}

Report run(const FakeEnvironment& env) {
  return neden::diagnose::diagnose(kExe, env, neden::kb::KnowledgeBase::embedded(), Lang::En);
}

const Finding* find_rule(const Report& r, std::string_view rule) {
  for (const auto& f : r.findings) {
    if (f.rule == rule) return &f;
  }
  return nullptr;
}

bool has_warning(const neden::pe::PeInfo& info, std::string_view part) {
  return std::any_of(info.warnings.begin(), info.warnings.end(),
                     [&](const std::string& w) { return w.find(part) != std::string::npos; });
}

void put32(std::vector<std::uint8_t>& b, std::size_t at, std::uint32_t v) {
  for (int i = 0; i < 4; ++i) b[at + i] = static_cast<std::uint8_t>(v >> (8 * i));
}

// An environment whose file reads run out of memory.
class ThrowingEnv : public FakeEnvironment {
 public:
  std::optional<std::vector<std::uint8_t>> read_file(const std::filesystem::path&, std::uint64_t) const override {
    throw std::bad_alloc();
  }
};

// An environment that runs out of memory while reading the event log (after the static analysis).
class ThrowingEventsEnv : public FakeEnvironment {
 public:
  std::vector<neden::env::EventRecord> events(const std::string&, const std::string&, const std::vector<std::uint32_t>&,
                                              int, int) const override {
    throw std::bad_alloc();
  }
};

}  // namespace

// ---- 1: the verified file is locked ----------------------------------------------------

TEST(file_lock_denies_write_and_delete_but_allows_reading) {
  wchar_t tmp[MAX_PATH];
  REQUIRE(GetTempPathW(MAX_PATH, tmp) != 0);
  const std::filesystem::path file =
      std::filesystem::path(tmp) / (L"neden-lock-test-" + std::to_wstring(GetCurrentProcessId()) + L".exe");
  REQUIRE(neden_test::write_file(file, {1, 2, 3, 4}));

  {
    neden::fix::FileLock lock;
    REQUIRE(neden::fix::FileLock::acquire(file, &lock));
    CHECK(lock.held());

    // Writing, replacing and deleting are refused while the lock is held...
    HANDLE w = CreateFileW(file.c_str(), GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr,
                           OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    CHECK(w == INVALID_HANDLE_VALUE);
    if (w != INVALID_HANDLE_VALUE) CloseHandle(w);
    CHECK(!DeleteFileW(file.c_str()));
    CHECK(!MoveFileW(file.c_str(), (file.wstring() + L".moved").c_str()));

    // ...but the signature check, the installer and msiexec can still read it.
    HANDLE r = CreateFileW(file.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_DELETE, nullptr, OPEN_EXISTING,
                           FILE_ATTRIBUTE_NORMAL, nullptr);
    CHECK(r != INVALID_HANDLE_VALUE);
    if (r != INVALID_HANDLE_VALUE) CloseHandle(r);
    lock.release();
    CHECK(!lock.held());
  }
  CHECK(DeleteFileW(file.c_str()));
}

// ---- 2: winget only from the per-user alias ----------------------------------------------

TEST(winget_path_is_only_the_windowsapps_alias) {
  const std::wstring p = neden::fix::winget_exe_path();
  if (p.empty()) {
    CHECK(!neden::fix::winget_available());
    return;
  }
  CHECK(neden::fix::winget_available());
  const std::wstring tail = L"\\Microsoft\\WindowsApps\\winget.exe";
  REQUIRE(p.size() > tail.size());
  CHECK(_wcsicmp(p.c_str() + p.size() - tail.size(), tail.c_str()) == 0);
}

// ---- 3: amplification caps ---------------------------------------------------------------

TEST(pe_total_imported_functions_are_capped) {
  PeBuilder b;
  b.machine = Machine::I386;
  for (int d = 0; d < 4; ++d) {
    std::vector<std::string> fns;
    for (int i = 1; i <= 65000; ++i) fns.push_back("#" + std::to_string(i));
    b.imports.push_back({"lib" + std::to_string(d) + ".dll", std::move(fns)});
  }
  const auto r = neden::pe::parse(b.build());
  REQUIRE(r.ok());
  std::size_t total = 0;
  for (const auto& d : r.info->imports) total += d.functions.size();
  CHECK(total <= 200000);
  CHECK(total >= 199000);
  CHECK(has_warning(*r.info, "imported functions in total"));
}

TEST(pe_total_export_name_bytes_are_capped) {
  PeBuilder b;
  b.machine = Machine::I386;
  b.dll = true;
  b.export_name = "big.dll";
  for (int i = 0; i < 60000; ++i) {
    std::string n = "N" + std::to_string(i);
    n.resize(300, 'x');
    b.exports.push_back(std::move(n));
  }
  const auto r = neden::pe::parse(b.build());
  REQUIRE(r.ok());
  CHECK(std::count_if(r.info->exports.begin(), r.info->exports.end(),
                      [](const auto& e) { return !e.name.empty(); }) < 60000);  // names beyond the cap are dropped
  CHECK(has_warning(*r.info, "export names exceed"));
}

TEST(resolve_dedupes_and_caps_missing_functions) {
  FakeEnvironment env = machine64();
  std::vector<std::string> fns = {"dup", "dup"};
  for (int i = 0; i < 2500; ++i) fns.push_back("fn" + std::to_string(i));
  env.add_file(kExe, exe_bytes(Machine::I386, {{"foo.dll", fns}}));
  env.add_file(kApp / "foo.dll", dll_bytes(Machine::I386, "foo.dll", {"other"}));
  const auto res = neden::resolve::resolve(kExe, env);
  const auto* m = res.find("foo.dll");
  REQUIRE(m != nullptr);
  CHECK(m->missing_functions.size() == 1000);
  CHECK(m->missing_functions_omitted == 2501 - 1000);  // 2501 distinct names, the rest only counted
  CHECK(std::count_if(m->missing_functions.begin(), m->missing_functions.end(),
                      [](const auto& f) { return f.function == "dup"; }) == 1);
}

TEST(diagnose_and_resolve_survive_bad_alloc) {
  ThrowingEnv env;
  const auto res = neden::resolve::resolve(kExe, env);
  CHECK(!res.target.ok());
  CHECK(res.target.detail.find("could not analyse") != std::string::npos);

  const Report r = run(env);
  CHECK(!r.resolution.target.ok());  // the CLI exits with 2 for this

  // A failure after the resolver finished is caught by diagnose() itself.
  ThrowingEventsEnv late;
  late.add_file(kExe, exe_bytes(Machine::I386, {}));
  const Report r2 = run(late);
  CHECK(!r2.resolution.target.ok());
  const Finding* f = find_rule(r2, "analysis-failed");
  REQUIRE(f != nullptr);
  CHECK(f->severity == Severity::Warning);
}

// ---- 4: ordinal imports are compared as numbers ---------------------------------------------

TEST(missing_ordinal_import_is_checked_against_the_system_copy_by_number) {
  FakeEnvironment env = machine64();
  env.add_file(kExe, exe_bytes(Machine::I386, {{"foo.dll", {"#5"}}}));
  env.add_file(kApp / "foo.dll", dll_bytes(Machine::I386, "foo.dll", {"A"}));
  env.add_file(kWow / "foo.dll", dll_bytes(Machine::I386, "foo.dll", {"A", "B", "C", "D", "E"}));
  const auto res = neden::resolve::resolve(kExe, env);
  const auto* m = res.find("foo.dll");
  REQUIRE(m != nullptr);
  REQUIRE(m->missing_functions.size() == 1);
  CHECK(m->missing_functions[0].by_ordinal);
  CHECK(m->missing_functions[0].ordinal == 5);
  CHECK(m->missing_functions[0].function == "#5");

  const Report r = run(env);
  const Finding* f = find_rule(r, "missing-export");
  REQUIRE(f != nullptr);
  CHECK(f->explanation.find("old copy") != std::string::npos);  // the system copy has ordinal 5
}

// ---- 8: delay-only is recomputed from all edges ----------------------------------------------

TEST(delay_only_is_cleared_when_a_module_is_also_reached_normally) {
  FakeEnvironment env = machine64();
  // x.dll is delay-loaded by the program but imported normally by b.dll; its own import y.dll is missing.
  env.add_file(kExe, exe_bytes(Machine::I386, {{"b.dll", {"f"}}}, {{"x.dll", {"g"}}}));
  env.add_file(kApp / "b.dll", dll_bytes(Machine::I386, "b.dll", {"f"}, {{"x.dll", {"g"}}}));
  env.add_file(kApp / "x.dll", dll_bytes(Machine::I386, "x.dll", {"g"}, {{"y.dll", {"h"}}}));
  const auto res = neden::resolve::resolve(kExe, env);
  const auto* x = res.find("x.dll");
  const auto* y = res.find("y.dll");
  REQUIRE(x != nullptr);
  REQUIRE(y != nullptr);
  CHECK(!x->delay_only);
  CHECK(!y->delay_only);
  CHECK(res.find("b.dll") != nullptr && !res.find("b.dll")->delay_only);
}

TEST(delay_only_stays_for_purely_delay_loaded_chains) {
  FakeEnvironment env = machine64();
  env.add_file(kExe, exe_bytes(Machine::I386, {{"KERNEL32.dll", {"ExitProcess"}}}, {{"p.dll", {"f"}}}));
  env.add_file(kApp / "p.dll", dll_bytes(Machine::I386, "p.dll", {"f"}, {{"q.dll", {"h"}}}));
  env.add_file(kApp / "q.dll", dll_bytes(Machine::I386, "q.dll", {"h"}));
  const auto res = neden::resolve::resolve(kExe, env);
  REQUIRE(res.find("p.dll") != nullptr);
  REQUIRE(res.find("q.dll") != nullptr);
  CHECK(res.find("p.dll")->delay_only);
  CHECK(res.find("q.dll")->delay_only);
  CHECK(!res.find("kernel32.dll")->delay_only);
}

// ---- 9: 16-bit detection -------------------------------------------------------------------

TEST(corrupt_pe_with_huge_lfanew_is_not_called_16bit) {
  FakeEnvironment env = machine64();
  auto bytes = exe_bytes(Machine::I386, {{"KERNEL32.dll", {"ExitProcess"}}});
  bytes[0x18] = 0x40;  // a real PE: relocation table offset is 0x40
  put32(bytes, 0x3C, 0x7FFFFFF0u);
  env.add_file(kExe, bytes);
  const Report r = run(env);
  CHECK(find_rule(r, "16bit-program") == nullptr);
  CHECK(find_rule(r, "corrupt-file") != nullptr);

  // e_lfanew inside the file but pointing at something that is neither "PE" nor "NE".
  put32(bytes, 0x3C, 0x200u);
  env.add_file(kExe, bytes);
  const Report r2 = run(env);
  CHECK(find_rule(r2, "16bit-program") == nullptr);
  CHECK(find_rule(r2, "corrupt-file") != nullptr);
}

TEST(ne_header_beyond_the_first_4k_is_16bit) {
  FakeEnvironment env = machine64();
  std::vector<std::uint8_t> bytes(0x2000, 0);
  bytes[0] = 'M';
  bytes[1] = 'Z';
  bytes[0x18] = 0x40;
  put32(bytes, 0x3C, 0x1800u);  // past the 4 KB head the diagnosis reads first
  bytes[0x1800] = 'N';
  bytes[0x1801] = 'E';
  env.add_file(kExe, bytes);
  CHECK(find_rule(run(env), "16bit-program") != nullptr);
}

TEST(plain_dos_program_is_16bit_whatever_lfanew_holds) {
  FakeEnvironment env = machine64();
  std::vector<std::uint8_t> bytes(0x200, 0);
  bytes[0] = 'M';
  bytes[1] = 'Z';
  bytes[0x18] = 0x1E;  // classic DOS header: relocation table at 0x1E
  put32(bytes, 0x3C, 0x7FFFFFF0u);
  env.add_file(kExe, bytes);
  CHECK(find_rule(run(env), "16bit-program") != nullptr);
}

// ---- 10: loader name rules, big files, manifest names --------------------------------------------

TEST(import_without_extension_gets_dll_appended) {
  FakeEnvironment env = machine64();
  env.add_file(kExe, exe_bytes(Machine::I386, {{"KERNEL32", {"ExitProcess"}}}));
  const auto res = neden::resolve::resolve(kExe, env);
  REQUIRE(res.modules.size() == 1);
  CHECK(res.modules[0].name == "kernel32.dll");
  CHECK(res.modules[0].location == neden::resolve::Location::KnownDll);
}

TEST(file_larger_than_the_read_cap_is_not_reported_truncated) {
  FakeEnvironment env = machine64();
  const auto bytes = exe_bytes(Machine::I386, {{"KERNEL32.dll", {"ExitProcess"}}});
  env.add_file(kExe, bytes);
  neden::resolve::Options opt;
  opt.max_image_bytes = bytes.size() - 0x100;  // pretend the file is bigger than the cap
  const auto res = neden::resolve::resolve(kExe, env, opt);
  if (res.target.ok()) {
    CHECK(!res.target.info->truncated);
    CHECK(has_warning(*res.target.info, "larger than the analysis limit"));
  }
  // Without a cap a cut-off file is still reported.
  auto cut = bytes;
  cut.resize(cut.size() - 0x100);
  env.add_file(kExe, cut);
  const auto res2 = neden::resolve::resolve(kExe, env);
  REQUIRE(res2.target.ok());
  CHECK(res2.target.info->truncated);
}

TEST(manifest_assembly_names_cannot_escape_the_program_folder) {
  FakeEnvironment env = machine64();
  const std::string manifest =
      "<assembly><dependency><dependentAssembly><assemblyIdentity type=\"win32\" name=\"../other\" "
      "version=\"1.0.0.0\"/></dependentAssembly></dependency></assembly>";
  env.add_file(kExe, exe_bytes(Machine::I386, {{"foo.dll", {"f"}}}, {}, manifest));
  env.add_file("C:\\Games\\other\\foo.dll", dll_bytes(Machine::I386, "foo.dll", {"f"}));
  const auto res = neden::resolve::resolve(kExe, env);
  const auto* m = res.find("foo.dll");
  REQUIRE(m != nullptr);
  CHECK(m->location == neden::resolve::Location::NotFound);

  // A well-formed private assembly folder still works.
  const std::string good =
      "<assembly><dependency><dependentAssembly><assemblyIdentity type=\"win32\" name=\"mylib.shared\" "
      "version=\"1.0.0.0\"/></dependentAssembly></dependency></assembly>";
  env.add_file(kExe, exe_bytes(Machine::I386, {{"foo.dll", {"f"}}}, {}, good));
  env.add_file(kApp / "mylib.shared" / "foo.dll", dll_bytes(Machine::I386, "foo.dll", {"f"}));
  const auto res2 = neden::resolve::resolve(kExe, env);
  REQUIRE(res2.find("foo.dll") != nullptr);
  CHECK(res2.find("foo.dll")->location == neden::resolve::Location::SxS);
}

// ---- 12: platform rules and .NET roll-forward ---------------------------------------------------

TEST(x64_program_on_arm64_windows_10_is_a_platform_mismatch) {
  FakeEnvironment env = machine64();
  env.os_info.is_arm64 = true;
  env.os_info.build = 19045;
  env.add_file(kExe, exe_bytes(Machine::AMD64, {}));
  CHECK(find_rule(run(env), "platform-mismatch") != nullptr);

  env.os_info.build = 22000;  // Windows 11 emulates x64
  CHECK(find_rule(run(env), "platform-mismatch") == nullptr);
}

namespace {

// Runs a program whose runtimeconfig.json asks for Microsoft.WindowsDesktop.App `wanted` with `roll_forward`
// while `installed` is the only installed version. True if "dotnet-runtime" is reported.
bool dotnet_missing(const std::string& wanted, const std::string& roll_forward, const std::string& installed) {
  FakeEnvironment env = machine64();
  env.add_file(kExe, exe_bytes(Machine::AMD64, {{"KERNEL32.dll", {"ExitProcess"}}}));
  std::string rc = "{\"runtimeOptions\":{\"tfm\":\"net8.0\",";
  if (!roll_forward.empty()) rc += "\"rollForward\":\"" + roll_forward + "\",";
  rc += "\"framework\":{\"name\":\"Microsoft.WindowsDesktop.App\",\"version\":\"" + wanted + "\"}}}";
  env.add_file(kApp / "game.runtimeconfig.json", std::vector<std::uint8_t>(rc.begin(), rc.end()));
  env.dotnet = {{"Microsoft.WindowsDesktop.App", installed, "x64"}};
  return find_rule(run(env), "dotnet-runtime") != nullptr;
}

}  // namespace

TEST(dotnet_roll_forward_disable_needs_the_exact_version) {
  CHECK(dotnet_missing("8.0.0", "Disable", "8.0.11"));
  CHECK(!dotnet_missing("8.0.0", "Disable", "8.0.0"));
  CHECK(!dotnet_missing("8.0.0", "", "8.0.11"));  // default roll-forward accepts a newer minor/patch
}

TEST(dotnet_roll_forward_latest_patch_stays_in_the_minor) {
  CHECK(dotnet_missing("8.0.0", "LatestPatch", "8.1.0"));
  CHECK(!dotnet_missing("8.0.0", "LatestPatch", "8.0.5"));
  CHECK(!dotnet_missing("8.0.0", "", "8.1.0"));
}

TEST(dotnet_prerelease_is_lower_than_the_release) {
  CHECK(dotnet_missing("8.0.0", "", "8.0.0-rc.1"));
  CHECK(!dotnet_missing("8.0.0", "", "8.0.1-rc.1"));
  CHECK(!dotnet_missing("8.0.0", "", "8.0.0"));
}

TEST(dotnet_huge_version_numbers_do_not_overflow) {
  // Must not crash or invoke undefined behaviour; a gigantic wanted version is simply not installed.
  CHECK(dotnet_missing("99999999999999999999.0.0", "", "8.0.0"));
  (void)dotnet_missing("8.0.0", "", "99999999999999999999.0.0");  // installed side saturates too
}
