// End-to-end tests of resolver + diagnosis rules on simulated machines.
#include <algorithm>

#include "kb/json.h"
#include "neden/diagnose.h"
#include "neden/env.h"
#include "neden/kb.h"
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

std::vector<std::uint8_t> exe(Machine m, neden_test::DllImports imports, neden_test::DllImports delay = {}) {
  PeBuilder b;
  b.machine = m;
  b.imports = std::move(imports);
  b.delay_imports = std::move(delay);
  return b.build();
}

std::vector<std::uint8_t> dll(Machine m, const std::string& name, std::vector<std::string> exports,
                              neden_test::DllImports imports = {}) {
  PeBuilder b;
  b.machine = m;
  b.dll = true;
  b.export_name = name;
  b.exports = std::move(exports);
  b.imports = std::move(imports);
  return b.build();
}

Report run(const FakeEnvironment& env, Lang lang = Lang::En) {
  return neden::diagnose::diagnose(kExe, env, neden::kb::KnowledgeBase::embedded(), lang);
}

const Finding* find_rule(const Report& r, std::string_view rule) {
  for (const auto& f : r.findings) {
    if (f.rule == rule) return &f;
  }
  return nullptr;
}

bool evidence_mentions(const Finding& f, std::string_view text) {
  return std::any_of(f.evidence.begin(), f.evidence.end(),
                     [&](const std::string& e) { return e.find(text) != std::string::npos; });
}

// A 64-bit Windows 10 with the essentials present.
FakeEnvironment machine64() {
  FakeEnvironment env;
  env.add_file(kWow / "kernel32.dll", dll(Machine::I386, "KERNEL32.dll", {"ExitProcess", "GetTickCount"}));
  env.add_file(kSys32 / "kernel32.dll", dll(Machine::AMD64, "KERNEL32.dll", {"ExitProcess", "GetTickCount"}));
  return env;
}

}  // namespace

TEST(diagnose_clean_program_has_no_errors) {
  FakeEnvironment env = machine64();
  env.add_file(kExe, exe(Machine::I386, {{"KERNEL32.dll", {"ExitProcess"}}}));
  const Report r = run(env);
  CHECK(!r.has_errors());
  REQUIRE(!r.findings.empty());
  CHECK(r.findings[0].rule == "no-problem-found");
  CHECK(r.program_arch == "x86");
}

TEST(diagnose_missing_vcredist_x86_on_x64) {
  FakeEnvironment env = machine64();
  env.add_file(kExe, exe(Machine::I386, {{"KERNEL32.dll", {"ExitProcess"}},
                                         {"MSVCP140.dll", {"?_Xbad_alloc@std@@YAXXZ"}},
                                         {"VCRUNTIME140.dll", {"memset"}}}));
  // The x64 runtime is installed, but that doesn't help a 32-bit program.
  env.add_file(kSys32 / "msvcp140.dll", dll(Machine::AMD64, "MSVCP140.dll", {"?_Xbad_alloc@std@@YAXXZ"}));
  const Report r = run(env);
  CHECK(r.has_errors());
  const Finding* f = find_rule(r, "missing-runtime");
  REQUIRE(f != nullptr);
  CHECK(f->severity == Severity::Error);
  REQUIRE(f->fix.has_value());
  CHECK(f->fix->package_id == "vcredist14");
  CHECK(f->fix->arch == "x86");
  CHECK(f->fix->winget_id == "Microsoft.VCRedist.2015+.x86");
  CHECK(f->fix->url.starts_with("https://"));
  CHECK(evidence_mentions(*f, "msvcp140.dll"));
  CHECK(evidence_mentions(*f, "vcruntime140.dll"));
  // Exactly one finding for both DLLs of the same package.
  CHECK(std::count_if(r.findings.begin(), r.findings.end(), [](const Finding& x) { return x.rule == "missing-runtime"; }) == 1);
}

TEST(diagnose_wrong_arch_in_app_dir) {
  FakeEnvironment env = machine64();
  env.add_file(kExe, exe(Machine::I386, {{"MSVCP140.dll", {"f"}}}));
  env.add_file(kApp / "msvcp140.dll", dll(Machine::AMD64, "MSVCP140.dll", {"f"}));
  env.add_file(kWow / "msvcp140.dll", dll(Machine::I386, "MSVCP140.dll", {"f"}));
  const Report r = run(env);
  const Finding* f = find_rule(r, "wrong-arch");
  REQUIRE(f != nullptr);
  CHECK(f->severity == Severity::Error);
  CHECK(f->title.find("0xc000007b") != std::string::npos);
  CHECK(evidence_mentions(*f, "MyGame"));
  CHECK(evidence_mentions(*f, "SysWOW64"));  // the correct copy is listed too
}

TEST(diagnose_wrong_arch_on_path) {
  FakeEnvironment env = machine64();
  env.path = {"C:\\Tools\\bin"};
  env.add_file(kExe, exe(Machine::I386, {{"zlib1.dll", {"inflate"}}}));
  env.add_file("C:\\Tools\\bin\\zlib1.dll", dll(Machine::AMD64, "zlib1.dll", {"inflate"}));
  const Report r = run(env);
  const Finding* f = find_rule(r, "wrong-arch");
  REQUIRE(f != nullptr);
  CHECK(evidence_mentions(*f, "Tools"));
  REQUIRE(f->fix.has_value());
  CHECK(f->fix->steps.find("C:\\Tools\\bin\\zlib1.dll") != std::string::npos);
}

TEST(diagnose_wow64_redirects_system32_on_path) {
  // PATH contains System32; a 32-bit process actually searches SysWOW64 there.
  FakeEnvironment env = machine64();
  env.path = {"C:\\Windows\\System32"};
  env.add_file(kExe, exe(Machine::I386, {{"KERNEL32.dll", {"ExitProcess"}}, {"onlyx64.dll", {"f"}}}));
  env.add_file(kSys32 / "onlyx64.dll", dll(Machine::AMD64, "onlyx64.dll", {"f"}));
  const Report r = run(env);
  CHECK(find_rule(r, "wrong-arch") == nullptr);
  CHECK(find_rule(r, "missing-program-file") != nullptr);
}

TEST(diagnose_old_copy_shadows_system_dll) {
  FakeEnvironment env = machine64();
  env.add_file(kExe, exe(Machine::I386, {{"MSVCP140.dll", {"_Thrd_sleep_for"}}}));
  env.add_file(kApp / "msvcp140.dll", dll(Machine::I386, "MSVCP140.dll", {"_Thrd_sleep"}));
  env.add_file(kWow / "msvcp140.dll", dll(Machine::I386, "MSVCP140.dll", {"_Thrd_sleep", "_Thrd_sleep_for"}));
  const Report r = run(env);
  const Finding* f = find_rule(r, "missing-export");
  REQUIRE(f != nullptr);
  CHECK(f->certain);
  CHECK(evidence_mentions(*f, "_Thrd_sleep_for"));
  REQUIRE(f->fix.has_value());
  CHECK(f->fix->steps.find(".old") != std::string::npos);
}

TEST(diagnose_old_os_reports_windows_too_old) {
  FakeEnvironment env = machine64();
  env.add_file(kExe, exe(Machine::I386, {{"KERNEL32.dll", {"ExitProcess", "GetSystemTimePreciseAsFileTime"}}}));
  const Report r = run(env);
  const Finding* f = find_rule(r, "windows-too-old");
  REQUIRE(f != nullptr);
  CHECK(evidence_mentions(*f, "GetSystemTimePreciseAsFileTime"));
}

TEST(diagnose_debug_runtime) {
  FakeEnvironment env = machine64();
  env.add_file(kExe, exe(Machine::AMD64, {{"VCRUNTIME140D.dll", {"memset"}}, {"ucrtbased.dll", {"malloc"}}}));
  const Report r = run(env);
  const Finding* f = find_rule(r, "debug-runtime");
  REQUIRE(f != nullptr);
  CHECK(!f->fix || f->fix->winget_id.empty());
  CHECK(find_rule(r, "missing-runtime") == nullptr);
}

TEST(diagnose_platform_x64_on_32bit_windows) {
  FakeEnvironment env;
  env.os_info.is_64bit = false;
  env.add_file(kExe, exe(Machine::AMD64, {{"MSVCP140.dll", {"f"}}}));
  const Report r = run(env);
  const Finding* f = find_rule(r, "platform-mismatch");
  REQUIRE(f != nullptr);
  CHECK(find_rule(r, "missing-runtime") == nullptr);  // nothing else matters
}

TEST(diagnose_platform_arm64_on_x64) {
  FakeEnvironment env = machine64();
  env.add_file(kExe, exe(Machine::ARM64, {}));
  CHECK(find_rule(run(env), "platform-mismatch") != nullptr);
}

TEST(diagnose_dll_instead_of_program) {
  FakeEnvironment env = machine64();
  env.add_file(kExe, dll(Machine::I386, "x.dll", {"f"}));
  const Report r = run(env);
  CHECK(find_rule(r, "not-a-program") != nullptr);
}

TEST(diagnose_corrupt_and_odd_files) {
  FakeEnvironment env = machine64();
  env.add_file(kExe, std::vector<std::uint8_t>(5000, 0));
  CHECK(find_rule(run(env), "corrupt-file") != nullptr);

  env.add_file(kExe, {'P', 'K', 3, 4, 0, 0, 0, 0});
  CHECK(find_rule(run(env), "archive-not-exe") != nullptr);

  auto good = exe(Machine::I386, {{"KERNEL32.dll", {"ExitProcess"}}});
  good.resize(good.size() - 0x100);  // cut the last section short
  env.add_file(kExe, good);
  CHECK(find_rule(run(env), "incomplete-file") != nullptr);

  std::vector<std::uint8_t> dos(0x80, 0);
  dos[0] = 'M';
  dos[1] = 'Z';
  env.add_file(kExe, dos);
  CHECK(find_rule(run(env), "16bit-program") != nullptr);

  FakeEnvironment missing = machine64();
  const Report r = run(missing);
  CHECK(find_rule(r, "unreadable-file") != nullptr);
}

TEST(diagnose_delay_load_is_warning) {
  FakeEnvironment env = machine64();
  env.add_file(kExe, exe(Machine::I386, {{"KERNEL32.dll", {"ExitProcess"}}}, {{"d3dx9_43.dll", {"D3DXCreateSprite"}}}));
  const Report r = run(env);
  const Finding* f = find_rule(r, "missing-runtime");
  REQUIRE(f != nullptr);
  CHECK(f->severity == Severity::Warning);
  CHECK(!r.has_errors());
  REQUIRE(f->fix.has_value());
  CHECK(f->fix->package_id == "directx-jun2010");
}

TEST(diagnose_program_files_and_unknown_dlls) {
  FakeEnvironment env = machine64();
  env.add_file(kExe, exe(Machine::AMD64, {{"steam_api64.dll", {"SteamAPI_Init"}}, {"foo_engine.dll", {"run"}}}));
  const Report r = run(env);
  int known = 0, unknown = 0;
  for (const auto& f : r.findings) {
    if (f.rule != "missing-program-file") continue;
    (f.certain ? known : unknown)++;
    if (f.certain) CHECK(evidence_mentions(f, "steam_api64.dll"));
    if (!f.certain) CHECK(evidence_mentions(f, "foo_engine.dll"));
  }
  CHECK(known == 1);
  CHECK(unknown == 1);
}

TEST(diagnose_ucrt_missing_on_windows7) {
  FakeEnvironment env = machine64();
  env.os_info.major = 6;
  env.os_info.minor = 1;
  env.os_info.build = 7601;
  // vcruntime140 is installed in the system dir but needs the Universal CRT.
  env.add_file(kExe, exe(Machine::I386, {{"VCRUNTIME140.dll", {"memset"}}}));
  env.add_file(kWow / "vcruntime140.dll",
               dll(Machine::I386, "VCRUNTIME140.dll", {"memset"}, {{"api-ms-win-crt-runtime-l1-1-0.dll", {"_exit"}}}));
  const Report r = run(env);
  const Finding* f = find_rule(r, "missing-runtime");
  REQUIRE(f != nullptr);
  REQUIRE(f->fix.has_value());
  CHECK(f->fix->package_id == "ucrt");
}

TEST(diagnose_api_set_resolves) {
  FakeEnvironment env = machine64();
  env.api_sets = {{"api-ms-win-crt-runtime-l1-1", "ucrtbase.dll"}};
  env.add_file(kExe, exe(Machine::I386, {{"api-ms-win-crt-runtime-l1-1-0.dll", {"_exit"}}}));
  CHECK(!run(env).has_errors());
}

TEST(diagnose_windows_internals_are_not_walked) {
  FakeEnvironment env = machine64();
  env.add_file(kExe, exe(Machine::I386, {{"winhttp.dll", {"WinHttpOpen"}}}));
  env.add_file(kWow / "winhttp.dll",
               dll(Machine::I386, "winhttp.dll", {"WinHttpOpen"}, {{"some-internal-thing.dll", {"x"}}}));
  CHECK(!run(env).has_errors());
}

TEST(diagnose_private_assembly_folder) {
  FakeEnvironment env = machine64();
  PeBuilder b;
  b.machine = Machine::AMD64;
  b.imports = {{"chrome_elf.dll", {"SignalInitializeCrashReporting"}}};
  b.manifest =
      "<assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersion=\"1.0\"><dependency><dependentAssembly>"
      "<assemblyIdentity type=\"win32\" name=\"140.0.1.2\" version=\"140.0.1.2\" language=\"*\"/>"
      "</dependentAssembly></dependency></assembly>";
  env.add_file(kExe, b.build());
  env.add_file(kApp / "140.0.1.2" / "chrome_elf.dll",
               dll(Machine::AMD64, "chrome_elf.dll", {"SignalInitializeCrashReporting"}));
  CHECK(!run(env).has_errors());
}

TEST(diagnose_common_controls_v6_from_winsxs) {
  FakeEnvironment env = machine64();
  PeBuilder b;
  b.machine = Machine::I386;
  b.imports = {{"COMCTL32.dll", {"#345", "TaskDialogIndirect"}}};
  b.manifest =
      "<assembly><dependency><dependentAssembly><assemblyIdentity type=\"win32\" "
      "name=\"Microsoft.Windows.Common-Controls\" version=\"6.0.0.0\" processorArchitecture=\"*\" "
      "publicKeyToken=\"6595b64144ccf1df\" language=\"*\"/></dependentAssembly></dependency></assembly>";
  env.add_file(kExe, b.build());
  env.add_file(kWow / "comctl32.dll", dll(Machine::I386, "COMCTL32.dll", {"InitCommonControls"}));  // v5.82
  const char* v6 = "C:\\Windows\\WinSxS\\x86_microsoft.windows.common-controls_6595b64144ccf1df_6.0.19041.1110_none_a8625c1886757984";
  std::vector<std::string> exports(400, "#");
  exports.push_back("TaskDialogIndirect");
  env.add_file(std::filesystem::path(v6) / "comctl32.dll", dll(Machine::I386, "COMCTL32.dll", exports));
  const Report r = run(env);
  CHECK(!r.has_errors());
  const auto* m = r.resolution.find("comctl32.dll");
  REQUIRE(m != nullptr);
  CHECK(m->location == neden::resolve::Location::SxS);
}

TEST(diagnose_netfx35) {
  FakeEnvironment env = machine64();
  PeBuilder b;
  b.machine = Machine::I386;
  b.imports = {{"mscoree.dll", {"_CorExeMain"}}};
  b.clr_metadata_version = "v2.0.50727";
  b.clr_flags = 1;
  env.add_file(kExe, b.build());
  env.add_file(kSys32 / "mscoree.dll", dll(Machine::AMD64, "mscoree.dll", {"_CorExeMain"}));
  env.netfx35 = false;
  const Report r = run(env);
  const Finding* f = find_rule(r, "netfx35");
  REQUIRE(f != nullptr);
  REQUIRE(f->fix.has_value());
  CHECK(f->fix->command.find("NetFx3") != std::string::npos);
  CHECK(r.program_arch == "x64");  // AnyCPU runs as 64-bit

  // A config file that allows CLR 4 makes it fine.
  const std::string config = "<configuration><startup><supportedRuntime version=\"v4.0\"/></startup></configuration>";
  env.add_file(std::filesystem::path(kExe.wstring() + L".config"), std::vector<std::uint8_t>(config.begin(), config.end()));
  CHECK(find_rule(run(env), "netfx35") == nullptr);

  env.netfx35 = true;
  CHECK(find_rule(run(env), "netfx35") == nullptr);
}

TEST(diagnose_dotnet_desktop_runtime) {
  FakeEnvironment env = machine64();
  env.add_file(kExe, exe(Machine::AMD64, {{"KERNEL32.dll", {"ExitProcess"}}}));
  const std::string rc = R"({"runtimeOptions":{"tfm":"net8.0","framework":{"name":"Microsoft.WindowsDesktop.App","version":"8.0.0"}}})";
  env.add_file(kApp / "game.runtimeconfig.json", std::vector<std::uint8_t>(rc.begin(), rc.end()));
  env.dotnet = {{"Microsoft.WindowsDesktop.App", "6.0.36", "x64"}, {"Microsoft.WindowsDesktop.App", "8.0.11", "x86"}};
  const Report r = run(env);
  const Finding* f = find_rule(r, "dotnet-runtime");
  REQUIRE(f != nullptr);
  REQUIRE(f->fix.has_value());
  CHECK(f->fix->winget_id.find("DesktopRuntime.8") != std::string::npos);

  env.dotnet.push_back({"Microsoft.WindowsDesktop.App", "8.0.11", "x64"});
  CHECK(find_rule(run(env), "dotnet-runtime") == nullptr);
}

TEST(diagnose_turkish_text_and_report) {
  FakeEnvironment env = machine64();
  env.add_file(kExe, exe(Machine::I386, {{"MSVCP140.dll", {"f"}}}));
  const Report r = run(env, Lang::Tr);
  const Finding* f = find_rule(r, "missing-runtime");
  REQUIRE(f != nullptr);
  CHECK(f->title.starts_with("Eksik:"));
  const std::string text = neden::diagnose::to_text(r);
  CHECK(text.find("Neden Açılmıyor?") != std::string::npos);
  CHECK(text.find("winget install --id Microsoft.VCRedist.2015+.x86 -e") != std::string::npos);
  CHECK(text.find("github.com/nowackk-cp/why-wont-it-open") != std::string::npos);
}

TEST(diagnose_json_is_valid) {
  FakeEnvironment env = machine64();
  env.add_file(kExe, exe(Machine::I386, {{"MSVCP140.dll", {"f"}}, {"weird\"name\\.dll", {"g"}}}));
  const std::string json = neden::diagnose::to_json(run(env));
  std::string error;
  const auto doc = neden::json::parse(json, &error);
  REQUIRE(doc.has_value());
  const auto* findings = doc->find("findings");
  REQUIRE(findings != nullptr);
  CHECK(!findings->as_array().empty());
  CHECK(doc->find("modules") != nullptr);
}
