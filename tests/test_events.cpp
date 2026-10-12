// Rules 8 and 9: event log, Mark of the Web, Defender, Smart App Control.
// All tests run on simulated machines (FakeEnvironment) except the smoke test.
#include <algorithm>

#include "env/event_xml.h"
#include "neden/diagnose.h"
#include "neden/env.h"
#include "neden/kb.h"
#include "pe_builder.h"
#include "test.h"

using neden::diagnose::Finding;
using neden::diagnose::Lang;
using neden::diagnose::Report;
using neden::diagnose::Severity;
using neden::env::EventRecord;
using neden::env::FakeEnvironment;
using neden::pe::Machine;
using neden_test::PeBuilder;

namespace {

const std::filesystem::path kApp = "C:\\Games\\MyGame";
const std::filesystem::path kExe = kApp / "game.exe";
const std::filesystem::path kSys32 = "C:\\Windows\\System32";
const std::filesystem::path kWow = "C:\\Windows\\SysWOW64";

constexpr std::uint64_t kDay = 24ull * 3600ull * 10000000ull;

std::uint64_t ft(const char* iso) { return neden::env::parse_system_time(iso); }

// "Now" of all simulated machines: 2026-10-12 12:00 UTC.
const std::uint64_t kNow = ft("2026-10-12T12:00:00Z");

std::vector<std::uint8_t> exe_bytes(neden_test::DllImports imports, std::uint32_t certificate_size = 0) {
  PeBuilder b;
  b.machine = Machine::I386;
  b.imports = std::move(imports);
  b.certificate_size = certificate_size;
  return b.build();
}

std::vector<std::uint8_t> dll_bytes(const std::string& name, std::vector<std::string> exports) {
  PeBuilder b;
  b.machine = Machine::I386;
  b.dll = true;
  b.export_name = name;
  b.exports = std::move(exports);
  return b.build();
}

// A 64-bit Windows with a clean 32-bit game installed.
FakeEnvironment machine(std::uint32_t certificate_size = 0) {
  FakeEnvironment env;
  env.now_filetime = kNow;
  env.add_file(kWow / "kernel32.dll", dll_bytes("KERNEL32.dll", {"ExitProcess"}));
  env.add_file(kExe, exe_bytes({{"KERNEL32.dll", {"ExitProcess"}}}, certificate_size));
  return env;
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

bool contains(const std::string& s, std::string_view part) { return s.find(part) != std::string::npos; }

bool evidence_has(const Finding& f, std::string_view part) {
  return std::any_of(f.evidence.begin(), f.evidence.end(), [&](const std::string& e) { return contains(e, part); });
}

EventRecord app_error(const char* when, const char* app, const char* module, const char* code, const char* path) {
  EventRecord e;
  e.channel = "Application";
  e.provider = "Application Error";
  e.id = 1000;
  e.time = ft(when);
  e.data = {app, "1.0.0.0", "6abe7061", module, "1.0.0.0", "6abe7061", code, "00000000000f4034", "27cc",
            "01dd56592c80f17d", path, path, "2e965793-d64a-4c37-8905-3a19b1b0a3ad", "", ""};
  return e;
}

EventRecord simple_event(const char* channel, const char* provider, std::uint32_t id, const char* when,
                         std::vector<std::string> data, std::vector<std::string> names = {}) {
  EventRecord e;
  e.channel = channel;
  e.provider = provider;
  e.id = id;
  e.time = ft(when);
  e.data = std::move(data);
  e.names = std::move(names);
  return e;
}

EventRecord defender_event(std::uint32_t id, const char* when, const char* threat, const char* path) {
  return simple_event("Microsoft-Windows-Windows Defender/Operational", "Microsoft-Windows-Windows Defender", id, when,
                      {threat, path, id == 1117 ? "Quarantine" : ""}, {"Threat Name", "Path", "Action Name"});
}

EventRecord ci_block(const char* when, const char* file, const char* process) {
  return simple_event("Microsoft-Windows-CodeIntegrity/Operational", "Microsoft-Windows-CodeIntegrity", 3077, when,
                      {file, process, "VerifiedAndReputablePolicy"},
                      {"FileNameBuffer", "ProcessNameBuffer", "PolicyNameBuffer"});
}

}  // namespace

// ---- Plumbing ----------------------------------------------------------------------

TEST(event_xml_parses_real_application_error) {
  const std::string xml =
      "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Application "
      "Error'/><EventID Qualifiers='0'>1000</EventID><Version>0</Version><TimeCreated "
      "SystemTime='2026-10-07T13:52:01.4361128Z'/><Channel>Application</Channel></System><EventData><Data>vgtray.exe"
      "</Data><Data>1.19.1.18</Data><Data></Data><Data/><Data Name='Path'>C:\\a &amp; b\\x.exe</Data></EventData>"
      "</Event>";
  EventRecord e;
  REQUIRE(neden::env::parse_event_xml(xml, e));
  CHECK(e.provider == "Application Error");
  CHECK(e.id == 1000);
  CHECK(e.channel == "Application");
  REQUIRE(e.data.size() == 5);
  CHECK(e.data[0] == "vgtray.exe");
  CHECK(e.data[2].empty());
  CHECK(e.data[3].empty());
  CHECK(e.data[4] == "C:\\a & b\\x.exe");
  CHECK(e.names[4] == "Path");
  CHECK(e.time == 134358547214361128ull);
}

TEST(event_xml_time_conversion_epoch) {
  CHECK(neden::env::parse_system_time("1970-01-01T00:00:00Z") == 116444736000000000ull);
  CHECK(neden::env::parse_system_time("garbage") == 0);
  EventRecord e;
  CHECK(!neden::env::parse_event_xml("<Event><System></System></Event>", e));
}

TEST(fake_env_event_filtering) {
  FakeEnvironment env;
  env.now_filetime = kNow;
  env.event_log.push_back(simple_event("Application", "A", 1, "2026-10-01T00:00:00Z", {"old-ish"}));
  env.event_log.push_back(simple_event("Application", "A", 1, "2026-10-11T00:00:00Z", {"newest"}));
  env.event_log.push_back(simple_event("Application", "B", 2, "2026-10-05T00:00:00Z", {"other id"}));
  env.event_log.push_back(simple_event("System", "A", 1, "2026-10-10T00:00:00Z", {"other channel"}));
  env.event_log.push_back(simple_event("Application", "A", 1, "2026-01-01T00:00:00Z", {"too old"}));
  const auto all = env.events("application", "", {}, 30, 10);
  REQUIRE(all.size() == 3);
  CHECK(all[0].data[0] == "newest");  // most recent first
  CHECK(env.events("Application", "", {1}, 30, 10).size() == 2);
  CHECK(env.events("Application", "B", {}, 30, 10).size() == 1);
  CHECK(env.events("Application", "", {1}, 30, 1).size() == 1);
  CHECK(env.events("Application", "", {1}, 365, 10).size() == 3);
}

// ---- Rule 8: crashes ---------------------------------------------------------------

TEST(events_crash_matches_full_path_not_other_folder) {
  FakeEnvironment env = machine();
  env.event_log.push_back(app_error("2026-10-10T10:00:00Z", "game.exe", "game.exe", "c0000005", "C:\\Other\\game.exe"));
  CHECK(find_rule(run(env), "app-crash") == nullptr);

  env.event_log.push_back(app_error("2026-10-09T10:00:00Z", "game.exe", "game.exe", "c0000005", "C:\\Games\\MyGame\\game.exe"));
  const Report r = run(env);
  const Finding* f = find_rule(r, "app-crash");
  REQUIRE(f != nullptr);
  CHECK(f->severity == Severity::Warning);
  CHECK(f->certain);
  CHECK(contains(f->title, "1 crash"));  // only the matching one counted
  CHECK(evidence_has(*f, "2026-10-09 (3 days ago)"));
  CHECK(evidence_has(*f, "0xc0000005"));
}

TEST(events_crash_without_path_matches_file_name) {
  FakeEnvironment env = machine();
  env.event_log.push_back(app_error("2026-10-10T10:00:00Z", "GAME.EXE", "game.exe", "c0000005", ""));
  env.event_log.push_back(app_error("2026-10-10T11:00:00Z", "mygame.exe", "mygame.exe", "c0000005", ""));  // different program
  const Report rep_ = run(env);
  const Finding* f = find_rule(rep_, "app-crash");
  REQUIRE(f != nullptr);
  CHECK(contains(f->title, "1 crash"));
}

TEST(events_crash_ignores_events_older_than_30_days) {
  FakeEnvironment env = machine();
  env.event_log.push_back(app_error("2026-08-01T10:00:00Z", "game.exe", "game.exe", "c0000005", "C:\\Games\\MyGame\\game.exe"));
  CHECK(find_rule(run(env), "app-crash") == nullptr);
}

TEST(events_crash_code_translation) {
  struct Case {
    const char* code;
    const char* expect;
  };
  const Case cases[] = {{"c0000135", "DLL was not found"},     {"C0000139", "entry point"},
                        {"0xc0000142", "failed to initialize"}, {"c000007b", "bad image format"},
                        {"c0000005", "access violation"},       {"c0000409", "fail-fast"},
                        {"c00000fd", "stack overflow"},         {"e0434352", ".NET"},
                        {"80000003", "breakpoint"},             {"c0000417", "invalid C runtime"},
                        {"deadbeef", "0xdeadbeef"}};
  for (const Case& c : cases) {
    FakeEnvironment env = machine();
    env.event_log.push_back(app_error("2026-10-10T10:00:00Z", "game.exe", "game.exe", c.code, "C:\\Games\\MyGame\\game.exe"));
    const Report rep_ = run(env);
  const Finding* f = find_rule(rep_, "app-crash");
    REQUIRE(f != nullptr);
    if (!contains(f->title, c.expect)) {
      std::fprintf(stderr, "code %s: title was: %s\n", c.code, f->title.c_str());
    }
    CHECK(contains(f->title, c.expect));
  }
}

TEST(events_crash_access_violation_is_honest_about_cause) {
  FakeEnvironment env = machine();
  env.event_log.push_back(app_error("2026-10-10T10:00:00Z", "game.exe", "MSVCP140.dll", "c0000005", "C:\\Games\\MyGame\\game.exe"));
  const Report rep_ = run(env);
  const Finding* f = find_rule(rep_, "app-crash");
  REQUIRE(f != nullptr);
  CHECK(f->severity == Severity::Warning);
  CHECK(contains(f->explanation, "not a missing component"));
  CHECK(contains(f->explanation, "Visual C++"));  // the faulting module is a known runtime DLL: not missing
  CHECK(contains(f->explanation, "not missing"));
  CHECK(!f->fix || f->fix->package_id.empty());  // never "install the runtime" for a crash inside it
  CHECK(evidence_has(*f, "MSVCP140.dll"));
}

TEST(events_crash_confirms_static_finding_instead_of_duplicating) {
  FakeEnvironment env;
  env.now_filetime = kNow;
  env.add_file(kWow / "kernel32.dll", dll_bytes("KERNEL32.dll", {"ExitProcess"}));
  env.add_file(kExe, exe_bytes({{"KERNEL32.dll", {"ExitProcess"}}, {"MSVCP140.dll", {"f"}}}));
  env.event_log.push_back(app_error("2026-10-10T10:00:00Z", "game.exe", "ntdll.dll", "c0000135", "C:\\Games\\MyGame\\game.exe"));
  const Report r = run(env);
  const Finding* rt = find_rule(r, "missing-runtime");
  REQUIRE(rt != nullptr);
  CHECK(rt->severity == Severity::Error);
  const Finding* crash = find_rule(r, "app-crash");
  REQUIRE(crash != nullptr);
  CHECK(crash->severity == Severity::Info);
  CHECK(contains(crash->title, "event log confirms"));
  CHECK(!crash->fix.has_value());  // the only fix stays on the static finding
  CHECK(r.findings.front().rule == "missing-runtime");
}

TEST(events_dotnet_exception_text_is_included) {
  FakeEnvironment env = machine();
  env.event_log.push_back(app_error("2026-10-10T10:00:00Z", "game.exe", "KERNELBASE.dll", "e0434352", "C:\\Games\\MyGame\\game.exe"));
  env.event_log.push_back(simple_event(
      "Application", ".NET Runtime", 1026, "2026-10-10T10:00:01Z",
      {"Application: game.exe\r\nFramework Version: v4.0.30319\r\nDescription: The process was terminated due to an "
       "unhandled exception.\r\nException Info: System.IO.FileNotFoundException: Could not load file or assembly "
       "'Foo'\r\n   at Game.Main()"}));
  // A .NET crash of another program must not leak in.
  env.event_log.push_back(simple_event("Application", ".NET Runtime", 1026, "2026-10-11T10:00:00Z",
                                       {"Application: other.exe\r\nException Info: System.Exception: other"}));
  const Report rep_ = run(env);
  const Finding* f = find_rule(rep_, "app-crash");
  REQUIRE(f != nullptr);
  CHECK(contains(f->title, ".NET"));
  CHECK(evidence_has(*f, "System.IO.FileNotFoundException: Could not load file or assembly 'Foo'"));
  CHECK(!evidence_has(*f, "other"));
}

// ---- Rule 8: popup -----------------------------------------------------------------

TEST(events_popup_matches_program_name_with_boundaries) {
  FakeEnvironment env = machine();
  env.event_log.push_back(simple_event("Application", "Application Popup", 26, "2026-10-11T08:00:00Z",
                                       {"Application popup: mygame.exe - System Error : The program can't start "
                                        "because OTHER.dll is missing"}));
  CHECK(find_rule(run(env), "windows-error-popup") == nullptr);

  env.event_log.push_back(simple_event("Application", "Application Popup", 26, "2026-10-11T09:00:00Z",
                                       {"Application popup: game.exe - System Error : The program can't start "
                                        "because MSVCP140.dll is missing from your computer."}));
  const Report rep_ = run(env);
  const Finding* f = find_rule(rep_, "windows-error-popup");
  REQUIRE(f != nullptr);
  CHECK(f->severity == Severity::Warning);
  CHECK(evidence_has(*f, "Windows showed"));
  CHECK(evidence_has(*f, "MSVCP140.dll is missing"));
  CHECK(!contains(f->title, "OTHER"));
}

// ---- Rule 8: SideBySide ------------------------------------------------------------

namespace {
EventRecord sxs_event(std::uint32_t id, const char* when, const char* path) {
  EventRecord e = simple_event(
      "Application", "SideBySide", id, when,
      {"Microsoft.VC90.CRT,processorArchitecture=\"x86\",publicKeyToken=\"1fc8b3b9a1e18e3b\",type=\"win32\","
       "version=\"9.0.21022.8\"",
       "", "", "", "", "", "", "", "", "", path});
  return e;
}
}  // namespace

TEST(events_sidebyside_maps_vc90_to_vcredist2008_x86) {
  FakeEnvironment env = machine();
  env.event_log.push_back(sxs_event(33, "2026-10-10T10:00:00Z", "C:\\Games\\MyGame\\game.exe"));
  const Report r = run(env);
  const Finding* f = find_rule(r, "side-by-side");
  REQUIRE(f != nullptr);
  CHECK(f->severity == Severity::Error);  // 2 days old
  REQUIRE(f->fix.has_value());
  CHECK(f->fix->package_id == "vcredist2008");
  CHECK(f->fix->arch == "x86");
  CHECK(f->fix->winget_id == "Microsoft.VCRedist.2008.x86");
  CHECK(f->fix->url.starts_with("https://"));
  CHECK(evidence_has(*f, "Microsoft.VC90.CRT x86 9.0.21022.8"));
  CHECK(r.has_errors());
}

TEST(events_sidebyside_old_event_is_a_warning_and_vc80_maps_to_2005) {
  FakeEnvironment env = machine();
  EventRecord e = sxs_event(35, "2026-09-20T10:00:00Z", "C:\\Games\\MyGame\\game.exe");
  e.data[0] = "Microsoft.VC80.CRT,processorArchitecture=\"amd64\",type=\"win32\",version=\"8.0.50727.762\"";
  env.event_log.push_back(e);
  const Report rep_ = run(env);
  const Finding* f = find_rule(rep_, "side-by-side");
  REQUIRE(f != nullptr);
  CHECK(f->severity == Severity::Warning);  // 22 days old
  REQUIRE(f->fix.has_value());
  CHECK(f->fix->package_id == "vcredist2005");
  CHECK(f->fix->arch == "x64");  // taken from the event, not guessed
}

TEST(events_sidebyside_other_program_and_installed_runtime) {
  FakeEnvironment env = machine();
  env.event_log.push_back(sxs_event(33, "2026-10-10T10:00:00Z", "C:\\Other\\game.exe"));
  CHECK(find_rule(run(env), "side-by-side") == nullptr);

  env.event_log.push_back(sxs_event(33, "2026-10-10T11:00:00Z", "C:\\Games\\MyGame\\game.exe"));
  env.add_file("C:\\Windows\\WinSxS\\x86_microsoft.vc90.crt_1fc8b3b9a1e18e3b_9.0.30729.1_none_5090ab56bcba71c2\\msvcr90.dll",
               {1});
  const Report rep_ = run(env);
  const Finding* f = find_rule(rep_, "side-by-side");
  REQUIRE(f != nullptr);
  CHECK(f->severity == Severity::Info);  // seems fixed already: say so, no reinstall offer
  CHECK(!f->certain);
  CHECK(!f->fix.has_value());
}

TEST(events_sidebyside_merges_with_static_finding) {
  FakeEnvironment env;
  env.now_filetime = kNow;
  env.add_file(kWow / "kernel32.dll", dll_bytes("KERNEL32.dll", {"ExitProcess"}));
  env.add_file(kExe, exe_bytes({{"KERNEL32.dll", {"ExitProcess"}}, {"MSVCR90.dll", {"f"}}}));
  env.event_log.push_back(sxs_event(33, "2026-10-10T10:00:00Z", "C:\\Games\\MyGame\\game.exe"));
  const Report r = run(env);
  const Finding* rt = find_rule(r, "missing-runtime");
  REQUIRE(rt != nullptr);
  REQUIRE(rt->fix.has_value());
  CHECK(rt->fix->package_id == "vcredist2008");
  const Finding* f = find_rule(r, "side-by-side");
  REQUIRE(f != nullptr);
  CHECK(f->severity == Severity::Info);
  CHECK(!f->fix.has_value());  // `neden fix` must not install the package twice
}

// ---- Rule 9: Mark of the Web -------------------------------------------------------

TEST(motw_zone3_and_zone4_are_info_findings) {
  for (const char* zone : {"3", "4"}) {
    FakeEnvironment env = machine();
    env.set_zone_identifier(kExe, std::string("[ZoneTransfer]\r\nZoneId=") + zone +
                                      "\r\nReferrerUrl=https://example.com/download\r\n"
                                      "HostUrl=https://cdn.example.com/g.exe?token=SECRET&x=1\r\n");
    const Report r = run(env);
    const Finding* f = find_rule(r, "downloaded-from-internet");
    REQUIRE(f != nullptr);
    CHECK(f->severity == Severity::Info);
    CHECK(!r.has_errors());
    CHECK(contains(f->explanation, "Windows protected your PC"));
    REQUIRE(f->fix.has_value());
    CHECK(contains(f->fix->steps, "Run anyway"));
    CHECK(contains(f->fix->steps, "Only if you trust"));
    CHECK(contains(f->fix->steps, "Do not turn SmartScreen off"));
    CHECK(evidence_has(*f, "HostUrl: https://cdn.example.com/g.exe"));
    CHECK(!evidence_has(*f, "SECRET"));  // query strings may carry tokens
    CHECK(evidence_has(*f, "ReferrerUrl: https://example.com/download"));
  }
}

TEST(motw_other_zones_are_ignored) {
  FakeEnvironment env = machine();
  env.set_zone_identifier(kExe, "[ZoneTransfer]\r\nZoneId=2\r\n");
  CHECK(find_rule(run(env), "downloaded-from-internet") == nullptr);
  FakeEnvironment env2 = machine();
  CHECK(find_rule(run(env2), "downloaded-from-internet") == nullptr);
}

TEST(motw_works_even_when_the_file_does_not_parse) {
  FakeEnvironment env;
  env.now_filetime = kNow;
  env.add_file(kExe, std::vector<std::uint8_t>(64, 0));
  env.set_zone_identifier(kExe, "[ZoneTransfer]\r\nZoneId=3\r\n");
  CHECK(find_rule(run(env), "downloaded-from-internet") != nullptr);
  CHECK(find_rule(run(env), "corrupt-file") != nullptr);
}

// ---- Rule 9: Defender --------------------------------------------------------------

TEST(defender_quarantined_dll_explains_missing_program_file) {
  FakeEnvironment env;
  env.now_filetime = kNow;
  env.add_file(kWow / "kernel32.dll", dll_bytes("KERNEL32.dll", {"ExitProcess"}));
  env.add_file(kExe, exe_bytes({{"KERNEL32.dll", {"ExitProcess"}}, {"steam_api.dll", {"SteamAPI_Init"}}}));
  env.event_log.push_back(defender_event(1116, "2026-10-10T10:00:00Z", "Trojan:Win32/Wacatac.B!ml",
                                         "file:_C:\\Games\\MyGame\\steam_api.dll"));
  env.event_log.push_back(defender_event(1117, "2026-10-10T10:00:05Z", "Trojan:Win32/Wacatac.B!ml",
                                         "file:_C:\\Games\\MyGame\\steam_api.dll"));
  // Same file name in another folder: not ours.
  env.event_log.push_back(defender_event(1117, "2026-10-11T10:00:05Z", "Trojan:Other", "file:_C:\\Elsewhere\\steam_api.dll"));
  const Report r = run(env);

  const Finding* d = find_rule(r, "defender-quarantine");
  REQUIRE(d != nullptr);
  CHECK(d->severity == Severity::Error);
  CHECK(contains(d->title, "quarantined"));
  CHECK(contains(d->explanation, "steam_api.dll"));  // explicitly linked to the missing file
  CHECK(contains(d->explanation, "false positive"));
  CHECK(evidence_has(*d, "Wacatac"));
  CHECK(!evidence_has(*d, "Trojan:Other"));
  REQUIRE(d->fix.has_value());
  CHECK(contains(d->fix->steps, "Protection history"));
  CHECK(contains(d->fix->steps, "only if you are sure"));
  CHECK(d->fix->package_id.empty());

  const Finding* missing = find_rule(r, "missing-program-file");
  REQUIRE(missing != nullptr);
  CHECK(missing->certain);  // now backed by Defender's record
  CHECK(evidence_has(*missing, "Defender"));
  CHECK(find_rule(r, "no-problem-found") == nullptr);
}

TEST(defender_ignores_other_programs) {
  FakeEnvironment env = machine();
  env.event_log.push_back(defender_event(1117, "2026-10-10T10:00:05Z", "Trojan:X", "file:_C:\\Games\\OtherGame\\a.dll"));
  env.event_log.push_back(defender_event(1117, "2026-10-10T10:00:05Z", "Trojan:Y", "file:_C:\\Games\\MyGame2\\a.dll"));
  CHECK(find_rule(run(env), "defender-quarantine") == nullptr);
  // A file inside the program folder (even if it is not the exe) counts.
  env.event_log.push_back(defender_event(1116, "2026-10-10T10:00:05Z", "Trojan:Z", "file:_C:\\Games\\MyGame\\data\\mod.dll"));
  const Report rep_ = run(env);
  const Finding* f = find_rule(rep_, "defender-quarantine");
  REQUIRE(f != nullptr);
  CHECK(contains(f->title, "detected"));  // detection only, no recorded action
}

// ---- Rule 9: Smart App Control -----------------------------------------------------

TEST(sac_block_event_with_sac_on) {
  FakeEnvironment env = machine();
  env.sac_state = 1;
  env.event_log.push_back(ci_block("2026-10-11T10:00:00Z", "\\Device\\HarddiskVolume3\\Games\\MyGame\\game.exe",
                                   "\\Device\\HarddiskVolume3\\Windows\\explorer.exe"));
  const Report r = run(env);
  const Finding* f = find_rule(r, "code-integrity-block");
  REQUIRE(f != nullptr);
  CHECK(f->severity == Severity::Error);
  CHECK(contains(f->title, "Smart App Control blocked"));
  REQUIRE(f->fix.has_value());
  CHECK(contains(f->fix->steps, "signed"));
  CHECK(contains(f->fix->steps, "cannot be relaxed for a single app"));
  CHECK(contains(f->fix->steps, "does not recommend"));
  CHECK(find_rule(r, "sac-unsigned") == nullptr);  // the event already explains it
}

TEST(sac_block_event_without_sac_is_not_called_sac) {
  FakeEnvironment env = machine();
  env.sac_state = -1;
  env.event_log.push_back(ci_block("2026-10-11T10:00:00Z", "\\Device\\HarddiskVolume3\\Games\\MyGame\\game.exe", "x"));
  const Report rep_ = run(env);
  const Finding* f = find_rule(rep_, "code-integrity-block");
  REQUIRE(f != nullptr);
  CHECK(!contains(f->title, "Smart App Control blocked"));
  CHECK(contains(f->explanation, "cannot tell which"));
}

TEST(sac_ignores_unrelated_and_noisy_events) {
  FakeEnvironment env = machine();
  env.sac_state = 1;
  env.event_log.push_back(ci_block("2026-10-11T10:00:00Z", "\\Device\\HarddiskVolume3\\Other\\a.dll", "\\Device\\HarddiskVolume3\\Other\\b.exe"));
  // Event 3033 ("did not meet the Microsoft signing level") is routine noise and not a block of ours.
  EventRecord noisy = ci_block("2026-10-11T10:00:00Z", "\\Device\\HarddiskVolume3\\Games\\MyGame\\game.exe", "x");
  noisy.id = 3033;
  env.event_log.push_back(noisy);
  CHECK(find_rule(run(env), "code-integrity-block") == nullptr);
}

TEST(sac_on_and_unsigned_program_is_a_possibility_only) {
  FakeEnvironment env = machine();
  env.sac_state = 1;
  const Report rep_ = run(env);
  const Finding* f = find_rule(rep_, "sac-unsigned");
  REQUIRE(f != nullptr);
  CHECK(f->severity == Severity::Info);
  CHECK(!f->certain);

  FakeEnvironment signed_env = machine(/*certificate_size=*/4096);
  signed_env.sac_state = 1;
  CHECK(find_rule(run(signed_env), "sac-unsigned") == nullptr);

  FakeEnvironment off = machine();
  off.sac_state = 0;
  CHECK(find_rule(run(off), "sac-unsigned") == nullptr);
  FakeEnvironment unknown = machine();
  unknown.sac_state = -1;
  CHECK(find_rule(run(unknown), "sac-unsigned") == nullptr);
}

TEST(pe_security_directory_is_reported) {
  const auto signed_bytes = exe_bytes({{"KERNEL32.dll", {"ExitProcess"}}}, 2048);
  const auto parsed = neden::pe::parse(signed_bytes);
  REQUIRE(parsed.info.has_value());
  CHECK(parsed.info->security_dir_size == 2048);
  CHECK(parsed.info->has_signature());
  const auto plain = neden::pe::parse(exe_bytes({{"KERNEL32.dll", {"ExitProcess"}}}));
  REQUIRE(plain.info.has_value());
  CHECK(!plain.info->has_signature());
}

// ---- Turkish output, JSON ------------------------------------------------------------

TEST(events_turkish_text) {
  FakeEnvironment env = machine();
  env.event_log.push_back(app_error("2026-10-10T10:00:00Z", "game.exe", "game.exe", "c0000005", "C:\\Games\\MyGame\\game.exe"));
  env.set_zone_identifier(kExe, "ZoneId=3\r\n");
  const Report r = run(env, Lang::Tr);
  const Finding* crash = find_rule(r, "app-crash");
  REQUIRE(crash != nullptr);
  CHECK(contains(crash->title, "çökme"));
  CHECK(contains(crash->explanation, "Eksik bir bileşen değildir"));
  const Finding* web = find_rule(r, "downloaded-from-internet");
  REQUIRE(web != nullptr);
  CHECK(contains(web->title, "internetten"));
}

TEST(events_json_output_contains_new_rules) {
  FakeEnvironment env = machine();
  env.set_zone_identifier(kExe, "ZoneId=3\r\n");
  const std::string json = neden::diagnose::to_json(run(env));
  CHECK(contains(json, "downloaded-from-internet"));
}

// ---- Real machine ---------------------------------------------------------------------

TEST(system_environment_events_smoke) {
  const auto env = neden::env::make_system_environment();
  const auto events = env->events("Application", "", {}, 30, 5);  // may be empty, must not crash
  CHECK(events.size() <= 5);
  for (std::size_t i = 1; i < events.size(); ++i) CHECK(events[i - 1].time >= events[i].time);  // newest first
  for (const auto& e : events) {
    CHECK(e.id != 0 || !e.provider.empty());
    CHECK(e.time != 0);
    CHECK(e.channel == "Application");
  }
  CHECK(env->events("No-Such-Channel/Operational", "", {}, 30, 5).empty());
  CHECK(env->events("Application", "evil' or 1=1", {}, 30, 5).empty());
  CHECK(env->events("Application", "", {1000}, 30, 0).empty());
  const std::uint64_t now = env->now();
  CHECK(now > ft("2025-01-01T00:00:00Z"));
  const int sac = env->smart_app_control_state();
  CHECK(sac >= -1 && sac <= 2);
  CHECK(!env->zone_identifier("C:\\this\\file\\does\\not\\exist.exe").has_value());
}
