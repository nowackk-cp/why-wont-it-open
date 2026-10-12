// Rules 8 and 9: what the machine itself recorded about this program.
//
//   Rule 8  event log: crashes (Application Error / .NET Runtime), the popup
//           Windows showed, side-by-side (VC++ 2005/2008) manifest errors.
//   Rule 9  blockers: Mark of the Web, Microsoft Defender, Smart App Control /
//           code integrity.
//
// The event log is historical evidence. Everything here is Warning/Info unless
// the evidence is recent and specific, an event is only attributed to the
// program when its path (or, if the event has none, its file name) matches,
// and when the static analysis already found the cause the event finding only
// confirms it instead of repeating it.
#include <algorithm>
#include <cctype>
#include <cstdio>
#include <map>
#include <set>

#include "diagnose/internal.h"

namespace neden::diagnose::detail {

namespace {

using util::to_lower_ascii;

constexpr int kDays = 30;
constexpr std::uint64_t kTicksPerDay = 24ull * 3600ull * 10000000ull;

const char* const kAppLog = "Application";
const char* const kDefenderLog = "Microsoft-Windows-Windows Defender/Operational";
const char* const kCodeIntegrityLog = "Microsoft-Windows-CodeIntegrity/Operational";

// ---- Text helpers -------------------------------------------------------------

// Lower-case with '/' turned into '\'.
std::string norm(std::string_view s) {
  std::string out = to_lower_ascii(s);
  std::replace(out.begin(), out.end(), '/', '\\');
  return out;
}

// Removes a leading drive letter ("c:") so that "C:\x" and "\Device\HarddiskVolume3\x" can be compared.
std::string drive_less(std::string s) {
  if (s.size() >= 2 && std::isalpha(static_cast<unsigned char>(s[0])) && s[1] == ':') s.erase(0, 2);
  return s;
}

bool is_token_char(char c) { return std::isalnum(static_cast<unsigned char>(c)) || c == '_' || c == '-'; }

bool ends_with_device_volume(std::string_view before) {
  // "...\device\harddiskvolume3" (digits at the end, preceded by "harddiskvolume")
  std::size_t n = before.size();
  while (n > 0 && std::isdigit(static_cast<unsigned char>(before[n - 1]))) --n;
  return n < before.size() && before.substr(0, n).ends_with("harddiskvolume");
}

struct Prog {
  std::string full;  // drive-less, lower-case, e.g. "\games\mygame\game.exe"
  std::string dir;   // "\games\mygame"
  std::string name;  // "game.exe"
  char drive = 0;    // lower-case drive letter of the program, 0 if it has none (UNC path)
  // Lower-case NT device name of that drive ("\device\harddiskvolume3") if the environment can tell; empty if not.
  std::string device;
  // Lower-case names of the program's own modules that live in the program folder (found there, or missing
  // from it: a quarantined DLL no longer exists but is still the program's own file).
  std::vector<std::string> own_files;
};

// What may precede a drive-less path in a longer string. The drive must be the program's own: a path on
// D: never matches a program on C:. A "\Device\HarddiskVolumeN" prefix is compared with the program's
// volume when the environment can map the drive letter to a device name; when it cannot, such a prefix
// is accepted (a device path alone cannot be tied to a drive letter) and only the folder/file names decide.
bool anchored(std::string_view before, const Prog& p) {
  if (before.empty()) return true;
  if (before.back() == ':') {
    if (p.drive == 0 || before.size() < 2 || before[before.size() - 2] != p.drive) return false;
    return before.size() < 3 || !std::isalnum(static_cast<unsigned char>(before[before.size() - 3]));
  }
  if (ends_with_device_volume(before)) return p.device.empty() || before.ends_with(p.device);
  return false;
}

Prog make_prog(const std::filesystem::path& program, const env::Environment& env, const resolve::Result& resolution) {
  std::error_code ec;
  std::filesystem::path abs = std::filesystem::absolute(program, ec);
  if (ec) abs = program;
  abs = abs.lexically_normal();
  Prog p;
  const std::string full_with_drive = norm(u8(abs));
  p.full = drive_less(full_with_drive);
  p.name = to_lower_ascii(u8(abs.filename()));
  const std::string dir = drive_less(norm(u8(abs.parent_path())));
  p.dir = dir;
  while (p.dir.size() > 1 && p.dir.back() == '\\') p.dir.pop_back();
  if (p.dir == "\\") p.dir.clear();
  if (full_with_drive.size() >= 2 && std::isalpha(static_cast<unsigned char>(full_with_drive[0])) &&
      full_with_drive[1] == ':') {
    p.drive = full_with_drive[0];
    p.device = to_lower_ascii(env.device_path_of_drive(p.drive));
  }

  // The program's own modules in its folder, from the static analysis.
  std::string folder = norm(u8(abs.parent_path()));
  while (folder.size() > 3 && folder.back() == '\\') folder.pop_back();
  for (const resolve::Module& m : resolution.modules) {
    if (!m.path.empty()) {
      std::string parent = norm(u8(m.path.lexically_normal().parent_path()));
      while (parent.size() > 3 && parent.back() == '\\') parent.pop_back();
      if (parent == folder) p.own_files.push_back(to_lower_ascii(u8(m.path.filename())));
    } else if (m.location == resolve::Location::NotFound && !m.name.starts_with("api-ms-") &&
               !m.name.starts_with("ext-ms-")) {
      p.own_files.push_back(m.name);  // would be loaded from the program folder first
    }
  }
  return p;
}

// Is the directory `dir` (drive-less) ending at index `end` of `t`, properly anchored at its start?
bool dir_ends_at(const std::string& t, std::size_t end, const Prog& p) {
  const std::string& dir = p.dir;
  if (end < dir.size()) return false;
  const std::size_t start = end - dir.size();
  if (t.compare(start, dir.size(), dir) != 0) return false;
  return anchored(std::string_view(t).substr(0, start), p);
}

enum class Match { None, Name, Other, Full };

// How does `text` refer to the program?
//   Full  - it names this exact file (same folder)
//   Other - it names a file with the same name in a different folder
//   Name  - it names the file without any folder
Match match_name(const std::string& text, const std::string& name, const Prog& p) {
  if (name.empty()) return Match::None;
  const std::string t = norm(text);
  Match best = Match::None;
  for (std::size_t pos = t.find(name); pos != std::string::npos; pos = t.find(name, pos + 1)) {
    const std::size_t after = pos + name.size();
    if (after < t.size()) {
      const char c = t[after];
      if (is_token_char(c)) continue;
      if (c == '.' && after + 1 < t.size() && std::isalnum(static_cast<unsigned char>(t[after + 1]))) continue;
    }
    if (pos > 0) {
      const char b = t[pos - 1];
      if (b != '\\' && (is_token_char(b) || b == '.')) continue;
    }
    if (pos > 0 && t[pos - 1] == '\\') {
      if (dir_ends_at(t, pos - 1, p)) return Match::Full;
      best = Match::Other;
    } else if (best == Match::None) {
      best = Match::Name;
    }
  }
  return best;
}

Match match_text(const std::string& text, const Prog& p) { return match_name(text, p.name, p); }

// Does the text name, with its full path, the program itself or one of its own modules in the program
// folder? (A file merely sitting in the same folder, e.g. in Downloads, does not count.)
bool text_names_own_file(const std::string& text, const Prog& p) {
  if (match_text(text, p) == Match::Full) return true;
  return std::any_of(p.own_files.begin(), p.own_files.end(),
                     [&](const std::string& n) { return match_name(text, n, p) == Match::Full; });
}

// Does any of the fields refer to this program (see match_text for the rules)?
bool event_mentions_program(const env::EventRecord& e, const Prog& p) {
  bool name_only = false;
  bool other = false;
  for (const std::string& field : e.data) {
    switch (match_text(field, p)) {
      case Match::Full: return true;
      case Match::Other: other = true; break;
      case Match::Name: name_only = true; break;
      case Match::None: break;
    }
  }
  return name_only && !other;
}

std::string field_named(const env::EventRecord& e, std::string_view name) {
  for (std::size_t i = 0; i < e.names.size() && i < e.data.size(); ++i) {
    if (util::iequals(e.names[i], name)) return e.data[i];
  }
  return {};
}

std::string trim(std::string s) {
  const auto not_space = [](unsigned char c) { return !std::isspace(c); };
  s.erase(s.begin(), std::find_if(s.begin(), s.end(), not_space));
  s.erase(std::find_if(s.rbegin(), s.rend(), not_space).base(), s.end());
  return s;
}

// First line, whitespace collapsed, shortened to `max` bytes (never in the middle of a UTF-8 sequence).
std::string shorten(std::string s, std::size_t max = 240) {
  for (char& c : s) {
    if (c == '\r' || c == '\n' || c == '\t') c = ' ';
  }
  std::string out;
  for (const char c : s) {
    if (c == ' ' && !out.empty() && out.back() == ' ') continue;
    out += c;
  }
  out = trim(out);
  if (out.size() > max) {
    std::size_t cut = max;
    while (cut > 0 && (static_cast<unsigned char>(out[cut]) & 0xC0) == 0x80) --cut;
    out.resize(cut);
    out += "...";
  }
  return out;
}

std::string first_line(const std::string& s) {
  const std::size_t nl = s.find_first_of("\r\n");
  return trim(nl == std::string::npos ? s : s.substr(0, nl));
}

std::string file_name_of(const std::string& path) {
  const std::size_t slash = path.find_last_of("\\/");
  return slash == std::string::npos ? path : path.substr(slash + 1);
}

// "2026-10-07 (5 days ago)"
std::string when(std::uint64_t ft, std::uint64_t now, Lang lang) {
  // FILETIME -> civil date (UTC).
  const std::uint64_t days = ft / kTicksPerDay;  // days since 1601-01-01
  const std::int64_t z = static_cast<std::int64_t>(days) - 134774 + 719468;  // days since 0000-03-01
  const std::int64_t era = (z >= 0 ? z : z - 146096) / 146097;
  const unsigned doe = static_cast<unsigned>(z - era * 146097);
  const unsigned yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
  const std::int64_t y = static_cast<std::int64_t>(yoe) + era * 400;
  const unsigned doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
  const unsigned mp = (5 * doy + 2) / 153;
  const unsigned d = doy - (153 * mp + 2) / 5 + 1;
  const unsigned m = mp < 10 ? mp + 3 : mp - 9;
  char buf[48];
  std::snprintf(buf, sizeof(buf), "%04d-%02u-%02u", static_cast<int>(y + (m <= 2)), m, d);
  std::string out = buf;
  if (now >= ft) {
    const std::uint64_t ago = (now - ft) / kTicksPerDay;
    out += ago == 0 ? Tr{" (today)", " (bugün)"}(lang)
                    : format(Tr{" ({0} days ago)", " ({0} gün önce)"}(lang), {std::to_string(ago)});
  }
  return out;
}

// ---- Shared state of one run ----------------------------------------------------

class SystemRules {
 public:
  explicit SystemRules(const SystemRulesInput& in, std::vector<Finding>& findings)
      : in_(in), env_(in.env), lang_(in.lang), findings_(findings), prog_(make_prog(in.program, in.env, in.resolution)),
        now_(in.env.now()), static_has_error_(std::any_of(findings.begin(), findings.end(), [](const Finding& f) {
          return f.severity == Severity::Error;
        })) {}

  void run() {
    crashes();
    popups();
    side_by_side();
    mark_of_the_web();
    defender();
    code_integrity();
    unsigned_with_sac();
  }

 private:
  // ---- Rule 8a: Application Error / .NET Runtime ---------------------------------

  struct Code {
    const char* code;       // 8 lower-case hex digits
    Tr name;
    Tr meaning;
    bool load_failure;      // the program failed while loading DLLs
  };

  static const std::vector<Code>& code_table() {
    static const std::vector<Code> table = {
        {"c0000135",
         {"a required DLL was not found (STATUS_DLL_NOT_FOUND)", "gerekli bir DLL bulunamadı (STATUS_DLL_NOT_FOUND)"},
         {"Windows could not find a DLL the program needs while loading it. The log entry does not say which DLL.",
          "Windows, programın ihtiyaç duyduğu bir DLL'yi yüklerken bulamadı. Kayıt hangi DLL olduğunu söylemiyor."},
         true},
        {"c0000139",
         {"entry point not found (STATUS_ENTRYPOINT_NOT_FOUND)", "giriş noktası bulunamadı (STATUS_ENTRYPOINT_NOT_FOUND)"},
         {"A DLL was found, but it is the wrong version: it lacks a function the program asks for.",
          "Bir DLL bulundu ama yanlış sürüm: programın istediği bir fonksiyonu içermiyor."},
         true},
        {"c0000142",
         {"a DLL failed to initialize (STATUS_DLL_INIT_FAILED)", "bir DLL başlatılamadı (STATUS_DLL_INIT_FAILED)"},
         {"A DLL was found and loaded, but it failed while starting up. Typical causes are a damaged or wrong DLL, a "
          "DLL it depends on that is missing, or security software interfering.",
          "Bir DLL bulundu ve yüklendi ama kendini başlatırken hata verdi. Tipik sebepler bozuk ya da yanlış bir DLL, "
          "onun ihtiyaç duyduğu eksik bir DLL ya da araya giren güvenlik yazılımıdır."},
         true},
        {"c000007b",
         {"bad image format (STATUS_INVALID_IMAGE_FORMAT)", "geçersiz görüntü biçimi (STATUS_INVALID_IMAGE_FORMAT)"},
         {"A 32-bit program loaded a 64-bit DLL (or the other way round), or a DLL is damaged.",
          "32-bit bir program 64-bit bir DLL yükledi (ya da tersi) veya bir DLL bozuk."},
         true},
        {"c0000005",
         {"access violation (memory error)", "erişim ihlali (bellek hatası)"},
         {"The program crashed inside its own code (or a library it uses) by touching memory it must not. This is "
          "typically a bug, a damaged installation or an incompatible add-on. It is not a missing component, so "
          "installing runtimes will usually not help.",
          "Program, dokunmaması gereken belleğe erişerek kendi kodunun (ya da kullandığı bir kütüphanenin) içinde "
          "çöktü. Bu genelde bir hata, bozuk kurulum ya da uyumsuz bir eklentidir. Eksik bir bileşen değildir; "
          "runtime kurmak çoğunlukla yardımcı olmaz."},
         false},
        {"c0000409",
         {"stack buffer overrun / fail-fast (STATUS_STACK_BUFFER_OVERRUN)",
          "yığın taşması / hızlı sonlandırma (STATUS_STACK_BUFFER_OVERRUN)"},
         {"The program or its runtime library stopped itself on purpose after detecting a fatal internal error "
          "(\"fail-fast\"). Despite the name this is often a deliberate abort, not necessarily an attack.",
          "Program ya da runtime kütüphanesi ölümcül bir iç hata fark edip kendini bilerek durdurdu "
          "(\"fail-fast\"). Adına rağmen bu çoğunlukla bilinçli bir sonlandırmadır, illa bir saldırı değildir."},
         false},
        {"c00000fd",
         {"stack overflow (STATUS_STACK_OVERFLOW)", "yığın taşması (STATUS_STACK_OVERFLOW)"},
         {"The program used up its stack memory, usually through endless recursion. This is a bug in the program.",
          "Program yığın belleğini tüketti, genelde sonsuz özyineleme yüzünden. Bu programdaki bir hatadır."},
         false},
        {"e0434352",
         {".NET unhandled exception", ".NET işlenmemiş istisnası"},
         {"A .NET program threw an error that nothing handled, so it was terminated.",
          "Bir .NET programı hiçbir yerde yakalanmayan bir hata verdi ve sonlandırıldı."},
         false},
        {"80000003",
         {"breakpoint (STATUS_BREAKPOINT)", "kesme noktası (STATUS_BREAKPOINT)"},
         {"A breakpoint instruction was executed. In released programs this is usually a deliberate abort from a "
          "failed internal check.",
          "Bir kesme noktası komutu çalıştırıldı. Yayımlanmış programlarda bu genelde başarısız bir iç kontrolün "
          "bilinçli sonlandırmasıdır."},
         false},
        {"c0000417",
         {"invalid C runtime parameter (STATUS_INVALID_CRUNTIME_PARAMETER)",
          "geçersiz C runtime parametresi (STATUS_INVALID_CRUNTIME_PARAMETER)"},
         {"The C runtime library detected an invalid argument passed by the program and stopped it. This is a bug in "
          "the program, not a missing component.",
          "C runtime kütüphanesi programın geçersiz bir argüman verdiğini fark edip programı durdurdu. Bu "
          "programdaki bir hatadır, eksik bileşen değil."},
         false},
        {"c0000374",
         {"heap corruption (STATUS_HEAP_CORRUPTION)", "yığın (heap) bozulması (STATUS_HEAP_CORRUPTION)"},
         {"The program damaged its own memory structures. This is a bug in the program or in an add-on it loaded.",
          "Program kendi bellek yapılarını bozdu. Bu programdaki ya da yüklediği bir eklentideki hatadır."},
         false},
        {"c000001d",
         {"illegal instruction (STATUS_ILLEGAL_INSTRUCTION)", "geçersiz komut (STATUS_ILLEGAL_INSTRUCTION)"},
         {"The program tried to run a processor instruction this computer's processor does not support (for "
          "example AVX on an old CPU). A different build of the program may exist.",
          "Program bu bilgisayarın işlemcisinin desteklemediği bir komutu çalıştırmaya çalıştı (örneğin eski bir "
          "işlemcide AVX). Programın farklı bir sürümü olabilir."},
         false},
    };
    return table;
  }

  static std::string normalize_code(std::string code) {
    code = to_lower_ascii(trim(code));
    if (code.starts_with("0x")) code.erase(0, 2);
    while (code.size() < 8) code.insert(code.begin(), '0');
    return code;
  }

  struct Crash {
    std::uint64_t time = 0;
    std::string code;     // normalized
    std::string module;   // faulting module
    std::string offset;
    std::string version;  // program version
    std::string dotnet;   // first line of the .NET exception text, if known
  };

  static std::string dotnet_exception_line(const std::string& text) {
    for (const char* marker : {"Exception Info:", "Unhandled Exception:"}) {
      const std::size_t p = text.find(marker);
      if (p == std::string::npos) continue;
      std::string rest = text.substr(p + std::string(marker).size());
      const std::size_t start = rest.find_first_not_of(" \t\r\n");
      if (start == std::string::npos) continue;
      return shorten(first_line(rest.substr(start)), 300);
    }
    return {};
  }

  void crashes() {
    std::vector<Crash> list;
    for (const env::EventRecord& e : env_.events(kAppLog, "Application Error", {1000}, kDays, 300)) {
      // Layout (verified on Windows 10): [0] app, [1] app version, [3] faulting module, [6] exception code,
      // [7] fault offset, [10] app path, [11] module path.
      if (e.data.size() < 7) continue;
      const std::string& path = e.data.size() > 10 ? e.data[10] : std::string();
      // Prefer the full path; fall back to the bare name only when the event has no path.
      const Match m = match_text(!trim(path).empty() ? path : e.data[0], prog_);
      if (m != Match::Full && m != Match::Name) continue;
      Crash c;
      c.time = e.time;
      c.code = normalize_code(e.data[6]);
      c.module = e.data[3];
      c.offset = e.data[7 < e.data.size() ? 7 : 6];
      c.version = e.data[1];
      list.push_back(std::move(c));
    }

    // .NET Runtime 1026 carries the exception text; the event only names the file, never the folder.
    std::vector<std::pair<std::uint64_t, std::string>> dotnet;
    for (const env::EventRecord& e : env_.events(kAppLog, ".NET Runtime", {1026}, kDays, 100)) {
      if (e.data.empty() || match_text(e.data[0], prog_) == Match::None) continue;
      if (match_text(e.data[0].substr(0, e.data[0].find('\n')), prog_) == Match::Other) continue;
      dotnet.emplace_back(e.time, dotnet_exception_line(e.data[0]));
    }
    std::vector<bool> used(dotnet.size(), false);
    for (Crash& c : list) {
      if (c.code != "e0434352") continue;
      std::size_t best = dotnet.size();
      std::uint64_t best_gap = 120ull * 10000000ull;
      for (std::size_t i = 0; i < dotnet.size(); ++i) {
        const std::uint64_t gap = dotnet[i].first > c.time ? dotnet[i].first - c.time : c.time - dotnet[i].first;
        if (gap <= best_gap) {
          best_gap = gap;
          best = i;
        }
      }
      if (best < dotnet.size()) {
        c.dotnet = dotnet[best].second;
        used[best] = true;
      }
    }
    for (std::size_t i = 0; i < dotnet.size(); ++i) {
      if (used[i]) continue;
      Crash c;
      c.time = dotnet[i].first;
      c.code = "e0434352";
      c.dotnet = dotnet[i].second;
      list.push_back(std::move(c));
    }
    if (list.empty()) return;
    std::stable_sort(list.begin(), list.end(), [](const Crash& a, const Crash& b) { return a.time > b.time; });

    const Crash& newest = list.front();
    const Code* info = nullptr;
    for (const Code& c : code_table()) {
      if (newest.code == c.code) info = &c;
    }
    const std::string code_text = "0x" + newest.code;
    const std::string code_name = info ? info->name(lang_) : format(Tr{"unrecognized error code {0}", "tanınmayan hata kodu {0}"}(lang_), {code_text});

    // Distinct (code, module) groups, newest first.
    std::map<std::string, int> counts;
    std::vector<const Crash*> groups;
    for (const Crash& c : list) {
      const std::string key = c.code + "|" + to_lower_ascii(c.module);
      if (counts[key]++ == 0) groups.push_back(&c);
    }

    Finding f;
    f.rule = "app-crash";
    f.certain = true;  // about the fact that it crashed; the cause is in the explanation
    const bool load_failure = info && info->load_failure;
    const bool confirms = load_failure && static_has_error_;
    f.severity = confirms ? Severity::Info : Severity::Warning;
    f.title = format(confirms ? Tr{"Windows' event log confirms: {1} ({0} crash record(s) in the last 30 days)",
                                   "Windows olay günlüğü doğruluyor: {1} (son 30 günde {0} çökme kaydı)"}(lang_)
                              : Tr{"Windows recorded {0} crash(es) of this program in the last 30 days: {1}",
                                   "Windows bu programın son 30 günde {0} çökmesini kaydetti: {1}"}(lang_),
                     {std::to_string(list.size()), code_name});

    std::string explanation = info ? info->meaning(lang_)
                                   : format(Tr{"Windows does not give a plain-language meaning for {0}. The program "
                                               "was terminated by an error of that type.",
                                               "{0} için sade bir açıklama yok. Program bu türde bir hata yüzünden "
                                               "sonlandırıldı."}(lang_),
                                            {code_text});
    if (load_failure && !static_has_error_) {
      explanation += Tr{" The file checks of this tool found nothing wrong at startup, so the DLL may be one that is "
                        "loaded later, or the problem has been fixed since this was recorded.",
                        " Bu aracın dosya kontrolleri açılışta bir sorun bulamadı; sorunlu DLL daha sonra yüklenen "
                        "bir DLL olabilir ya da kayıttan bu yana düzelmiş olabilir."}(lang_);
    }

    const std::string module_lower = to_lower_ascii(newest.module);
    const bool module_is_program = module_lower == prog_.name;
    const bool module_unknown = module_lower.empty() || module_lower.find("unloaded") != std::string::npos ||
                                module_lower.find("bad_module_info") != std::string::npos ||
                                module_lower.find("unknown") != std::string::npos;
    if (!module_unknown && !module_is_program) {
      const kb::DllEntry* entry = in_.kb.find_dll(module_lower);
      const kb::Package* pkg = entry && !entry->package.empty() ? in_.kb.find_package(entry->package) : nullptr;
      if (pkg && !load_failure) {
        explanation += " " + format(Tr{"The fault happened inside {0}, which belongs to {1}. That package is installed "
                                       "(it was loaded), so it is not missing; the usual cause is the program handing "
                                       "it bad data.",
                                       "Hata {0} içinde oluştu; bu dosya {1} paketine ait. Paket kurulu (yüklenmiş), "
                                       "yani eksik değil; genelde sebep programın ona hatalı veri vermesidir."}(lang_),
                                    {newest.module, pkg->name});
      }
    }

    // Evidence: newest record, then the other distinct groups, then the count.
    auto line = [&](const Crash& c, int count) {
      std::string s = when(c.time, now_, lang_) + ": " +
                      format(Tr{"exception 0x{0}", "hata kodu 0x{0}"}(lang_), {c.code});
      if (!c.module.empty()) s += format(Tr{" in {0}", ", modül: {0}"}(lang_), {c.module});
      if (!c.offset.empty()) s += format(Tr{" at offset {0}", ", ofset: {0}"}(lang_), {c.offset});
      if (!c.version.empty()) s += format(Tr{", program version {0}", ", program sürümü: {0}"}(lang_), {c.version});
      if (count > 1) s += format(Tr{" (x{0})", " (x{0})"}(lang_), {std::to_string(count)});
      return s;
    };
    f.evidence.push_back(line(newest, counts[newest.code + "|" + module_lower]));
    if (!newest.dotnet.empty()) {
      f.evidence.push_back(format(Tr{".NET Runtime: {0}", ".NET Runtime: {0}"}(lang_), {newest.dotnet}));
    }
    for (std::size_t i = 1; i < groups.size() && i < 3; ++i) {
      f.evidence.push_back(line(*groups[i], counts[groups[i]->code + "|" + to_lower_ascii(groups[i]->module)]));
    }
    if (!module_unknown && module_is_program) {
      f.evidence.push_back(Tr{"The fault is inside the program's own code.", "Hata programın kendi kodunda."}(lang_));
    }
    if (!module_unknown && !module_is_program) {
      f.evidence.push_back(format(Tr{"faulting module: {0}", "hatalı modül: {0}"}(lang_), {newest.module}));
    }

    if (!confirms) {
      Fix fix;
      if (load_failure) {
        fix.steps = Tr{"Reinstall the program (for games: \"Verify integrity of game files\"). If it keeps happening, "
                       "look at the file findings of this report and at Event Viewer for details.",
                       "Programı yeniden kurun (oyunlar için: \"Oyun dosyalarının bütünlüğünü doğrula\"). Sürerse bu "
                       "raporun dosya bulgularına ve Olay Görüntüleyicisi'ndeki ayrıntılara bakın."}(lang_);
      } else {
        fix.steps = Tr{"Check for an update of the program (and of its add-ons or mods), reinstall it, and for games "
                       "verify the game files and update the graphics driver. Reliability Monitor (run \"perfmon "
                       "/rel\") lists the same crashes. If it keeps crashing, send the details above to the "
                       "developer.",
                       "Programın (ve eklenti/modlarının) güncellemesini kontrol edin, yeniden kurun; oyunlarda oyun "
                       "dosyalarını doğrulayın ve ekran kartı sürücüsünü güncelleyin. Güvenilirlik İzleyicisi "
                       "(\"perfmon /rel\") aynı çökmeleri listeler. Sürerse yukarıdaki ayrıntıları geliştiriciye "
                       "iletin."}(lang_);
      }
      f.fix = std::move(fix);
    }
    f.explanation = std::move(explanation);
    findings_.push_back(std::move(f));
  }

  // ---- Rule 8b: the popup Windows showed (Application Popup, ID 26) -------------

  static std::vector<std::string> dll_names_in(const std::string& text) {
    std::vector<std::string> out;
    const std::string t = to_lower_ascii(text);
    for (std::size_t pos = t.find(".dll"); pos != std::string::npos; pos = t.find(".dll", pos + 1)) {
      std::size_t start = pos;
      while (start > 0 && (is_token_char(t[start - 1]) || t[start - 1] == '.')) --start;
      const std::string name = t.substr(start, pos + 4 - start);
      if (name.size() > 4) out.push_back(name);
    }
    return out;
  }

  bool static_mentions(std::string_view needle_lower) const {
    for (const Finding& f : findings_) {
      for (const std::string& ev : f.evidence) {
        if (to_lower_ascii(ev).find(needle_lower) != std::string::npos) return true;
      }
    }
    return false;
  }

  void popups() {
    for (const env::EventRecord& e : env_.events(kAppLog, "Application Popup", {26}, kDays, 100)) {
      if (e.data.empty() || !event_mentions_program(e, prog_)) continue;
      // Only the newest popup is shown; older ones are usually the same message again.
      const std::string text = shorten(e.data[0], 400);
      bool confirmed = false;
      for (const std::string& dll : dll_names_in(e.data[0])) {
        if (static_mentions(dll)) confirmed = true;
      }
      Finding f;
      f.rule = "windows-error-popup";
      f.certain = true;
      f.severity = confirmed ? Severity::Info : Severity::Warning;
      f.title = confirmed ? Tr{"Windows' event log confirms: it showed an error message when this program started",
                               "Windows olay günlüğü doğruluyor: bu program açılırken bir hata mesajı gösterdi"}(lang_)
                          : Tr{"Windows showed an error message when this program started",
                               "Bu program açılırken Windows bir hata mesajı gösterdi"}(lang_);
      f.explanation =
          confirmed
              ? Tr{"This is the message Windows displayed; it matches a file problem found by this tool.",
                   "Bu, Windows'un gösterdiği mesajdır; bu aracın bulduğu bir dosya sorunuyla örtüşüyor."}(lang_)
              : Tr{"This is the exact text Windows displayed to the user, which is stronger evidence than any "
                   "guess. It was recorded in the past; if you installed or repaired something since, it may no "
                   "longer apply.",
                   "Bu, Windows'un kullanıcıya gösterdiği metnin kendisidir ve her tahminden daha güçlü bir kanıttır. "
                   "Geçmişte kaydedilmiş; o zamandan beri bir şey kurduysanız ya da onardıysanız artık geçerli "
                   "olmayabilir."}(lang_);
      f.evidence.push_back(format(Tr{"Windows showed ({0}): {1}", "Windows şunu gösterdi ({0}): {1}"}(lang_),
                                  {when(e.time, now_, lang_), text}));
      if (!confirmed) {
        Fix fix;
        fix.steps = Tr{"Follow what the message says (usually: reinstall the program). If it names a DLL, install the "
                       "official package that contains it; never download single DLL files from websites.",
                       "Mesajın söylediğini yapın (genelde: programı yeniden kurmak). Bir DLL adı geçiyorsa onu "
                       "içeren resmi paketi kurun; tek tek DLL dosyalarını asla sitelerden indirmeyin."}(lang_);
        f.fix = std::move(fix);
      }
      findings_.push_back(std::move(f));
      return;
    }
  }

  // ---- Rule 8c: side-by-side (manifest) errors ----------------------------------

  struct Assembly {
    std::string name;     // "Microsoft.VC90.CRT"
    std::string arch;     // "x86", "x64", "arm64" or ""
    std::string version;  // "9.0.21022.8" or ""
    std::string package;  // KB package id, or ""
  };

  static std::string attr_value(const std::string& lower, std::size_t from, std::size_t to, std::string_view key) {
    const std::size_t p = lower.find(std::string(key) + "=\"", from);
    if (p == std::string::npos || p >= to) return {};
    const std::size_t start = p + key.size() + 2;
    const std::size_t end = lower.find('"', start);
    if (end == std::string::npos || end > to) return {};
    return lower.substr(start, end - start);
  }

  static std::vector<Assembly> assemblies_in(const std::string& text) {
    std::vector<Assembly> out;
    const std::string lower = to_lower_ascii(text);
    for (const char* family : {"microsoft.vc80.", "microsoft.vc90."}) {
      for (std::size_t pos = lower.find(family); pos != std::string::npos; pos = lower.find(family, pos + 1)) {
        std::size_t end = pos;
        while (end < lower.size() && (std::isalnum(static_cast<unsigned char>(lower[end])) || lower[end] == '.')) ++end;
        Assembly a;
        a.name = text.substr(pos, end - pos);
        const std::size_t limit = std::min(lower.size(), end + 300);
        a.version = attr_value(lower, end, limit, "version");
        std::string arch = attr_value(lower, end, limit, "processorarchitecture");
        a.arch = arch == "x86" ? "x86" : arch == "amd64" ? "x64" : arch == "arm64" ? "arm64" : "";
        a.package = std::string(family) == "microsoft.vc80." ? "vcredist2005" : "vcredist2008";
        // VC++ debug assemblies have no redistributable.
        if (lower.find("debug", pos) < end) a.package.clear();
        out.push_back(std::move(a));
      }
    }
    return out;
  }

  bool winsxs_has(const Assembly& a, const std::string& arch) const {
    const std::string prefix_arch = arch == "x64" ? "amd64" : arch == "arm64" ? "arm64" : "x86";
    const std::string prefix = prefix_arch + "_" + to_lower_ascii(a.name) + "_";
    return !env_.list_dir(env_.windows_dir() / "WinSxS", prefix).empty();
  }

  void side_by_side() {
    for (const env::EventRecord& e : env_.events(kAppLog, "SideBySide", {33, 35, 59, 63, 80}, kDays, 100)) {
      if (!event_mentions_program(e, prog_)) continue;
      std::vector<Assembly> asms;
      for (const std::string& field : e.data) {
        for (Assembly& a : assemblies_in(field)) asms.push_back(std::move(a));
      }
      const std::uint64_t age_days = now_ > e.time ? (now_ - e.time) / kTicksPerDay : 0;
      Finding f;
      f.rule = "side-by-side";
      f.certain = true;
      f.severity = age_days <= 7 ? Severity::Error : Severity::Warning;

      const std::string id_text = std::to_string(e.id);
      std::string asm_names;
      for (const Assembly& a : asms) asm_names += (asm_names.empty() ? "" : ", ") + a.name;

      const Assembly* fixable = nullptr;
      for (const Assembly& a : asms) {
        if (!a.package.empty()) {
          fixable = &a;
          break;
        }
      }
      std::string arch = fixable && !fixable->arch.empty() ? fixable->arch : in_.arch;
      const kb::Package* pkg = fixable ? in_.kb.find_package(fixable->package) : nullptr;

      bool installed_now = false;
      bool covered = false;
      if (fixable && pkg) {
        for (const Finding& s : findings_) {
          if (s.fix && s.fix->package_id == pkg->id) covered = true;
        }
        installed_now = !arch.empty() && winsxs_has(*fixable, arch);
      }

      if (covered) {
        f.severity = Severity::Info;
        f.title = format(Tr{"Windows' event log confirms: {0} is needed", "Windows olay günlüğü doğruluyor: {0} gerekli"}(lang_),
                         {pkg->name});
        f.explanation = Tr{"Windows itself reported that this side-by-side component could not be found when the "
                           "program started. This matches the missing package reported above.",
                           "Windows, program açılırken bu yan yana (side-by-side) bileşenin bulunamadığını bizzat "
                           "bildirdi. Bu, yukarıda bildirilen eksik paketle örtüşüyor."}(lang_);
      } else if (fixable && pkg && installed_now) {
        f.severity = Severity::Info;
        f.certain = false;
        f.title = format(Tr{"Windows once reported a missing {0}, but it seems to be installed now",
                            "Windows bir zamanlar {0} eksikliğini bildirdi ama şimdi kurulu görünüyor"}(lang_),
                         {pkg->name});
        f.explanation = Tr{"A component of this runtime is present in the WinSxS store today, so the problem may "
                           "already be fixed. If the program still fails, the exact version it asks for may be "
                           "missing.",
                           "Bu runtime'ın bir bileşeni şu an WinSxS deposunda var, yani sorun çoktan düzelmiş "
                           "olabilir. Program hâlâ açılmıyorsa istediği tam sürüm eksik olabilir."}(lang_);
      } else if (fixable && pkg) {
        f.title = format(Tr{"Windows reported that {0} ({1}) is missing", "Windows {0} ({1}) paketinin eksik olduğunu bildirdi"}(lang_),
                         {pkg->name, arch.empty() ? "?" : arch});
        f.explanation = Tr{"When the program started, Windows could not find a side-by-side runtime component it "
                           "declares in its manifest (error recorded in the Application log). Programs built with "
                           "Visual C++ 2005/2008 need exactly this package.",
                           "Program açılırken Windows, manifest'inde belirttiği bir yan yana (side-by-side) runtime "
                           "bileşenini bulamadı (Uygulama günlüğüne kaydedilen hata). Visual C++ 2005/2008 ile "
                           "yapılmış programlar tam olarak bu paketi ister."}(lang_);
        if (!arch.empty()) f.fix = make_package_fix(*pkg, arch, env_, lang_);
        if (f.fix) {
          f.fix->steps += Tr{" Never download single DLL files from \"DLL download\" websites.",
                             " Tek tek DLL dosyalarını asla \"DLL indirme\" sitelerinden indirmeyin."}(lang_);
        }
      } else {
        f.title = Tr{"Windows reported a side-by-side (manifest) error for this program",
                     "Windows bu program için bir yan yana (side-by-side) / manifest hatası bildirdi"}(lang_);
        f.explanation = Tr{"Windows could not build the program's component configuration: a component named in its "
                           "manifest is missing, or the manifest itself is broken. This tool cannot tell which "
                           "package is meant from the log entry.",
                           "Windows programın bileşen yapılandırmasını oluşturamadı: manifest'inde adı geçen bir "
                           "bileşen eksik ya da manifest'in kendisi bozuk. Bu araç kayıttan hangi paketin "
                           "kastedildiğini çıkaramıyor."}(lang_);
        Fix fix;
        fix.steps = Tr{"Reinstall the program. If it is old, look for the Visual C++ 2005/2008 redistributable "
                       "in the developer's instructions.",
                       "Programı yeniden kurun. Eskiyse, geliştiricinin yönergelerinde Visual C++ 2005/2008 "
                       "yeniden dağıtılabilir paketini arayın."}(lang_);
        f.fix = std::move(fix);
      }

      f.evidence.push_back(format(Tr{"SideBySide event {0}, {1}", "SideBySide olayı {0}, {1}"}(lang_),
                                  {id_text, when(e.time, now_, lang_)}));
      if (asms.empty() && !e.data.empty() && !trim(e.data[0]).empty()) f.evidence.push_back(shorten(e.data[0], 200));
      for (const Assembly& a : asms) {
        std::string s = a.name;
        if (!a.arch.empty()) s += " " + a.arch;
        if (!a.version.empty()) s += " " + a.version;
        f.evidence.push_back(s);
      }
      findings_.push_back(std::move(f));
      return;
    }
  }

  // ---- Rule 9a: Mark of the Web ---------------------------------------------------

  static std::string clean_url(std::string url) {
    url = trim(std::move(url));
    // Query strings and fragments can carry tokens; show only where the file came from.
    const std::size_t cut = url.find_first_of("?#");
    if (cut != std::string::npos) url.resize(cut);
    return shorten(url, 160);
  }

  static std::string ini_value(const std::string& text, std::string_view key) {
    std::size_t pos = 0;
    while (pos < text.size()) {
      std::size_t end = text.find_first_of("\r\n", pos);
      if (end == std::string::npos) end = text.size();
      const std::string line = text.substr(pos, end - pos);
      if (line.size() > key.size() && line[key.size()] == '=' &&
          util::iequals(std::string_view(line).substr(0, key.size()), key)) {
        return trim(line.substr(key.size() + 1));
      }
      pos = end + 1;
    }
    return {};
  }

  void mark_of_the_web() {
    const auto zone = env_.zone_identifier(in_.program);
    if (!zone) return;
    const std::string zone_id = ini_value(*zone, "ZoneId");
    if (zone_id != "3" && zone_id != "4") return;

    Finding f;
    f.rule = "downloaded-from-internet";
    f.severity = Severity::Info;
    f.certain = true;  // the mark is there; whether SmartScreen asked is up to Windows
    f.title = Tr{"This program was downloaded from the internet",
                 "Bu program internetten indirilmiş"}(lang_);
    f.explanation = Tr{"Windows marks files that came from the internet or from an untrusted zone. When you start "
                       "such a program, SmartScreen may show \"Windows protected your PC\" and stop it until you "
                       "confirm. That is a safety check, not a fault in the program, and this tool cannot tell "
                       "whether it appeared.",
                       "Windows, internetten ya da güvenilmeyen bir bölgeden gelen dosyaları işaretler. Böyle bir "
                       "programı başlatınca SmartScreen \"Windows bilgisayarınızı korudu\" penceresini gösterip siz "
                       "onaylayana kadar programı durdurabilir. Bu bir güvenlik kontrolüdür, programdaki bir arıza "
                       "değil; bu araç pencerenin çıkıp çıkmadığını bilemez."}(lang_);
    f.evidence.push_back(zone_id == "3" ? Tr{"ZoneId=3 (Internet)", "ZoneId=3 (İnternet)"}(lang_)
                                        : Tr{"ZoneId=4 (Restricted sites)", "ZoneId=4 (Kısıtlı siteler)"}(lang_));
    for (const char* key : {"HostUrl", "ReferrerUrl"}) {
      const std::string url = clean_url(ini_value(*zone, key));
      if (!url.empty() && !url.starts_with("about:")) f.evidence.push_back(std::string(key) + ": " + url);
    }
    Fix fix;
    fix.steps = Tr{"Only if you trust where it came from (the developer's own website or an official store): in the "
                   "SmartScreen window click \"More info\", then \"Run anyway\". Alternatively open the file's "
                   "Properties and tick \"Unblock\" (this affects only this file). If you are not sure about the "
                   "source, do not run it - that is exactly what the warning is for. Do not turn SmartScreen off "
                   "for everything.",
                   "Yalnızca geldiği yere güveniyorsanız (geliştiricinin kendi sitesi ya da resmi bir mağaza): "
                   "SmartScreen penceresinde \"Ek bilgi\", ardından \"Yine de çalıştır\" düğmesine tıklayın. Ya da "
                   "dosyanın Özellikleri'nde \"Engellemeyi kaldır\" kutusunu işaretleyin (yalnızca bu dosyayı "
                   "etkiler). Kaynaktan emin değilseniz çalıştırmayın - uyarı tam olarak bunun için var. "
                   "SmartScreen'i her şey için kapatmayın."}(lang_);
    f.fix = std::move(fix);
    findings_.push_back(std::move(f));
  }

  // ---- Rule 9b: Microsoft Defender -------------------------------------------------

  void defender() {
    struct Hit {
      std::uint64_t time;
      std::string threat, action, path;
      bool acted;
    };
    std::vector<Hit> hits;
    std::string all_text;  // for linking to missing files
    for (const env::EventRecord& e : env_.events(kDefenderLog, "", {1116, 1117}, kDays, 200)) {
      std::string path = field_named(e, "Path");
      if (path.empty()) {
        for (const std::string& d : e.data) path += d + "\n";
      }
      // Only the program itself or one of its own modules (not just any file in the same folder). A bare
      // name without folder is accepted too, but not another folder's file of the same name.
      if (!text_names_own_file(path, prog_) && match_text(path, prog_) != Match::Name) continue;
      std::string action = field_named(e, "Action Name");
      if (action.empty()) action = field_named(e, "Status Description");
      const std::string action_lower = to_lower_ascii(action);
      if (action_lower.find("allow") != std::string::npos || action_lower.find("no action") != std::string::npos) continue;
      Hit h;
      h.time = e.time;
      h.threat = field_named(e, "Threat Name");
      h.action = shorten(action, 80);
      h.path = shorten(path, 240);
      h.acted = e.id == 1117;
      all_text += norm(path) + "\n";
      hits.push_back(std::move(h));
    }
    if (hits.empty()) return;

    const bool acted = std::any_of(hits.begin(), hits.end(), [](const Hit& h) { return h.acted; });

    // Link to the static "missing program file" finding.
    std::vector<std::string> linked;
    for (Finding& s : findings_) {
      if (s.rule != "missing-program-file") continue;
      bool touched = false;
      for (const std::string& ev : s.evidence) {
        const std::string name = to_lower_ascii(ev.substr(0, ev.find(' ')));
        if (name.size() < 5 || all_text.find(name) == std::string::npos) continue;
        linked.push_back(name);
        touched = true;
      }
      if (touched) {
        s.certain = true;
        s.evidence.push_back(Tr{"Microsoft Defender recorded a detection for this file (see the Defender finding).",
                                "Microsoft Defender bu dosya için bir tespit kaydetti (Defender bulgusuna bakın)."}(lang_));
      }
    }

    Finding f;
    f.rule = "defender-quarantine";
    f.severity = Severity::Error;
    f.certain = true;
    f.title = acted ? Tr{"Microsoft Defender quarantined or removed files of this program",
                         "Microsoft Defender bu programın dosyalarını karantinaya aldı ya da sildi"}(lang_)
                    : Tr{"Microsoft Defender detected a threat in this program's files",
                         "Microsoft Defender bu programın dosyalarında tehdit tespit etti"}(lang_);
    f.explanation = Tr{"Microsoft Defender reported a detection involving this program or its folder. If it removed "
                       "a file the program needs, the program cannot start. A detection can be real malware or a "
                       "false positive; this tool cannot tell which.",
                       "Microsoft Defender bu program ya da klasörüyle ilgili bir tespit bildirdi. Programın "
                       "ihtiyaç duyduğu bir dosyayı kaldırdıysa program açılamaz. Tespit gerçek bir zararlı ya da "
                       "yanlış alarm olabilir; bu araç hangisi olduğunu bilemez."}(lang_);
    if (!linked.empty()) {
      std::string names;
      std::set<std::string> seen;
      for (const std::string& n : linked) {
        if (seen.insert(n).second) names += (names.empty() ? "" : ", ") + n;
      }
      f.explanation += " " + format(Tr{"This explains the missing file(s) reported above: {0}.",
                                       "Bu, yukarıda bildirilen eksik dosya(lar)ı açıklıyor: {0}."}(lang_),
                                    {names});
    }
    std::set<std::string> shown;
    for (const Hit& h : hits) {
      if (f.evidence.size() >= 5) break;
      if (!shown.insert(to_lower_ascii(h.threat + "|" + h.path)).second) continue;
      std::string s = when(h.time, now_, lang_) + ": ";
      s += h.threat.empty() ? Tr{"detection", "tespit"}(lang_) : h.threat;
      if (!h.action.empty()) s += " [" + h.action + "]";
      s += " - " + h.path;
      f.evidence.push_back(std::move(s));
    }
    Fix fix;
    fix.steps = Tr{"Open Windows Security > Virus & threat protection > Protection history and look at the item. "
                   "Restore it only if you are sure the file is safe (for example a false positive in a program from "
                   "a source you trust); if you are not sure, leave it quarantined and get a fresh copy of the "
                   "program from its official source. This tool never restores files.",
                   "Windows Güvenliği > Virüs ve tehdit koruması > Koruma geçmişi bölümünü açıp öğeye bakın. "
                   "Dosyanın güvenli olduğundan eminseniz (örneğin güvendiğiniz bir kaynaktaki programda yanlış "
                   "alarm) geri yükleyin; emin değilseniz karantinada bırakın ve programın resmi kaynağından yeni "
                   "bir kopya alın. Bu araç dosya geri yüklemez."}(lang_);
    f.fix = std::move(fix);
    findings_.push_back(std::move(f));
  }

  // ---- Rule 9c: code integrity / Smart App Control ----------------------------------
  //
  // Only ID 3077 (enforced block: the file violated the code integrity policy) counts.
  // 3033 ("did not meet the Microsoft signing level") fires constantly for harmless
  // loads (e.g. Chrome), 3076/3034 are audit-only, 3089 is a companion record.

  bool ci_blocked_ = false;

  void code_integrity() {
    const int sac = env_.smart_app_control_state();
    for (const env::EventRecord& e : env_.events(kCodeIntegrityLog, "", {3077}, kDays, 200)) {
      bool hit = false;
      for (const std::string& field : e.data) {
        if (text_names_own_file(field, prog_)) hit = true;
      }
      if (!hit) continue;
      ci_blocked_ = true;

      std::string file = field_named(e, "FileNameBuffer");
      if (file.empty()) {
        for (const std::string& d : e.data) {
          if (d.find('\\') != std::string::npos) {
            file = d;
            break;
          }
        }
      }
      Finding f;
      f.rule = "code-integrity-block";
      f.severity = Severity::Error;
      f.certain = true;  // Windows logged an enforced block
      if (sac == 1) {
        f.title = Tr{"Smart App Control blocked this program", "Akıllı Uygulama Denetimi bu programı engelledi"}(lang_);
        f.explanation = Tr{"Smart App Control is on and Windows logged that it blocked a file of this program. It "
                           "allows only apps that are signed by a trusted publisher or known to be safe, so unsigned "
                           "or little-known programs are blocked.",
                           "Akıllı Uygulama Denetimi açık ve Windows bu programın bir dosyasını engellediğini "
                           "kaydetti. Yalnızca güvenilir bir yayıncı tarafından imzalanmış ya da güvenli bilinen "
                           "uygulamalara izin verir; imzasız ya da az bilinen programlar engellenir."}(lang_);
      } else {
        f.title = Tr{"Windows blocked this program because of an application-control policy",
                     "Windows bu programı bir uygulama denetimi ilkesi yüzünden engelledi"}(lang_);
        f.explanation = Tr{"Windows logged that its code integrity policy blocked a file of this program. This is "
                           "either Smart App Control (Windows 11) or an App Control / WDAC policy, for example one "
                           "set by an organization. This tool cannot tell which; Smart App Control is not reported "
                           "as on on this computer.",
                           "Windows, kod bütünlüğü ilkesinin bu programın bir dosyasını engellediğini kaydetti. Bu "
                           "ya Akıllı Uygulama Denetimi (Windows 11) ya da örneğin bir kurum tarafından konan bir "
                           "Uygulama Denetimi / WDAC ilkesidir. Bu araç hangisi olduğunu bilemez; bu bilgisayarda "
                           "Akıllı Uygulama Denetimi açık görünmüyor."}(lang_);
      }
      f.evidence.push_back(when(e.time, now_, lang_) + ": " + Tr{"blocked ", "engellendi: "}(lang_) +
                           (file.empty() ? prog_.name : shorten(file, 240)));
      const std::string policy = field_named(e, "PolicyNameBuffer");
      if (!policy.empty()) f.evidence.push_back(format(Tr{"policy: {0}", "ilke: {0}"}(lang_), {shorten(policy, 120)}));
      Fix fix;
      fix.steps = Tr{"Get a digitally signed version of the program from its developer, or ask the developer. "
                     "Smart App Control cannot be relaxed for a single app: it can only be switched off completely, "
                     "and once off it stays off until Windows is reset or reinstalled. Whether that trade-off is "
                     "worth it is your decision; this tool does not recommend it. If the policy comes from your "
                     "organization, ask your administrator.",
                     "Programın geliştiricisinden dijital imzalı bir sürüm edinin ya da geliştiriciye sorun. Akıllı "
                     "Uygulama Denetimi tek bir uygulama için gevşetilemez: yalnızca tamamen kapatılabilir ve "
                     "kapatıldıktan sonra Windows sıfırlanana ya da yeniden kurulana kadar kapalı kalır. Bu "
                     "değiş tokuşa değip değmeyeceği sizin kararınızdır; bu araç bunu önermez. İlke kurumunuzdan "
                     "geliyorsa yöneticinize sorun."}(lang_);
      f.fix = std::move(fix);
      findings_.push_back(std::move(f));
      return;
    }
  }

  // ---- Rule 9d: Smart App Control is on and the program is unsigned -----------------

  void unsigned_with_sac() {
    if (ci_blocked_ || env_.smart_app_control_state() != 1) return;
    const auto& info = in_.resolution.target.info;
    if (!info || info->is_dll || info->has_signature()) return;
    Finding f;
    f.rule = "sac-unsigned";
    f.severity = Severity::Info;
    f.certain = false;
    f.title = Tr{"Smart App Control is on and this program is not digitally signed",
                 "Akıllı Uygulama Denetimi açık ve bu program dijital imzalı değil"}(lang_);
    f.explanation = Tr{"Smart App Control blocks unsigned programs that Microsoft does not know to be safe. If this "
                       "program fails to start without any error, this may be why - but no block was recorded in the "
                       "event log, so this is only a possibility.",
                       "Akıllı Uygulama Denetimi, Microsoft'un güvenli bilmediği imzasız programları engeller. Bu "
                       "program hiçbir hata göstermeden açılmıyorsa sebep bu olabilir - ancak olay günlüğünde bir "
                       "engelleme kaydı yok, yani bu yalnızca bir ihtimal."}(lang_);
    f.evidence.push_back(Tr{"no digital signature found in the file (not verified either way)",
                            "dosyada dijital imza bulunamadı (geçerliliği ayrıca doğrulanmadı)"}(lang_));
    Fix fix;
    fix.steps = Tr{"Ask the developer for a signed version. Smart App Control can only be switched off completely, and "
                   "that is permanent until Windows is reset; this tool does not recommend it.",
                   "Geliştiriciden imzalı bir sürüm isteyin. Akıllı Uygulama Denetimi yalnızca tamamen "
                   "kapatılabilir ve bu, Windows sıfırlanana kadar kalıcıdır; bu araç bunu önermez."}(lang_);
    f.fix = std::move(fix);
    findings_.push_back(std::move(f));
  }

  const SystemRulesInput& in_;
  const env::Environment& env_;
  Lang lang_;
  std::vector<Finding>& findings_;
  Prog prog_;
  std::uint64_t now_;
  bool static_has_error_;
};

}  // namespace

void apply_system_rules(const SystemRulesInput& in, std::vector<Finding>& findings) {
  SystemRules(in, findings).run();
}

}  // namespace neden::diagnose::detail
