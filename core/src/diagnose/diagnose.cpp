#include "neden/diagnose.h"

#include <windows.h>

#include <algorithm>
#include <cstdio>
#include <exception>
#include <map>
#include <set>

#include "diagnose/internal.h"
#include "kb/json.h"
#include "neden/version.h"
#include "util/text.h"

namespace neden::diagnose {

namespace detail {

std::string format(std::string pattern, std::initializer_list<std::string> args) {
  std::size_t i = 0;
  for (const std::string& a : args) {
    const std::string token = "{" + std::to_string(i++) + "}";
    for (std::size_t pos = pattern.find(token); pos != std::string::npos; pos = pattern.find(token, pos + a.size())) {
      pattern.replace(pos, token.size(), a);
    }
  }
  return pattern;
}

Fix make_package_fix(const kb::Package& pkg, const std::string& arch, const env::Environment& env, Lang lang) {
  Fix fix;
  fix.package_id = pkg.id;
  fix.package_name = pkg.name;
  fix.arch = arch;
  fix.winget_id = pkg.winget_for(arch);
  fix.url = pkg.url_for(arch);
  fix.info_url = pkg.info_url;
  if (pkg.kind == "windows-feature") {
    fix.steps = format(Tr{"Turn on \"{0}\" in Windows Features.", "Windows Özellikleri'nden \"{0}\" seçeneğini açın."}(lang),
                       {pkg.name});
  } else if (pkg.kind == "os-update") {
    fix.steps = format(Tr{"Install all Windows updates; {0} is delivered through Windows Update. On Windows 10 and "
                          "later it is built in, so if it is missing there, Windows files are damaged (run "
                          "\"sfc /scannow\" as administrator).",
                          "Tüm Windows güncellemelerini yükleyin; {0} Windows Update üzerinden gelir. Windows 10 "
                          "ve sonrasında zaten yerleşiktir; orada eksikse Windows dosyaları bozulmuştur (yönetici "
                          "olarak \"sfc /scannow\" çalıştırın)."}(lang),
                       {pkg.name});
  } else {
    fix.steps = format(Tr{"Install {0} ({1}) from the official source.",
                          "{0} ({1}) paketini resmi kaynağından kurun."}(lang),
                       {pkg.name, arch});
    if (arch == "x86" && env.os().is_64bit) {
      fix.steps += Tr{" This program is 32-bit, so it needs the x86 version even on 64-bit Windows.",
                      " Bu program 32-bit olduğu için 64-bit Windows'ta bile x86 sürümüne ihtiyaç duyar."}(lang);
    }
  }
  return fix;
}

}  // namespace detail

namespace {

using resolve::Location;
using resolve::Module;
using util::to_lower_ascii;

using detail::format;
using detail::Tr;
using detail::u8;

std::string arch_of(pe::Machine m) { return pe::machine_name(m); }

std::string os_string(const env::OsInfo& os) {
  return "Windows " + std::to_string(os.major) + "." + std::to_string(os.minor) + "." + std::to_string(os.build) +
         (os.is_arm64 ? " arm64" : os.is_64bit ? " x64" : " x86");
}

class Diagnoser {
 public:
  Diagnoser(const env::Environment& env, const kb::KnowledgeBase& kb, Lang lang) : env_(env), kb_(kb), lang_(lang) {}

  Report run(const std::filesystem::path& program) {
    Report report;
    report.program = program;
    report.lang = lang_;
    report.os = os_string(env_.os());
    resolve::Options options;
    options.is_redistributable = [this](std::string_view name) {
      const kb::DllEntry* e = kb_.find_dll(name);
      return e && !e->package.empty() && !e->program_file && !e->gpu_driver;
    };
    report.resolution = resolve::resolve(program, env_, options);
    const resolve::Result& res = report.resolution;
    program_name_ = to_lower_ascii(u8(program.filename()));

    if (!res.target.ok()) {
      corrupt_target(program, res.target);
    } else {
      const pe::PeInfo& info = *res.target.info;
      arch_ = arch_of(res.process_machine);
      report.program_arch = arch_;
      if (info.truncated) incomplete_file();
      if (platform(info, res.process_machine)) {
        dlls(res);
        netfx35(program, info);
        dotnet(program);
        packed(info);
      }
    }

    const bool nothing = std::none_of(findings_.begin(), findings_.end(),
                                      [](const Finding& f) { return f.severity != Severity::Info; });
    if (nothing) nothing_found();

    // Rules 8 and 9: what the machine itself recorded (event log, downloaded-file mark, Defender, Smart App
    // Control). They run even when the file did not parse.
    const std::size_t static_count = findings_.size();
    detail::apply_system_rules({env_, kb_, lang_, program, res, arch_ == "unknown" ? std::string() : arch_},
                               findings_);
    if (nothing) {
      // A machine-level cause that is a certain Error (e.g. Defender removed a file) makes "nothing found" misleading.
      const bool cause = std::any_of(findings_.begin() + static_cast<std::ptrdiff_t>(static_count), findings_.end(),
                                     [](const Finding& f) { return f.severity == Severity::Error; });
      if (cause) {
        findings_.erase(std::remove_if(findings_.begin(), findings_.end(),
                                       [](const Finding& f) { return f.rule == "no-problem-found"; }),
                        findings_.end());
      }
    }
    std::stable_sort(findings_.begin(), findings_.end(), [](const Finding& a, const Finding& b) {
      if (a.severity != b.severity) return a.severity < b.severity;
      return a.certain && !b.certain;
    });
    report.findings = std::move(findings_);
    return report;
  }

 private:
  // ---- Rule 6: corrupt or incomplete file ---------------------------------

  void corrupt_target(const std::filesystem::path& program, const pe::ParseResult& r) {
    Finding f;
    f.rule = "corrupt-file";
    f.evidence.push_back(std::string("parse: ") + pe::parse_error_name(r.error) + (r.detail.empty() ? "" : " (" + r.detail + ")"));

    if (r.error == pe::ParseError::IoError) {
      f.rule = "unreadable-file";
      f.title = Tr{"The file cannot be read", "Dosya okunamıyor"}(lang_);
      f.explanation = Tr{"The file could not be opened. Another program may be using it, an antivirus may be blocking "
                         "it, or you may not have permission to read it.",
                         "Dosya açılamadı. Başka bir program kullanıyor olabilir, bir antivirüs engelliyor olabilir ya "
                         "da dosyayı okuma izniniz olmayabilir."}(lang_);
      f.certain = false;
      findings_.push_back(std::move(f));
      return;
    }

    const auto head = env_.read_file(program, 4096).value_or(std::vector<std::uint8_t>{});
    const bool all_zero = !head.empty() && std::all_of(head.begin(), head.end(), [](std::uint8_t b) { return b == 0; });
    const bool zip = head.size() >= 4 && head[0] == 'P' && head[1] == 'K' && head[2] == 3 && head[3] == 4;
    const bool rar = head.size() >= 4 && head[0] == 'R' && head[1] == 'a' && head[2] == 'r' && head[3] == '!';
    const bool seven_zip = head.size() >= 2 && head[0] == '7' && head[1] == 'z';

    if ((r.error == pe::ParseError::NotPe || r.error == pe::ParseError::BadPeOffset) && is_16bit(program, head)) {
      f.rule = "16bit-program";
      f.title = Tr{"This is a 16-bit (DOS / Windows 3.x) program", "Bu 16-bit (DOS / Windows 3.x) bir program"}(lang_);
      f.explanation = Tr{"64-bit Windows cannot run 16-bit programs at all. This is not something a missing file can "
                         "cause.",
                         "64-bit Windows 16-bit programları hiç çalıştıramaz. Bu bir eksik dosya sorunu değil."}(lang_);
      Fix fix;
      fix.steps = Tr{"Run it in an emulator such as DOSBox (DOS games) or a virtual machine with an old Windows "
                     "version.",
                     "DOSBox gibi bir emülatörde (DOS oyunları için) ya da eski bir Windows sürümü kurulu sanal "
                     "makinede çalıştırın."}(lang_);
      fix.info_url = "https://www.dosbox.com/";
      f.fix = std::move(fix);
      findings_.push_back(std::move(f));
      return;
    }

    if (zip || rar || seven_zip) {
      f.rule = "archive-not-exe";
      f.title = Tr{"This is an archive, not a program", "Bu bir program değil, sıkıştırılmış arşiv"}(lang_);
      f.explanation = Tr{"The file is a ZIP/RAR/7z archive that has been renamed to .exe or is being opened the wrong "
                         "way.",
                         "Dosya .exe olarak adlandırılmış ya da yanlış açılmaya çalışılan bir ZIP/RAR/7z arşivi."}(lang_);
      Fix fix;
      fix.steps = Tr{"Extract the archive first (right click → Extract All, or use 7-Zip) and run the program inside.",
                     "Önce arşivi çıkarın (sağ tık → Tümünü Ayıkla ya da 7-Zip) ve içindeki programı "
                     "çalıştırın."}(lang_);
      f.fix = std::move(fix);
      findings_.push_back(std::move(f));
      return;
    }

    if (r.error == pe::ParseError::Empty || all_zero) {
      f.title = Tr{"The file is empty or was not downloaded completely",
                   "Dosya boş ya da tam inmemiş"}(lang_);
      f.explanation = Tr{"The file contains no program code. This usually happens when a download was interrupted or "
                         "a disk/sync tool did not finish writing it.",
                         "Dosyada program kodu yok. Bu genelde indirme yarıda kaldığında ya da bir disk/eşitleme aracı "
                         "dosyayı yazmayı bitirmediğinde olur."}(lang_);
    } else if (r.error == pe::ParseError::NotMz) {
      f.rule = "not-a-program";
      f.title = Tr{"This file is not a Windows program", "Bu dosya bir Windows programı değil"}(lang_);
      f.explanation = Tr{"The file does not start like a Windows executable. It may be a different kind of file with an "
                         ".exe name, or it is badly damaged.",
                         "Dosya bir Windows programı gibi başlamıyor. Adı .exe olan başka türde bir dosya olabilir ya "
                         "da ağır şekilde bozulmuştur."}(lang_);
    } else {
      f.title = Tr{"The program file is damaged", "Program dosyası bozuk"}(lang_);
      f.explanation = Tr{"The file's executable structure is invalid. It was probably downloaded incompletely or "
                         "damaged on disk.",
                         "Dosyanın program yapısı geçersiz. Büyük ihtimalle eksik indirilmiş ya da diskte "
                         "bozulmuş."}(lang_);
    }
    Fix fix;
    fix.steps = Tr{"Download the program again from its official source, or reinstall it.",
                   "Programı resmi kaynağından yeniden indirin ya da yeniden kurun."}(lang_);
    f.fix = std::move(fix);
    findings_.push_back(std::move(f));
  }

  // A DOS / Windows 3.x program is either a plain MZ executable (relocation table offset e_lfarlc below
  // 0x40, so there is no "new header" pointer at all) or an MZ stub followed by an NE header at e_lfanew.
  // A corrupt PE (valid-looking DOS header, e_lfarlc >= 0x40, e_lfanew pointing nowhere or at garbage)
  // is NOT 16-bit.
  bool is_16bit(const std::filesystem::path& program, const std::vector<std::uint8_t>& head) const {
    if (head.size() < 0x1A || head[0] != 'M' || head[1] != 'Z') return false;
    const std::uint32_t lfarlc = head[0x18] | (head[0x19] << 8);
    if (lfarlc < 0x40) return true;  // plain DOS program, whatever bytes 0x3C.. hold
    if (head.size() < 0x40) return false;
    const std::uint64_t lfanew = head[0x3C] | (head[0x3D] << 8) | (head[0x3E] << 16) |
                                 (static_cast<std::uint64_t>(head[0x3F]) << 24);
    constexpr std::uint64_t kMaxProbe = 16ull * 1024 * 1024;  // NE headers sit near the start of the file
    if (lfanew < 0x40 || lfanew + 2 > kMaxProbe) return false;
    std::vector<std::uint8_t> probe;
    const std::vector<std::uint8_t>* data = &head;
    if (lfanew + 2 > head.size()) {
      auto more = env_.read_file(program, lfanew + 2);  // the real file, not just the 4 KB head
      if (!more) return false;
      probe = std::move(*more);
      data = &probe;
    }
    if (lfanew + 2 > data->size()) return false;
    const auto at = static_cast<std::size_t>(lfanew);  // <= 16 MB, fits on x86
    return (*data)[at] == 'N' && (*data)[at + 1] == 'E';
  }

  void incomplete_file() {
    Finding f;
    f.rule = "incomplete-file";
    f.title = Tr{"The program file is incomplete", "Program dosyası eksik (yarım)"}(lang_);
    f.explanation = Tr{"Parts of the program are missing from the end of the file. This almost always means the "
                       "download was interrupted.",
                       "Programın bazı bölümleri dosyanın sonunda yok. Bu neredeyse her zaman indirmenin yarıda "
                       "kaldığı anlamına gelir."}(lang_);
    Fix fix;
    fix.steps = Tr{"Download the program again from its official source, or reinstall it.",
                   "Programı resmi kaynağından yeniden indirin ya da yeniden kurun."}(lang_);
    f.fix = std::move(fix);
    findings_.push_back(std::move(f));
  }

  // ---- Rule 5: platform mismatch. Returns false if nothing else is worth checking.

  bool platform(const pe::PeInfo& info, pe::Machine process) {
    const env::OsInfo os = env_.os();

    if (info.is_dll) {
      Finding f;
      f.rule = "not-a-program";
      f.title = Tr{"This is a DLL, not a program", "Bu bir program değil, DLL dosyası"}(lang_);
      f.explanation = Tr{"DLL files are libraries used by programs; they cannot be started by double-clicking. Start "
                         "the program's .exe instead. Its dependencies are still checked below.",
                         "DLL dosyaları programların kullandığı kütüphanelerdir; çift tıklanarak açılamazlar. Bunun "
                         "yerine programın .exe dosyasını çalıştırın. Bağımlılıkları yine de aşağıda kontrol "
                         "edildi."}(lang_);
      f.severity = Severity::Warning;
      findings_.push_back(std::move(f));
    }

    if (info.subsystem == 1 || (info.subsystem >= 10 && info.subsystem <= 13)) {
      Finding f;
      f.rule = "not-a-program";
      f.title = Tr{"This file is a driver or boot component, not a program",
                   "Bu dosya bir program değil, sürücü ya da önyükleme bileşeni"}(lang_);
      f.explanation = Tr{"It is meant to be loaded by Windows or the firmware, not started by a user.",
                         "Kullanıcı tarafından değil, Windows ya da donanım yazılımı tarafından yüklenmek için "
                         "yapılmış."}(lang_);
      f.evidence.push_back("subsystem=" + std::to_string(info.subsystem));
      findings_.push_back(std::move(f));
      return false;
    }

    std::string needed;
    bool runnable = true;
    switch (process) {
      case pe::Machine::I386: break;
      case pe::Machine::AMD64:
        // ARM64 Windows runs x64 programs only from Windows 11 (build 22000) on; Windows 10 on ARM emulates x86 only.
        runnable = os.is_64bit && (!os.is_arm64 || os.build >= 22000);
        needed = os.is_arm64 ? Tr{"64-bit (x64) Windows, or Windows 11 on ARM", "64-bit (x64) Windows ya da ARM işlemcili Windows 11"}(lang_)
                             : Tr{"64-bit (x64) Windows", "64-bit (x64) Windows"}(lang_);
        break;
      case pe::Machine::ARM64: runnable = os.is_arm64; needed = Tr{"Windows on ARM", "ARM işlemcili Windows"}(lang_); break;
      case pe::Machine::ARMNT: runnable = os.is_arm64 && os.build < 26100; needed = Tr{"Windows on ARM (32-bit ARM apps)", "ARM işlemcili Windows (32-bit ARM uygulamaları)"}(lang_); break;
      case pe::Machine::IA64: runnable = false; needed = Tr{"Itanium Windows (no longer exists)", "Itanium Windows (artık yok)"}(lang_); break;
      default: runnable = false; needed = Tr{"a different processor type", "farklı bir işlemci türü"}(lang_); break;
    }
    if (!runnable) {
      Finding f;
      f.rule = "platform-mismatch";
      f.title = format(Tr{"This program is built for {0}", "Bu program {0} için yapılmış"}(lang_), {needed});
      f.explanation = format(Tr{"The program is {0}, but this computer runs {1}. No file or runtime can fix this.",
                                "Program {0}, ama bu bilgisayarda {1} çalışıyor. Bunu hiçbir dosya ya da runtime "
                                "düzeltemez."}(lang_),
                             {arch_, os_string(os)});
      Fix fix;
      fix.steps = process == pe::Machine::AMD64
                      ? Tr{"Download the 32-bit (x86) version of the program if the developer offers one. Otherwise "
                           "it needs 64-bit Windows.",
                           "Geliştirici sunuyorsa programın 32-bit (x86) sürümünü indirin. Yoksa 64-bit Windows "
                           "gerekir."}(lang_)
                      : Tr{"Download the version of the program made for your processor (usually x64 or x86).",
                           "Programın işlemcinize uygun sürümünü indirin (genelde x64 ya da x86)."}(lang_);
      f.fix = std::move(fix);
      findings_.push_back(std::move(f));
      return false;
    }

    const std::pair<std::uint32_t, std::uint32_t> need{info.major_subsystem_version, info.minor_subsystem_version};
    const std::pair<std::uint32_t, std::uint32_t> have{os.major, os.minor};
    if (need > have && need.first <= 10) {
      Finding f;
      f.rule = "windows-too-old";
      f.title = Tr{"This program needs a newer version of Windows", "Bu program daha yeni bir Windows sürümü istiyor"}(lang_);
      f.explanation = format(Tr{"The program declares that it needs Windows version {0}.{1} or later; this computer "
                                "has {2}.{3}.",
                                "Program en az {0}.{1} Windows sürümü gerektirdiğini belirtiyor; bu bilgisayarda "
                                "{2}.{3} var."}(lang_),
                             {std::to_string(need.first), std::to_string(need.second), std::to_string(have.first),
                              std::to_string(have.second)});
      Fix fix;
      fix.steps = Tr{"Update Windows, or look for an older version of the program that supports your Windows.",
                     "Windows'u güncelleyin ya da programın sizin Windows sürümünüzü destekleyen eski bir sürümünü "
                     "bulun."}(lang_);
      f.fix = std::move(fix);
      findings_.push_back(std::move(f));
    }
    return true;
  }

  // ---- Rules 1-4: DLL problems ---------------------------------------------

  void dlls(const resolve::Result& res) {
    // Missing DLLs that map to the same package become one finding.
    struct Group {
      const kb::Package* package = nullptr;
      std::vector<const Module*> modules;
      bool delay_only = true;
    };
    std::map<std::string, Group> runtime_groups;
    std::vector<const Module*> unknown, debug_rt, program_files, gpu, api_sets;

    for (const Module& m : res.modules) {
      if (m.arch_mismatch) {
        wrong_arch(m, res);
        continue;
      }
      if (m.invalid_image) {
        corrupt_dll(m);
        continue;
      }
      if (!m.missing_functions.empty()) missing_exports(m, res);
      if (!is_missing(m)) continue;

      const kb::DllEntry* entry = kb_.find_dll(m.name);
      if (entry && entry->debug_only) {
        debug_rt.push_back(&m);
      } else if (entry && entry->program_file) {
        program_files.push_back(&m);
      } else if (entry && entry->gpu_driver) {
        gpu.push_back(&m);
      } else if (const kb::Package* pkg = entry ? kb_.find_package(entry->package) : nullptr) {
        Group& g = runtime_groups[pkg->id];
        g.package = pkg;
        g.modules.push_back(&m);
        g.delay_only = g.delay_only && m.delay_only;
      } else if (m.name.starts_with("api-ms-win-") || m.name.starts_with("ext-ms-win-")) {
        api_sets.push_back(&m);
      } else {
        unknown.push_back(&m);
      }
    }

    for (const auto& [id, g] : runtime_groups) missing_runtime(*g.package, g.modules, g.delay_only);
    if (!debug_rt.empty()) debug_runtime(debug_rt);
    if (!program_files.empty()) missing_program_files(program_files, true);
    if (!gpu.empty()) gpu_driver(gpu);
    if (!api_sets.empty()) missing_api_sets(api_sets);
    if (!unknown.empty()) missing_program_files(unknown, false);
  }

  static bool is_missing(const Module& m) {
    if (m.location == Location::ApiSet) return m.api_set_host.empty();
    return m.path.empty();
  }

  std::string chain(const Module& m) const {
    std::string s = m.name;
    if (!m.importers.empty()) s += "  <-  " + m.importers.front();
    if (m.delay_only) s += Tr{"  (delay-loaded)", "  (gecikmeli yüklenen)"}(lang_);
    return s;
  }

  Fix package_fix(const kb::Package& pkg) const { return detail::make_package_fix(pkg, arch_, env_, lang_); }

  void missing_runtime(const kb::Package& pkg, const std::vector<const Module*>& modules, bool delay_only) {
    Finding f;
    f.rule = "missing-runtime";
    f.severity = delay_only ? Severity::Warning : Severity::Error;
    f.title = format(Tr{"Missing: {0} ({1})", "Eksik: {0} ({1})"}(lang_), {pkg.name, arch_});
    f.explanation = delay_only
                        ? Tr{"The program can start, but some features will fail because these files belong to a "
                             "runtime package that is not installed.",
                             "Program açılabilir ama bazı özellikleri çalışmaz, çünkü bu dosyalar kurulu olmayan bir "
                             "runtime paketine ait."}(lang_)
                        : Tr{"The program needs files from this runtime package, and it is not installed for the "
                             "program's architecture. Windows refuses to start the program without it.",
                             "Program bu runtime paketindeki dosyalara ihtiyaç duyuyor ve paket, programın mimarisi "
                             "için kurulu değil. Windows bu paket olmadan programı başlatmaz."}(lang_);
    for (const Module* m : modules) f.evidence.push_back(chain(*m));
    f.fix = package_fix(pkg);
    f.fix->steps += Tr{" Never download single DLL files from \"DLL download\" websites.",
                       " Tek tek DLL dosyalarını asla \"DLL indirme\" sitelerinden indirmeyin."}(lang_);
    findings_.push_back(std::move(f));
  }

  void debug_runtime(const std::vector<const Module*>& modules) {
    Finding f;
    f.rule = "debug-runtime";
    f.title = Tr{"The developer shipped a Debug build by mistake", "Geliştirici yanlışlıkla Debug derlemeyi yayımlamış"}(lang_);
    f.explanation = Tr{"The program needs debug versions of the Visual C++ runtime. These only exist on developers' "
                       "computers; there is no official installer for them and they may not be redistributed.",
                       "Program Visual C++ runtime'ının debug sürümlerini istiyor. Bunlar sadece geliştirici "
                       "bilgisayarlarında bulunur; resmi bir kurulum paketi yoktur ve dağıtılmaları yasaktır."}(lang_);
    for (const Module* m : modules) f.evidence.push_back(chain(*m));
    Fix fix;
    fix.steps = Tr{"Report this to the program's developer and ask for a Release build. Do NOT download these DLLs "
                   "from the internet.",
                   "Bunu programın geliştiricisine bildirin ve Release derleme isteyin. Bu DLL'leri asla internetten "
                   "indirmeyin."}(lang_);
    f.fix = std::move(fix);
    findings_.push_back(std::move(f));
  }

  void missing_program_files(const std::vector<const Module*>& modules, bool known_program_file) {
    Finding f;
    f.rule = "missing-program-file";
    const bool all_delay = std::all_of(modules.begin(), modules.end(), [](const Module* m) { return m->delay_only; });
    f.severity = all_delay ? Severity::Warning : Severity::Error;
    f.certain = known_program_file;
    f.title = known_program_file
                  ? Tr{"Some of the program's own files are missing", "Programın kendi dosyalarından bazıları eksik"}(lang_)
                  : Tr{"Files the program needs are missing", "Programın ihtiyaç duyduğu dosyalar eksik"}(lang_);
    f.explanation = known_program_file
                        ? Tr{"These files are shipped with the program itself, not with Windows or a runtime "
                             "package. They may have been deleted or quarantined by an antivirus.",
                             "Bu dosyalar Windows ya da bir runtime paketiyle değil, programın kendisiyle gelir. "
                             "Silinmiş ya da bir antivirüs tarafından karantinaya alınmış olabilirler."}(lang_)
                        : Tr{"These files are not part of Windows and are not in the tool's list of known runtime "
                             "packages, so they most likely belong to the program itself. The tool is not certain.",
                             "Bu dosyalar Windows'un parçası değil ve aracın bildiği runtime paketleri listesinde de "
                             "yok; büyük ihtimalle programın kendisine ait. Araç bundan emin değil."}(lang_);
    if (all_delay) {
      f.explanation += Tr{" They are loaded on demand, so the program may start but some features will fail.",
                          " Bunlar ihtiyaç anında yüklenir; program açılabilir ama bazı özellikler çalışmaz."}(lang_);
    }
    for (const Module* m : modules) f.evidence.push_back(chain(*m));
    Fix fix;
    fix.steps = Tr{"Reinstall the program. For games, use \"Verify integrity of game files\" (Steam) or \"Verify\" / "
                   "\"Repair\" in your launcher. Check your antivirus quarantine too.",
                   "Programı yeniden kurun. Oyunlarda \"Oyun dosyalarının bütünlüğünü doğrula\" (Steam) ya da "
                   "başlatıcıdaki \"Doğrula\" / \"Onar\" seçeneğini kullanın. Antivirüsünüzün karantinasına da "
                   "bakın."}(lang_);
    f.fix = std::move(fix);
    findings_.push_back(std::move(f));
  }

  void gpu_driver(const std::vector<const Module*>& modules) {
    Finding f;
    f.rule = "gpu-driver";
    f.title = Tr{"Graphics driver components are missing", "Ekran kartı sürücüsü bileşenleri eksik"}(lang_);
    f.explanation = Tr{"These files are installed by the graphics card driver (NVIDIA, AMD or Intel), not by a "
                       "separate package.",
                       "Bu dosyaları ayrı bir paket değil, ekran kartı sürücüsü (NVIDIA, AMD ya da Intel) "
                       "kurar."}(lang_);
    for (const Module* m : modules) f.evidence.push_back(chain(*m));
    Fix fix;
    fix.steps = Tr{"Install the latest driver from your graphics card vendor's official website. If your computer "
                   "has no supported graphics card, the program cannot run on it.",
                   "Ekran kartı üreticinizin resmi sitesinden en güncel sürücüyü kurun. Bilgisayarınızda desteklenen "
                   "bir ekran kartı yoksa program bu bilgisayarda çalışamaz."}(lang_);
    f.fix = std::move(fix);
    findings_.push_back(std::move(f));
  }

  void missing_api_sets(const std::vector<const Module*>& modules) {
    Finding f;
    f.rule = "windows-too-old";
    const bool all_delay = std::all_of(modules.begin(), modules.end(), [](const Module* m) { return m->delay_only; });
    f.severity = all_delay ? Severity::Warning : Severity::Error;
    f.title = Tr{"This program uses Windows features this computer doesn't have",
                 "Bu program bu bilgisayarda olmayan Windows özelliklerini kullanıyor"}(lang_);
    f.explanation = Tr{"Names starting with api-ms-win- are parts of Windows itself, not downloadable files. If they "
                       "are missing, the program was built for a newer Windows version.",
                       "api-ms-win- ile başlayan adlar indirilebilir dosyalar değil, Windows'un kendi parçalarıdır. "
                       "Eksiklerse program daha yeni bir Windows sürümü için yapılmıştır."}(lang_);
    for (const Module* m : modules) f.evidence.push_back(chain(*m));
    Fix fix;
    fix.steps = Tr{"Install all Windows updates. If the problem remains, the program needs a newer Windows version. "
                   "Never download api-ms-win-*.dll files from websites.",
                   "Tüm Windows güncellemelerini yükleyin. Sorun sürerse program daha yeni bir Windows sürümü "
                   "istiyor demektir. api-ms-win-*.dll dosyalarını asla sitelerden indirmeyin."}(lang_);
    f.fix = std::move(fix);
    findings_.push_back(std::move(f));
  }

  // Rule 2: the first DLL found has the wrong architecture (0xc000007b).
  void wrong_arch(const Module& m, const resolve::Result& res) {
    Finding f;
    f.rule = "wrong-arch";
    f.severity = m.delay_only ? Severity::Warning : Severity::Error;
    const std::string dll_arch = arch_of(m.machine);
    f.title = format(Tr{"{0} is the wrong type ({1} instead of {2}) — error 0xc000007b",
                        "{0} yanlış türde ({2} yerine {1}) — 0xc000007b hatası"}(lang_),
                     {m.name, dll_arch, arch_});
    f.evidence.push_back(format(Tr{"used: {0} ({1})", "kullanılan: {0} ({1})"}(lang_), {u8(m.path), dll_arch}));
    for (std::size_t i = 1; i < m.candidates.size(); ++i) {
      const auto& c = m.candidates[i];
      f.evidence.push_back(format(Tr{"also found: {0} ({1})", "ayrıca bulundu: {0} ({1})"}(lang_),
                                  {u8(c.path), arch_of(c.machine)}));
    }
    if (!m.importers.empty()) f.evidence.push_back(chain(m));

    const kb::DllEntry* entry = kb_.find_dll(m.name);
    const kb::Package* pkg = entry ? kb_.find_package(entry->package) : nullptr;
    const std::string where = u8(m.path);
    switch (m.location) {
      case Location::AppDir:
        f.explanation = format(Tr{"Windows looks in the program's folder first and finds a {0} copy of {1} there, but "
                                  "the program is {2}. Mixing them is impossible.",
                                  "Windows önce programın klasörüne bakıyor ve orada {1} dosyasının {0} bir "
                                  "kopyasını buluyor, ama program {2}. İkisi bir arada çalışamaz."}(lang_),
                               {dll_arch, m.name, arch_});
        break;
      case Location::PathDir:
        f.explanation = format(Tr{"A folder listed in the PATH environment variable contains a {0} copy of {1}, and "
                                  "Windows finds it before the correct one. Such stray copies usually come from DLL "
                                  "download websites or another program's installer.",
                                  "PATH ortam değişkenindeki bir klasörde {1} dosyasının {0} bir kopyası var ve Windows "
                                  "doğru dosyadan önce onu buluyor. Bu tür başıboş kopyalar genelde DLL indirme "
                                  "sitelerinden ya da başka bir programın kurulumundan gelir."}(lang_),
                               {dll_arch, m.name});
        break;
      default:
        f.explanation = format(Tr{"The copy of {0} in a Windows folder is {1}, but this {2} program needs a {2} one. "
                                  "This typically happens after copying a DLL downloaded from a website into "
                                  "System32 or SysWOW64.",
                                  "Windows klasöründeki {0} kopyası {1}, ama bu {2} program {2} bir kopya istiyor. Bu "
                                  "genelde bir siteden indirilmiş DLL System32 ya da SysWOW64 içine kopyalandıktan "
                                  "sonra olur."}(lang_),
                               {m.name, dll_arch, arch_});
        break;
    }

    Fix fix = pkg ? package_fix(*pkg) : Fix{};
    std::string steps;
    if (m.location == Location::AppDir) {
      steps = Tr{"Reinstall the program (or download the correct 32/64-bit edition). If you put this DLL into the "
                 "program folder yourself, delete it: ",
                 "Programı yeniden kurun (ya da doğru 32/64-bit sürümünü indirin). Bu DLL'i program klasörüne siz "
                 "koyduysanız silin: "}(lang_) +
              where;
    } else {
      steps = Tr{"Delete (or rename) the wrong copy: ", "Yanlış kopyayı silin (ya da adını değiştirin): "}(lang_) + where;
    }
    if (pkg) steps += ". " + fix.steps;
    fix.steps = steps;
    f.fix = std::move(fix);
    (void)res;
    findings_.push_back(std::move(f));
  }

  void corrupt_dll(const Module& m) {
    Finding f;
    f.rule = "corrupt-dll";
    f.severity = m.delay_only ? Severity::Warning : Severity::Error;
    f.title = format(Tr{"{0} is damaged", "{0} bozuk"}(lang_), {m.name});
    f.explanation = Tr{"The file exists but is not a valid DLL (damaged, empty or incompletely downloaded).",
                       "Dosya var ama geçerli bir DLL değil (bozuk, boş ya da eksik inmiş)."}(lang_);
    f.evidence.push_back(u8(m.path) + " (" + m.invalid_reason + ")");
    const kb::DllEntry* entry = kb_.find_dll(m.name);
    const kb::Package* pkg = entry ? kb_.find_package(entry->package) : nullptr;
    Fix fix = pkg ? package_fix(*pkg) : Fix{};
    if (pkg) {
      fix.steps = Tr{"Delete the damaged file, then reinstall: ", "Bozuk dosyayı silin, sonra yeniden kurun: "}(lang_) +
                  fix.steps;
    } else if (m.system_owned) {
      fix.steps = Tr{"Run \"sfc /scannow\" in an administrator command prompt to repair Windows files.",
                     "Windows dosyalarını onarmak için yönetici olarak açılmış komut isteminde \"sfc /scannow\" "
                     "çalıştırın."}(lang_);
      fix.command = "sfc /scannow";
    } else {
      fix.steps = Tr{"Reinstall the program.", "Programı yeniden kurun."}(lang_);
    }
    f.fix = std::move(fix);
    findings_.push_back(std::move(f));
  }

  // Rule 3: "The procedure entry point ... could not be located".
  void missing_exports(const Module& m, const resolve::Result& res) {
    Finding f;
    f.rule = "missing-export";
    f.severity = m.delay_only ? Severity::Warning : Severity::Error;
    f.title = format(Tr{"{0} is too old for this program (entry point not found)",
                        "{0} bu program için çok eski (giriş noktası bulunamadı)"}(lang_),
                     {m.name});
    std::size_t shown = 0;
    for (const auto& mf : m.missing_functions) {
      if (shown++ == 5) {
        f.evidence.push_back("... +" + std::to_string(m.missing_functions.size() - 5 + m.missing_functions_omitted));
        break;
      }
      f.evidence.push_back(format(Tr{"{0} not found in {1} (needed by {2})", "{0}, {1} içinde yok ({2} istiyor)"}(lang_),
                                  {mf.function, m.name, mf.importer}));
    }
    f.evidence.push_back(format(Tr{"used: {0}", "kullanılan: {0}"}(lang_), {u8(m.path)}));

    const kb::DllEntry* entry = kb_.find_dll(m.name);
    const kb::Package* pkg = entry ? kb_.find_package(entry->package) : nullptr;

    if (m.location == Location::AppDir || m.location == Location::PathDir) {
      const resolve::Candidate* system_copy = nullptr;
      for (const auto& c : m.candidates) {
        if (c.location == Location::SystemDir && c.machine == m.machine) system_copy = &c;
      }
      const bool system_has_all = system_copy && exports_all(system_copy->path, m.missing_functions);
      if (system_has_all) {
        f.explanation = format(Tr{"An old copy of {0} next to the program (or in a PATH folder) is used instead of "
                                  "the newer one in Windows, and it lacks functions the program needs.",
                                  "Windows'taki güncel {0} yerine programın yanındaki (ya da PATH'teki bir "
                                  "klasördeki) eski bir kopya kullanılıyor ve programın istediği fonksiyonlar onda "
                                  "yok."}(lang_),
                               {m.name});
        f.evidence.push_back(format(Tr{"newer copy: {0}", "güncel kopya: {0}"}(lang_), {u8(system_copy->path)}));
        Fix fix;
        fix.steps = format(Tr{"Rename the old copy (e.g. to {0}.old) so Windows uses the system one: {1}",
                              "Windows'un sistemdeki kopyayı kullanması için eski kopyanın adını değiştirin (örneğin "
                              "{0}.old): {1}"}(lang_),
                           {m.name, u8(m.path)});
        f.fix = std::move(fix);
      } else if (pkg) {
        f.explanation = format(Tr{"The copy of {0} that Windows uses is older than what the program was built with.",
                                  "Windows'un kullandığı {0} kopyası, programın derlendiği sürümden daha eski."}(lang_),
                               {m.name});
        Fix fix = package_fix(*pkg);
        fix.steps = Tr{"Install the latest version: ", "En güncel sürümü kurun: "}(lang_) + fix.steps +
                    format(Tr{" If the error remains, rename the old copy: {0}",
                              " Hata sürerse eski kopyanın adını değiştirin: {0}"}(lang_),
                           {u8(m.path)});
        f.fix = std::move(fix);
      } else {
        f.certain = false;
        f.explanation = format(Tr{"The program's files don't match each other: {0} is a different version than the "
                                  "program expects. This often happens after a partial update or after copying files "
                                  "from another version.",
                                  "Programın dosyaları birbiriyle uyuşmuyor: {0}, programın beklediğinden farklı bir "
                                  "sürüm. Bu genelde yarım kalmış bir güncellemeden ya da başka bir sürümden dosya "
                                  "kopyalandıktan sonra olur."}(lang_),
                               {m.name});
        Fix fix;
        fix.steps = Tr{"Reinstall the program (or verify game files in your launcher).",
                       "Programı yeniden kurun (ya da başlatıcıdan oyun dosyalarını doğrulayın)."}(lang_);
        f.fix = std::move(fix);
      }
    } else if (pkg) {
      f.explanation = format(Tr{"The installed {0} is older than the version the program was built with.",
                                "Kurulu {0}, programın derlendiği sürümden daha eski."}(lang_),
                             {pkg->name});
      Fix fix = package_fix(*pkg);
      fix.steps = Tr{"Install the latest version: ", "En güncel sürümü kurun: "}(lang_) + fix.steps;
      f.fix = std::move(fix);
    } else {
      f.rule = "windows-too-old";
      f.title = Tr{"This program needs a newer version of Windows",
                   "Bu program daha yeni bir Windows sürümü istiyor"}(lang_);
      f.explanation = format(Tr{"{0} is part of Windows, and this Windows version doesn't have the functions the "
                                "program uses.",
                                "{0} Windows'un bir parçası ve bu Windows sürümünde programın kullandığı fonksiyonlar "
                                "yok."}(lang_),
                             {m.name});
      Fix fix;
      fix.steps = Tr{"Install all Windows updates. If the problem remains, the program requires a newer Windows "
                     "version (or an older program version that supports yours).",
                     "Tüm Windows güncellemelerini yükleyin. Sorun sürerse program daha yeni bir Windows sürümü (ya "
                     "da programın sizin sürümünüzü destekleyen eski bir sürümünü) gerektiriyordur."}(lang_);
      f.fix = std::move(fix);
    }
    (void)res;
    findings_.push_back(std::move(f));
  }

  bool exports_all(const std::filesystem::path& dll, const std::vector<resolve::MissingFunction>& functions) const {
    const auto bytes = env_.read_file(dll, 512ull * 1024 * 1024);
    if (!bytes) return false;
    const pe::ParseResult r = pe::parse(*bytes);
    if (!r.ok()) return false;
    std::set<std::string> names;
    std::set<std::uint32_t> ordinals;
    for (const auto& e : r.info->exports) {
      names.insert(e.name);
      ordinals.insert(e.ordinal);
    }
    return std::all_of(functions.begin(), functions.end(), [&](const resolve::MissingFunction& f) {
      if (f.by_ordinal) return ordinals.count(f.ordinal) > 0;
      return names.count(f.function) > 0;
    });
  }

  // ---- Rule 7: .NET Framework 3.5 ---------------------------------------------

  void netfx35(const std::filesystem::path& program, const pe::PeInfo& info) {
    if (!info.clr) return;
    const std::string& v = info.clr->metadata_version;
    if (!(v.starts_with("v2.") || v.starts_with("v1."))) return;
    if (env_.netfx35_installed()) return;

    // <supportedRuntime version="v4.0"/> in program.exe.config lets CLR 4 run it.
    std::filesystem::path config = program;
    config += ".config";
    if (auto bytes = env_.read_file(config, 1024 * 1024)) {
      const std::string text = to_lower_ascii(std::string(bytes->begin(), bytes->end()));
      std::size_t pos = 0;
      while ((pos = text.find("supportedruntime", pos)) != std::string::npos) {
        const std::size_t end = text.find('>', pos);
        const std::string tag = text.substr(pos, end == std::string::npos ? std::string::npos : end - pos);
        if (tag.find("\"v4") != std::string::npos || tag.find("'v4") != std::string::npos) {
          if (env_.netfx4_installed()) return;
        }
        pos += 16;
      }
    }

    Finding f;
    f.rule = "netfx35";
    f.title = Tr{"Missing: .NET Framework 3.5", "Eksik: .NET Framework 3.5"}(lang_);
    f.explanation = Tr{"This program was built for .NET Framework 2.0–3.5, which is not enabled on this computer. "
                       "Newer .NET versions cannot run it.",
                       "Bu program .NET Framework 2.0–3.5 için yapılmış ve bu sürüm bu bilgisayarda açık değil. Yeni "
                       ".NET sürümleri onu çalıştıramaz."}(lang_);
    f.evidence.push_back("CLR metadata " + v);
    Fix fix;
    if (const kb::Package* pkg = kb_.find_package("netfx35")) fix = package_fix(*pkg);
    fix.steps = Tr{"Open \"Turn Windows features on or off\" (optionalfeatures.exe), tick \".NET Framework 3.5 "
                   "(includes .NET 2.0 and 3.0)\" and press OK. Windows downloads it from Windows Update.",
                   "\"Windows özelliklerini aç veya kapat\" penceresini açın (optionalfeatures.exe), \".NET Framework "
                   "3.5 (.NET 2.0 ve 3.0 içerir)\" kutusunu işaretleyip Tamam'a basın. Windows bunu Windows "
                   "Update'ten indirir."}(lang_);
    fix.command = "DISM /Online /Enable-Feature /FeatureName:NetFx3 /All";
    f.fix = std::move(fix);
    findings_.push_back(std::move(f));
  }

  // ---- Rule 10: .NET 5 and later (program.runtimeconfig.json) -------------------

  struct DotnetVersion {
    std::vector<std::uint64_t> parts;  // at least 3 numbers
    bool prerelease = false;           // "8.0.0-rc.1"
  };

  static DotnetVersion version_parts(std::string_view v) {
    DotnetVersion out;
    std::uint64_t cur = 0;
    bool any = false;
    for (const char c : v) {
      if (c >= '0' && c <= '9') {
        if (cur < 1000000000ull) cur = cur * 10 + static_cast<std::uint64_t>(c - '0');  // saturates, no overflow
        any = true;
      } else if (c == '.') {
        out.parts.push_back(cur);
        cur = 0;
        any = false;
      } else {
        out.prerelease = c == '-';  // "-rc.1" / "-preview.3"; the suffix itself is not compared
        break;
      }
    }
    if (any) out.parts.push_back(cur);
    while (out.parts.size() < 3) out.parts.push_back(0);
    return out;
  }

  // Release > prerelease of the same numbers.
  static bool version_less(const DotnetVersion& a, const DotnetVersion& b) {
    if (a.parts != b.parts) return a.parts < b.parts;
    return a.prerelease && !b.prerelease;
  }

  void dotnet(const std::filesystem::path& program) {
    std::filesystem::path config = program;
    config.replace_extension(".runtimeconfig.json");
    const auto bytes = env_.read_file(config, 1024 * 1024);
    if (!bytes) return;
    const auto doc = json::parse(std::string_view(reinterpret_cast<const char*>(bytes->data()), bytes->size()));
    if (!doc) return;
    const json::Value* options = doc->find("runtimeOptions");
    if (!options) return;

    std::vector<const json::Value*> frameworks;
    if (const json::Value* fw = options->find("framework")) frameworks.push_back(fw);
    if (const json::Value* fws = options->find("frameworks")) {
      for (const json::Value& fw : fws->as_array()) frameworks.push_back(&fw);
    }
    std::string roll = "Minor";
    if (const json::Value* r = options->find("rollForward")) roll = r->as_string();
    const bool any_major = roll == "Major" || roll == "LatestMajor";
    const bool disable = roll == "Disable";            // exactly the requested version
    const bool same_minor = roll == "LatestPatch";     // same major.minor, newest patch

    const auto installed = env_.dotnet_frameworks();
    for (const json::Value* fw : frameworks) {
      const json::Value* name_v = fw->find("name");
      const json::Value* version_v = fw->find("version");
      if (!name_v || !version_v) continue;
      const std::string& name = name_v->as_string();
      const std::string& version = version_v->as_string();
      const DotnetVersion want = version_parts(version);

      bool ok = false;
      for (const auto& inst : installed) {
        if (inst.name != name || inst.arch != arch_) continue;
        const DotnetVersion have = version_parts(inst.version);
        if (version_less(have, want)) continue;
        if (disable && have.parts != want.parts) continue;
        if (same_minor && (have.parts[0] != want.parts[0] || have.parts[1] != want.parts[1])) continue;
        if (!any_major && have.parts[0] != want.parts[0]) continue;
        ok = true;
        break;
      }
      if (ok) continue;

      Finding f;
      f.rule = "dotnet-runtime";
      const std::string major = std::to_string(want.parts[0]);
      const bool desktop = name == "Microsoft.WindowsDesktop.App" || name == "Microsoft.NETCore.App";
      f.title = format(Tr{"Missing: .NET {0} {1} ({2})", "Eksik: .NET {0} {1} ({2})"}(lang_),
                       {major, desktop ? "Desktop Runtime" : name, arch_});
      f.explanation = format(Tr{"The program is built on .NET {0} and needs {1} version {2} or a newer {0}.x for "
                                "{3}, which is not installed. Other .NET versions on this computer don't count.",
                                "Program .NET {0} ile yapılmış ve {3} için {1} {2} ya da daha yeni bir {0}.x sürümüne "
                                "ihtiyaç duyuyor; bu sürüm kurulu değil. Bilgisayardaki başka .NET sürümleri yerine "
                                "geçmez."}(lang_),
                             {major, name, version, arch_});
      f.evidence.push_back(u8(config.filename()) + ": " + name + " " + version + " (rollForward " + roll + ")");
      Fix fix;
      if (const kb::Package* pkg = kb_.find_package("dotnet-desktop-" + major); pkg && desktop) {
        fix = package_fix(*pkg);
      } else {
        fix.arch = arch_;
        fix.info_url = "https://dotnet.microsoft.com/download/dotnet/" + major + ".0";
        fix.steps = format(Tr{"Install the {0} runtime for .NET {1} ({2}) from the official .NET download page.",
                              ".NET {1} için {0} runtime'ını ({2}) resmi .NET indirme sayfasından kurun."}(lang_),
                           {name, major, arch_});
      }
      f.fix = std::move(fix);
      findings_.push_back(std::move(f));
    }
  }

  // ---- Rule 12: packed / protected executables ---------------------------------

  void packed(const pe::PeInfo& info) {
    if (info.clr) return;
    std::size_t functions = 0;
    for (const auto& imp : info.imports) functions += imp.functions.size();
    double max_entropy = 0;
    for (const auto& s : info.sections) {
      if (s.raw_size >= 4096) max_entropy = std::max(max_entropy, s.entropy);
    }
    if (max_entropy < 7.2 || functions > 20) return;
    Finding f;
    f.rule = "analysis-limited";
    f.severity = Severity::Info;
    f.certain = false;
    f.title = Tr{"Analysis is limited for this file", "Bu dosyada analiz sınırlı"}(lang_);
    f.explanation = Tr{"The program is compressed or protected (packed), so most of what it loads is hidden until it "
                       "runs. The tool will not guess; problems may exist that it cannot see.",
                       "Program sıkıştırılmış ya da korunmuş (paketlenmiş); yüklediği şeylerin çoğu çalışana kadar "
                       "gizli. Araç tahmin yürütmez; göremediği sorunlar olabilir."}(lang_);
    char buf[64];
    std::snprintf(buf, sizeof(buf), "entropy %.2f, %zu imported functions", max_entropy, functions);
    f.evidence.push_back(buf);
    findings_.push_back(std::move(f));
  }

  void nothing_found() {
    Finding f;
    f.rule = "no-problem-found";
    f.severity = Severity::Info;
    f.title = Tr{"No missing or incompatible components found", "Eksik ya da uyumsuz bileşen bulunamadı"}(lang_);
    f.explanation = Tr{"Every DLL the program needs at startup was found with the right architecture and version. "
                       "If it still won't open, the cause is something this tool doesn't check yet: an antivirus "
                       "blocking it, a crash inside the program, missing game data or a broken configuration.",
                       "Programın açılışta ihtiyaç duyduğu tüm DLL'ler doğru mimari ve sürümde bulundu. Program hâlâ "
                       "açılmıyorsa sebep bu aracın henüz kontrol etmediği bir şeydir: programı engelleyen bir "
                       "antivirüs, programın içinde bir çökme, eksik oyun verileri ya da bozuk bir ayar."}(lang_);
    Fix fix;
    fix.steps = Tr{"Check Windows Security → Protection history, and Event Viewer → Windows Logs → Application for "
                   "an \"Application Error\" entry about the program.",
                   "Windows Güvenliği → Koruma geçmişi'ne ve Olay Görüntüleyicisi → Windows Günlükleri → Uygulama "
                   "altında programla ilgili \"Application Error\" kaydına bakın."}(lang_);
    f.fix = std::move(fix);
    findings_.push_back(std::move(f));
  }

  const env::Environment& env_;
  const kb::KnowledgeBase& kb_;
  Lang lang_;
  std::string arch_ = "unknown";
  std::string program_name_;
  std::vector<Finding> findings_;
};

// ---- Output ------------------------------------------------------------------

std::string json_escape(std::string_view s) {
  std::string out;
  out.reserve(s.size() + 2);
  out += '"';
  for (const char ch : s) {
    const auto c = static_cast<unsigned char>(ch);
    switch (c) {
      case '"': out += "\\\""; break;
      case '\\': out += "\\\\"; break;
      case '\n': out += "\\n"; break;
      case '\r': out += "\\r"; break;
      case '\t': out += "\\t"; break;
      default:
        if (c < 0x20) {
          char buf[8];
          std::snprintf(buf, sizeof(buf), "\\u%04x", c);
          out += buf;
        } else {
          out += ch;
        }
    }
  }
  out += '"';
  return out;
}

// Hides the user name in paths before a report is shared publicly.
std::string anonymize(std::string s) {
  wchar_t buf[MAX_PATH];
  const DWORD n = GetEnvironmentVariableW(L"USERPROFILE", buf, MAX_PATH);
  if (n == 0 || n >= MAX_PATH) return s;
  const std::string profile = util::wide_to_utf8(buf);
  const std::string lower_profile = to_lower_ascii(profile);
  for (std::size_t pos = to_lower_ascii(s).find(lower_profile); pos != std::string::npos;
       pos = to_lower_ascii(s).find(lower_profile, pos + 13)) {
    s.replace(pos, profile.size(), "%USERPROFILE%");
  }
  return s;
}

}  // namespace

const char* severity_name(Severity s) {
  switch (s) {
    case Severity::Error: return "error";
    case Severity::Warning: return "warning";
    case Severity::Info: return "info";
  }
  return "info";
}

Lang default_lang() { return PRIMARYLANGID(GetUserDefaultUILanguage()) == LANG_TURKISH ? Lang::Tr : Lang::En; }

bool Report::has_errors() const {
  return std::any_of(findings.begin(), findings.end(), [](const Finding& f) { return f.severity == Severity::Error; });
}

namespace {

// std::bad_alloc or any other failure while analysing: report "could not analyse" instead of terminating.
Report failed_report(const std::filesystem::path& program, const env::Environment& env, Lang lang,
                     const char* what) noexcept {
  Report report;
  try {
    report.program = program;
    report.lang = lang;
    report.os = os_string(env.os());
    report.resolution.target_path = program;
    report.resolution.target.error = pe::ParseError::IoError;
    report.resolution.target.detail = std::string("could not analyse the file: ") + what;
    Finding f;
    f.rule = "analysis-failed";
    f.severity = Severity::Warning;
    f.certain = false;
    f.title = Tr{"The file could not be analysed", "Dosya analiz edilemedi"}(lang);
    f.explanation = Tr{"An unexpected error (for example, not enough memory for a very large or unusual file) stopped "
                       "the analysis. No conclusion can be drawn.",
                       "Beklenmeyen bir hata (örneğin çok büyük ya da olağandışı bir dosya için yetersiz bellek) "
                       "analizi durdurdu. Bir sonuca varılamıyor."}(lang);
    f.evidence.push_back(what);
    report.findings.push_back(std::move(f));
  } catch (...) {
  }
  return report;
}

}  // namespace

Report diagnose(const std::filesystem::path& program, const env::Environment& env, const kb::KnowledgeBase& kb,
                Lang lang) {
  try {
    return Diagnoser(env, kb, lang).run(program);
  } catch (const std::exception& e) {
    return failed_report(program, env, lang, e.what());
  } catch (...) {
    return failed_report(program, env, lang, "unexpected error");
  }
}

std::string to_json(const Report& r) {
  std::string o = "{\n";
  o += "  \"tool\": " + json_escape("neden " + std::string(version())) + ",\n";
  o += "  \"program\": " + json_escape(u8(r.program)) + ",\n";
  o += "  \"arch\": " + json_escape(r.program_arch) + ",\n";
  o += "  \"os\": " + json_escape(r.os) + ",\n";
  o += "  \"findings\": [";
  for (std::size_t i = 0; i < r.findings.size(); ++i) {
    const Finding& f = r.findings[i];
    o += i ? ",\n" : "\n";
    o += "    {\n";
    o += "      \"rule\": " + json_escape(f.rule) + ",\n";
    o += "      \"severity\": " + json_escape(severity_name(f.severity)) + ",\n";
    o += std::string("      \"certain\": ") + (f.certain ? "true" : "false") + ",\n";
    o += "      \"title\": " + json_escape(f.title) + ",\n";
    o += "      \"explanation\": " + json_escape(f.explanation) + ",\n";
    o += "      \"evidence\": [";
    for (std::size_t e = 0; e < f.evidence.size(); ++e) o += (e ? ", " : "") + json_escape(f.evidence[e]);
    o += "]";
    if (f.fix) {
      const Fix& x = *f.fix;
      o += ",\n      \"fix\": {";
      bool first = true;
      auto field = [&](const char* k, const std::string& v) {
        if (v.empty()) return;
        o += first ? "\n" : ",\n";
        first = false;
        o += std::string("        \"") + k + "\": " + json_escape(v);
      };
      field("package", x.package_id);
      field("packageName", x.package_name);
      field("arch", x.arch);
      field("winget", x.winget_id);
      field("url", x.url);
      field("infoUrl", x.info_url);
      field("command", x.command);
      field("steps", x.steps);
      o += "\n      }";
    }
    o += "\n    }";
  }
  o += r.findings.empty() ? "],\n" : "\n  ],\n";
  o += "  \"modules\": [";
  const auto& mods = r.resolution.modules;
  for (std::size_t i = 0; i < mods.size(); ++i) {
    const Module& m = mods[i];
    o += i ? ",\n" : "\n";
    o += "    {\"name\": " + json_escape(m.name) + ", \"location\": " + json_escape(resolve::location_name(m.location)) +
         ", \"path\": " + json_escape(u8(m.path)) + ", \"machine\": " + json_escape(pe::machine_name(m.machine)) +
         ", \"depth\": " + std::to_string(m.depth) + (m.delay_only ? ", \"delay\": true" : "") +
         (m.api_set_host.empty() ? "" : ", \"apiSetHost\": " + json_escape(m.api_set_host)) + "}";
  }
  o += mods.empty() ? "]\n" : "\n  ]\n";
  o += "}\n";
  return o;
}

std::string to_text(const Report& r) {
  const Lang lang = r.lang;
  std::string o;
  o += Tr{"### Why Won't It Open? — report\n\n", "### Neden Açılmıyor? — rapor\n\n"}(lang);
  o += Tr{"**Program:** ", "**Program:** "}(lang) + u8(r.program.filename());
  if (!r.program_arch.empty()) o += " (" + r.program_arch + ")";
  o += "  \n**Windows:** " + r.os + "\n\n";
  int n = 0;
  for (const Finding& f : r.findings) {
    const char* tag = f.severity == Severity::Error     ? (lang == Lang::Tr ? "[HATA]" : "[ERROR]")
                      : f.severity == Severity::Warning ? (lang == Lang::Tr ? "[UYARI]" : "[WARNING]")
                                                         : (lang == Lang::Tr ? "[BİLGİ]" : "[INFO]");
    o += std::to_string(++n) + ". " + tag + " **" + f.title + "**";
    if (!f.certain) o += Tr{" _(not certain)_", " _(kesin değil)_"}(lang);
    o += "\n   " + f.explanation + "\n";
    for (const std::string& e : f.evidence) o += "   - `" + anonymize(e) + "`\n";
    if (f.fix) {
      o += Tr{"   **Fix:** ", "   **Çözüm:** "}(lang) + anonymize(f.fix->steps) + "\n";
      if (!f.fix->winget_id.empty()) o += "   `winget install --id " + f.fix->winget_id + " -e`\n";
      if (!f.fix->command.empty()) o += "   `" + f.fix->command + "`\n";
      if (!f.fix->url.empty()) o += Tr{"   Official download: ", "   Resmi indirme: "}(lang) + f.fix->url + "\n";
      else if (!f.fix->info_url.empty()) o += Tr{"   Official page: ", "   Resmi sayfa: "}(lang) + f.fix->info_url + "\n";
    }
    o += "\n";
  }
  o += "---\n";
  o += Tr{"_Generated by Why Won't It Open? ", "_Neden Açılmıyor? "}(lang) + std::string(version()) +
       Tr{" — free & open source: https://github.com/nowackk-cp/why-wont-it-open_\n",
          " ile oluşturuldu — ücretsiz ve açık kaynak: https://github.com/nowackk-cp/why-wont-it-open_\n"}(lang);
  return o;
}

}  // namespace neden::diagnose
