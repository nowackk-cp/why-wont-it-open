#include "neden/resolve.h"

#include <algorithm>
#include <deque>
#include <map>
#include <memory>
#include <set>
#include <unordered_set>
#include <cwctype>

#include "util/text.h"

namespace neden::resolve {

namespace {

using util::to_lower_ascii;

constexpr std::uint64_t kMaxImageBytes = 512ull * 1024 * 1024;
constexpr std::uint64_t kHeaderBytes = 4096;

bool is_api_set_name(std::string_view lower) {
  return lower.starts_with("api-ms-") || lower.starts_with("ext-ms-");
}

// VC++ 2005/2008 runtimes live in WinSxS and are found through the program's manifest.
// Returns the assembly name fragment, e.g. "microsoft.vc90.crt", or "".
std::string sxs_assembly_for(std::string_view lower) {
  struct Rule {
    std::string_view prefix;
    std::string_view assembly;
  };
  static constexpr Rule kRules[] = {
      {"msvcr80", "microsoft.vc80.crt"},  {"msvcp80", "microsoft.vc80.crt"},  {"msvcm80", "microsoft.vc80.crt"},
      {"mfc80", "microsoft.vc80.mfc"},    {"mfcm80", "microsoft.vc80.mfc"},   {"atl80", "microsoft.vc80.atl"},
      {"vcomp", "microsoft.vc80.openmp"}, {"msvcr90", "microsoft.vc90.crt"},  {"msvcp90", "microsoft.vc90.crt"},
      {"msvcm90", "microsoft.vc90.crt"},  {"mfc90", "microsoft.vc90.mfc"},    {"mfcm90", "microsoft.vc90.mfc"},
      {"atl90", "microsoft.vc90.atl"},    {"vcomp90", "microsoft.vc90.openmp"},
  };
  for (const Rule& r : kRules) {
    if (lower.starts_with(r.prefix)) {
      if (r.prefix == "vcomp" && !lower.starts_with("vcomp.dll")) continue;  // only VC80's vcomp.dll
      return std::string(r.assembly);
    }
  }
  return {};
}

const char* sxs_arch_prefix(pe::Machine m) {
  switch (m) {
    case pe::Machine::I386: return "x86_";
    case pe::Machine::AMD64: return "amd64_";
    case pe::Machine::IA64: return "ia64_";
    default: return nullptr;
  }
}

struct Exports {
  std::unordered_set<std::string> names;
  std::unordered_set<std::uint32_t> ordinals;
};

struct Image {
  pe::ParseResult parse;
  std::shared_ptr<Exports> exports;  // built lazily
};

struct Edge {
  std::string importer;      // lower-case, empty for the program itself
  bool importer_system = false;
  std::string dll;           // lower-case
  const std::vector<pe::ImportedFunction>* functions = nullptr;
  std::shared_ptr<Image> keep_alive;  // owner of `functions`
  bool delay = false;
  int depth = 1;
};

class Resolver {
 public:
  Resolver(const fs::path& program, const env::Environment& env, const Options& options)
      : program_(program), env_(env), options_(options) {}

  Result run() {
    Result result;
    result.target_path = program_;
    auto bytes = env_.read_file(program_, kMaxImageBytes);
    if (!bytes) {
      result.target.error = pe::ParseError::IoError;
      result.target.detail = "cannot read file";
      return result;
    }
    if (bytes->empty()) {
      result.target.error = pe::ParseError::Empty;
      result.target.detail = "file is empty";
      return result;
    }
    auto target = std::make_shared<Image>();
    target->parse = pe::parse(*bytes);
    result.target = target->parse;
    if (!target->parse.ok()) return result;

    const pe::PeInfo& info = *target->parse.info;
    process_ = process_machine(info, env_.os());
    result.process_machine = process_;
    const bool wow = env_.os().is_64bit && (process_ == pe::Machine::I386 || process_ == pe::Machine::ARMNT);
    system_dir_ = wow ? env_.syswow64_dir() : env_.system_dir();
    result.system_dir = system_dir_;
    app_dir_ = program_.parent_path();
    for (const std::string& k : env_.known_dlls()) known_.insert(to_lower_ascii(k));

    for (const pe::ImportedDll& imp : info.imports) {
      queue_.push_back(Edge{"", false, to_lower_ascii(imp.name), &imp.functions, target, imp.delay_load, 1});
    }

    while (!queue_.empty()) {
      Edge edge = std::move(queue_.front());
      queue_.pop_front();
      visit(edge, result);
    }
    return result;
  }

 private:
  static pe::Machine process_machine(const pe::PeInfo& info, const env::OsInfo& os) {
    // AnyCPU .NET programs run as a native 64-bit process on 64-bit Windows.
    if (info.clr && info.clr->il_only() && !info.clr->requires_32bit() && !info.clr->prefers_32bit() &&
        info.machine == pe::Machine::I386 && os.is_64bit) {
      return os.is_arm64 ? pe::Machine::ARM64 : pe::Machine::AMD64;
    }
    return info.machine;
  }

  void visit(const Edge& edge, Result& result) {
    Module* module = nullptr;
    auto it = index_.find(edge.dll);
    if (it != index_.end()) {
      module = &result.modules[it->second];
      if (!edge.delay) module->delay_only = false;
    } else {
      if (static_cast<int>(result.modules.size()) >= options_.max_modules) {
        result.truncated_walk = true;
        return;
      }
      index_[edge.dll] = result.modules.size();
      result.modules.push_back(locate(edge.dll));
      module = &result.modules.back();
      module->delay_only = edge.delay;
      module->depth = edge.depth;
      enqueue_dependencies(*module, edge.depth);
      module = &result.modules[index_[edge.dll]];  // enqueue doesn't touch modules, but stay safe
    }

    const std::string importer = edge.importer.empty() ? to_lower_ascii(program_.filename().string()) : edge.importer;
    if (std::find(module->importers.begin(), module->importers.end(), importer) == module->importers.end()) {
      module->importers.push_back(importer);
    }
    check_functions(edge, importer, *module);
  }

  Module locate(const std::string& name) {
    Module m;
    m.name = name;

    if (is_api_set_name(name)) {
      if (auto host = env_.resolve_api_set(name)) {
        m.location = Location::ApiSet;
        m.api_set_host = *host;
        m.system_owned = true;
        if (!host->empty()) {
          m.path = system_dir_ / *host;
          m.machine = process_;
        }
        return m;
      }
      // Older Windows without a schema entry: fall back to physical stub DLLs.
    }

    if (known_.count(name)) {
      m.location = Location::KnownDll;
      m.path = system_dir_ / name;
      m.machine = process_;
      m.system_owned = true;
      return m;
    }

    struct Dir {
      fs::path path;
      Location location;
    };
    std::vector<Dir> dirs = {{app_dir_, Location::AppDir},
                             {system_dir_, Location::SystemDir},
                             {env_.windows_dir(), Location::WindowsDir}};
    for (const fs::path& p : env_.path_dirs()) dirs.push_back({p, Location::PathDir});

    std::set<std::wstring> seen;
    for (const Dir& d : dirs) {
      if (d.path.empty()) continue;
      const fs::path file = d.path / name;
      std::wstring key = file.lexically_normal().wstring();
      for (wchar_t& c : key) c = static_cast<wchar_t>(towlower(c));
      if (!seen.insert(key).second) continue;
      if (!env_.file_exists(file)) continue;
      m.candidates.push_back({file, d.location, header_machine(file)});
    }

    if (m.candidates.empty()) {
      locate_sxs(m);
      return m;
    }

    const Candidate& first = m.candidates.front();
    m.path = first.path;
    m.location = first.location;
    m.system_owned = first.location == Location::SystemDir || first.location == Location::WindowsDir;
    const Image& image = load(first.path);
    if (!image.parse.ok()) {
      m.invalid_image = true;
      m.invalid_reason = pe::parse_error_name(image.parse.error);
      return m;
    }
    m.machine = image.parse.info->machine;
    m.arch_mismatch = !machine_compatible(process_, m.machine);
    return m;
  }

  void locate_sxs(Module& m) {
    const std::string assembly = sxs_assembly_for(m.name);
    const char* arch = sxs_arch_prefix(process_);
    if (assembly.empty() || !arch) return;
    const fs::path winsxs = env_.windows_dir() / "WinSxS";
    for (const std::string& dir : env_.list_dir(winsxs, std::string(arch) + assembly + "_")) {
      const fs::path file = winsxs / dir / m.name;
      if (env_.file_exists(file)) {
        m.path = file;
        m.location = Location::SxS;
        m.machine = process_;
        m.system_owned = true;
        return;
      }
    }
  }

  void enqueue_dependencies(const Module& m, int depth) {
    if (m.path.empty() || m.invalid_image || m.arch_mismatch) return;
    if (m.location == Location::KnownDll || m.location == Location::ApiSet || m.location == Location::SxS) return;
    auto image = load_shared(m.path);
    if (!image->parse.ok()) return;
    for (const pe::ImportedDll& imp : image->parse.info->imports) {
      const std::string dll = to_lower_ascii(imp.name);
      if (m.system_owned) {
        // Windows' own DLLs delay-load optional components and extension API
        // sets that are legitimately absent on many editions.
        if (imp.delay_load || dll.starts_with("ext-ms-")) continue;
      }
      queue_.push_back(Edge{m.name, m.system_owned, dll, &imp.functions, image, imp.delay_load || m.delay_only,
                            depth + 1});
    }
  }

  void check_functions(const Edge& edge, const std::string& importer, Module& module) {
    if (!edge.functions || edge.functions->empty()) return;
    if (module.path.empty() || module.invalid_image || module.arch_mismatch) return;
    if (module.location == Location::ApiSet) return;
    if (edge.importer_system && module.system_owned) return;  // Windows is consistent with itself

    const Exports* exports = exports_of(module.path);
    if (!exports) return;
    for (const pe::ImportedFunction& f : *edge.functions) {
      const bool found = f.by_ordinal ? exports->ordinals.count(f.ordinal) > 0 : exports->names.count(f.name) > 0;
      if (found) continue;
      MissingFunction mf{importer, f.by_ordinal ? "#" + std::to_string(f.ordinal) : f.name};
      const bool dup = std::any_of(module.missing_functions.begin(), module.missing_functions.end(), [&](const auto& x) {
        return x.importer == mf.importer && x.function == mf.function;
      });
      if (!dup) module.missing_functions.push_back(std::move(mf));
    }
  }

  const Exports* exports_of(const fs::path& path) {
    auto image = load_shared(path);
    if (!image->parse.ok()) return nullptr;
    if (!image->exports) {
      auto e = std::make_shared<Exports>();
      for (const pe::ExportedFunction& f : image->parse.info->exports) {
        if (!f.name.empty()) e->names.insert(f.name);
        e->ordinals.insert(f.ordinal);
      }
      image->exports = std::move(e);
    }
    return image->exports.get();
  }

  pe::Machine header_machine(const fs::path& path) {
    auto bytes = env_.read_file(path, kHeaderBytes);
    if (!bytes) return pe::Machine::Unknown;
    const pe::ParseResult r = pe::parse(*bytes);
    return r.ok() ? r.info->machine : pe::Machine::Unknown;
  }

  const Image& load(const fs::path& path) { return *load_shared(path); }

  std::shared_ptr<Image> load_shared(const fs::path& path) {
    std::wstring key = path.lexically_normal().wstring();
    for (wchar_t& c : key) c = static_cast<wchar_t>(towlower(c));
    auto it = images_.find(key);
    if (it != images_.end()) return it->second;
    auto image = std::make_shared<Image>();
    if (auto bytes = env_.read_file(path, kMaxImageBytes)) {
      image->parse = pe::parse(*bytes);
    } else {
      image->parse.error = pe::ParseError::IoError;
      image->parse.detail = "cannot read file";
    }
    images_[key] = image;
    return image;
  }

  fs::path program_;
  const env::Environment& env_;
  Options options_;
  pe::Machine process_ = pe::Machine::Unknown;
  fs::path system_dir_;
  fs::path app_dir_;
  std::unordered_set<std::string> known_;
  std::deque<Edge> queue_;
  std::map<std::string, std::size_t> index_;
  std::map<std::wstring, std::shared_ptr<Image>> images_;
};

}  // namespace

const char* location_name(Location l) {
  switch (l) {
    case Location::NotFound: return "not-found";
    case Location::KnownDll: return "known-dll";
    case Location::ApiSet: return "api-set";
    case Location::AppDir: return "app-dir";
    case Location::SystemDir: return "system-dir";
    case Location::WindowsDir: return "windows-dir";
    case Location::PathDir: return "path";
    case Location::SxS: return "winsxs";
  }
  return "unknown";
}

bool machine_compatible(pe::Machine process, pe::Machine dll) {
  if (process == pe::Machine::Unknown || dll == pe::Machine::Unknown) return true;
  return process == dll;
}

const Module* Result::find(std::string_view lower_name) const {
  for (const Module& m : modules) {
    if (m.name == lower_name) return &m;
  }
  return nullptr;
}

Result resolve(const fs::path& program, const env::Environment& env, const Options& options) {
  return Resolver(program, env, options).run();
}

}  // namespace neden::resolve
