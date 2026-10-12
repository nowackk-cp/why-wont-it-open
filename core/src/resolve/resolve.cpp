#include "neden/resolve.h"

#include <algorithm>
#include <deque>
#include <map>
#include <memory>
#include <set>
#include <unordered_set>
#include <cstring>
#include <cwctype>
#include <exception>
#include <new>
#include <unordered_map>

#include "util/text.h"

namespace neden::resolve {

namespace {

using util::to_lower_ascii;

constexpr std::size_t kMaxStoredMissingPerModule = 1000;
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

// One import relationship, kept to recompute delay-only status after the walk.
struct RawEdge {
  std::string importer;  // lower-case module name, empty for the program itself
  std::string dll;       // lower-case
  bool delay = false;
};

// False if a manifest attribute value contains a path separator, a drive colon, "..", or a wildcard.
bool safe_manifest_value(std::string_view v) {
  if (v.find("..") != std::string_view::npos) return false;
  for (const char c : v) {
    if (c == '\\' || c == '/' || c == ':' || c == '*' || c == '?' || c == '\0') return false;
  }
  return true;
}

// Name the loader would look up: lower-case, ".dll" appended when there is no extension.
std::string loader_name(std::string_view name) {
  std::string n = to_lower_ascii(name);
  if (n.empty()) return n;
  if (n.find('.') == std::string::npos) {
    n += ".dll";
  } else if (n.back() == '.') {
    n.pop_back();  // "foo." means exactly "foo", no extension added
  }
  return n;
}

class Resolver {
 public:
  Resolver(const fs::path& program, const env::Environment& env, const Options& options)
      : program_(program), env_(env), options_(options) {}

  Result run() {
    Result result;
    result.target_path = program_;
    auto bytes = env_.read_file(program_, options_.max_image_bytes);
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
    // The parse result lives in `result` (no copy); edges point into it. `result` is not
    // moved or modified while the walk runs, and vector buffers survive moves anyway.
    result.target = pe::parse(*bytes);
    if (!result.target.ok()) return result;
    if (bytes->size() >= options_.max_image_bytes) {
      // Only the first max_image_bytes were read; a section "running past the end" is our cap,
      // not a damaged file.
      result.target.info->truncated = false;
      result.target.info->warnings.push_back("file is larger than the analysis limit; only the first " +
                                             std::to_string(bytes->size()) + " bytes were analysed");
    }
    bytes.reset();

    const pe::PeInfo& info = *result.target.info;
    process_ = process_machine(info, env_.os());
    result.process_machine = process_;
    wow_ = env_.os().is_64bit && (process_ == pe::Machine::I386 || process_ == pe::Machine::ARMNT);
    system_dir_ = wow_ ? env_.syswow64_dir() : env_.system_dir();
    result.system_dir = system_dir_;
    app_dir_ = program_.parent_path();
    for (const std::string& k : env_.known_dlls()) known_.insert(to_lower_ascii(k));

    // Side-by-side assemblies the program asks for in its manifest (e.g. Common Controls 6).
    std::string manifest = info.manifest;
    if (manifest.empty()) {
      fs::path external = program_;
      external += ".manifest";
      if (auto m = env_.read_file(external, 1024 * 1024)) manifest.assign(m->begin(), m->end());
    }
    load_sxs_assemblies(manifest);

    for (const pe::ImportedDll& imp : info.imports) {
      queue_.push_back(Edge{"", false, loader_name(imp.name), &imp.functions, nullptr, imp.delay_load, 1});
    }

    while (!queue_.empty()) {
      Edge edge = std::move(queue_.front());
      queue_.pop_front();
      visit(edge, result);
    }
    recompute_delay_only(result);
    return result;
  }

 private:
  // A 32-bit process on 64-bit Windows sees System32 as SysWOW64.
  fs::path for_process(const fs::path& p) const {
    if (!wow_) return p;
    const std::wstring sys32 = to_lower_w((env_.windows_dir() / "System32").wstring());
    const std::wstring s = p.wstring();
    const std::wstring lower = to_lower_w(s);
    if (lower.starts_with(sys32) && (lower.size() == sys32.size() || lower[sys32.size()] == L'\\')) {
      return fs::path(env_.syswow64_dir().wstring() + s.substr(sys32.size()));
    }
    return p;
  }

  static std::wstring to_lower_w(std::wstring s) {
    for (wchar_t& c : s) c = static_cast<wchar_t>(towlower(c));
    return s;
  }

  // Reads attribute `name` from an XML start tag (very small, tolerant parser).
  static std::string xml_attr(std::string_view tag, std::string_view name) {
    std::size_t pos = 0;
    while ((pos = tag.find(name, pos)) != std::string_view::npos) {
      const bool boundary = pos == 0 || tag[pos - 1] == ' ' || tag[pos - 1] == '\t' || tag[pos - 1] == '\n' ||
                            tag[pos - 1] == '\r';
      std::size_t p = pos + name.size();
      while (p < tag.size() && (tag[p] == ' ' || tag[p] == '\t')) ++p;
      if (boundary && p < tag.size() && tag[p] == '=') {
        ++p;
        while (p < tag.size() && (tag[p] == ' ' || tag[p] == '\t')) ++p;
        if (p < tag.size() && (tag[p] == '"' || tag[p] == '\'')) {
          const char quote = tag[p];
          const std::size_t end = tag.find(quote, p + 1);
          if (end != std::string_view::npos) return std::string(tag.substr(p + 1, end - p - 1));
        }
      }
      pos += name.size();
    }
    return {};
  }

  void load_sxs_assemblies(const std::string& manifest_text) {
    if (manifest_text.empty()) return;
    const std::string text = to_lower_ascii(manifest_text);
    const fs::path winsxs = env_.windows_dir() / "WinSxS";
    std::size_t pos = 0;
    while ((pos = text.find("<dependentassembly", pos)) != std::string::npos) {
      const std::size_t id = text.find("assemblyidentity", pos);
      if (id == std::string::npos) break;
      const std::size_t end = text.find('>', id);
      if (end == std::string::npos) break;
      const std::string_view tag(text.data() + id, end - id);
      pos = end;

      const std::string name = xml_attr(tag, "name");
      const std::string version = xml_attr(tag, "version");
      const std::string token = xml_attr(tag, "publickeytoken");
      std::string arch = xml_attr(tag, "processorarchitecture");
      if (name.empty()) continue;
      // Manifest values become path components / WinSxS folder-name prefixes: refuse anything
      // that could escape the intended folder or act as a wildcard.
      if (!safe_manifest_value(name) || !safe_manifest_value(version) || !safe_manifest_value(token) ||
          (arch != "*" && !safe_manifest_value(arch))) {
        continue;
      }
      if (token.empty()) {
        // Private assembly: a folder next to the program (Chrome's "<version>\",
        // Blender's "blender.shared\").
        const fs::path dir = app_dir_ / name;
        if (env_.dir_exists(dir)) sxs_dirs_.push_back(dir);
        continue;
      }
      if (arch.empty() || arch == "*") {
        const char* p = sxs_arch_prefix(process_);
        if (!p) continue;
        arch.assign(p, std::strlen(p) - 1);
      }
      // Servicing policy redirects to the newest build with the same major.minor.
      const std::string major_minor = version.substr(0, version.find('.', version.find('.') + 1));
      const std::string prefix = arch + "_" + name + "_" + token + "_" + major_minor;
      std::vector<std::string> dirs = env_.list_dir(winsxs, prefix);
      std::sort(dirs.begin(), dirs.end(), [](const std::string& a, const std::string& b) {
        return version_key(a) > version_key(b);
      });
      if (!dirs.empty()) sxs_dirs_.push_back(winsxs / dirs.front());
    }
  }

  // "x86_name_token_6.0.19041.1110_none_hash" -> {6, 0, 19041, 1110}
  static std::vector<int> version_key(const std::string& dir) {
    std::vector<int> key;
    std::size_t start = 0;
    for (int i = 0; i < 3 && start != std::string::npos; ++i) start = dir.find('_', start + 1);
    if (start == std::string::npos) return key;
    int cur = 0;
    for (std::size_t i = start + 1; i < dir.size() && dir[i] != '_'; ++i) {
      if (dir[i] == '.') {
        key.push_back(cur);
        cur = 0;
      } else if (dir[i] >= '0' && dir[i] <= '9') {
        if (cur < 100000000) cur = cur * 10 + (dir[i] - '0');  // saturate: no signed overflow
      }
    }
    key.push_back(cur);
    return key;
  }

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

    raw_edges_.push_back({edge.importer, edge.dll, edge.delay});
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

    // Activation context (manifest) redirection comes before the search order.
    for (const fs::path& dir : sxs_dirs_) {
      const fs::path file = dir / name;
      if (env_.file_exists(file)) {
        m.location = Location::SxS;
        m.path = file;
        m.machine = process_;
        m.system_owned = true;
        return m;
      }
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
    std::vector<Dir> dirs = {{for_process(app_dir_), Location::AppDir},
                             {system_dir_, Location::SystemDir},
                             {env_.windows_dir(), Location::WindowsDir}};
    for (const fs::path& p : env_.path_dirs()) dirs.push_back({for_process(p), Location::PathDir});

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
    // Judge by the folder, not the label: a program inside System32 has app dir == system dir.
    const std::wstring parent = to_lower_w(first.path.parent_path().lexically_normal().wstring());
    m.system_owned = parent == to_lower_w(system_dir_.lexically_normal().wstring()) ||
                     parent == to_lower_w(env_.windows_dir().lexically_normal().wstring());
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
    if (m.location == Location::KnownDll || m.location == Location::ApiSet) return;
    // Windows' own DLLs are consistent with the Windows they ship with; their
    // internals (optional delay-loads, edition-specific API sets) are not the
    // user's problem. Redistributable runtimes in the system dir are walked.
    const bool redistributable = options_.is_redistributable && options_.is_redistributable(m.name);
    if (m.system_owned && !redistributable) return;
    auto image = load_shared(m.path);
    if (!image->parse.ok()) return;
    for (const pe::ImportedDll& imp : image->parse.info->imports) {
      const std::string dll = loader_name(imp.name);
      if (m.system_owned && imp.delay_load) continue;
      // Delay-only status is recomputed from all edges after the walk (recompute_delay_only).
      queue_.push_back(Edge{m.name, m.system_owned, dll, &imp.functions, image, imp.delay_load, depth + 1});
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
      MissingFunction mf{importer, f.by_ordinal ? "#" + std::to_string(f.ordinal) : f.name, f.by_ordinal, f.ordinal};
      auto& seen = missing_seen_[module.name];
      if (!seen.insert(mf.importer + '\n' + mf.function).second) continue;  // already recorded
      if (module.missing_functions.size() >= kMaxStoredMissingPerModule) {
        ++module.missing_functions_omitted;
        continue;
      }
      module.missing_functions.push_back(std::move(mf));
    }
  }

  // A module is delay-only iff every path from the program to it contains a delay edge,
  // i.e. it is not reachable from the program through normal (non-delay) edges only.
  void recompute_delay_only(Result& result) {
    std::unordered_map<std::string, std::vector<const RawEdge*>> by_importer;
    for (const RawEdge& e : raw_edges_) {
      if (!e.delay) by_importer[e.importer].push_back(&e);
    }
    std::unordered_set<std::string> reached;
    std::deque<std::string> work{std::string()};  // the program itself has the empty name
    while (!work.empty()) {
      const std::string cur = std::move(work.front());
      work.pop_front();
      const auto it = by_importer.find(cur);
      if (it == by_importer.end()) continue;
      for (const RawEdge* e : it->second) {
        if (reached.insert(e->dll).second) work.push_back(e->dll);
      }
    }
    for (Module& m : result.modules) m.delay_only = reached.count(m.name) == 0;
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
    if (auto bytes = env_.read_file(path, options_.max_image_bytes)) {
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
  bool wow_ = false;
  std::vector<fs::path> sxs_dirs_;
  std::unordered_set<std::string> known_;
  std::deque<Edge> queue_;
  std::vector<RawEdge> raw_edges_;
  std::unordered_map<std::string, std::unordered_set<std::string>> missing_seen_;  // module -> importer+function keys
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
  try {
    return Resolver(program, env, options).run();
  } catch (const std::exception& e) {
    // std::bad_alloc on a hostile file, or any other failure: a clean "could not analyse" result.
    Result r;
    r.target_path = program;
    r.target.error = pe::ParseError::IoError;
    r.target.detail = std::string("could not analyse the file: ") + e.what();
    return r;
  } catch (...) {
    Result r;
    r.target_path = program;
    r.target.error = pe::ParseError::IoError;
    r.target.detail = "could not analyse the file: unexpected error";
    return r;
  }
}

}  // namespace neden::resolve
