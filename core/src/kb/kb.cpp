#include "neden/kb.h"

#include <cstdio>
#include <cstdlib>

#include "kb/json.h"

namespace neden::kb::detail {
extern const unsigned char kEmbeddedKb[];
extern const std::size_t kEmbeddedKbSize;
}  // namespace neden::kb::detail

namespace neden::kb {

namespace {

std::string ascii_lower(std::string_view s) {
  std::string out(s);
  for (char& c : out) {
    if (c >= 'A' && c <= 'Z') c = static_cast<char>(c - 'A' + 'a');
  }
  return out;
}

std::string lookup(const ArchMap& map, std::string_view arch) {
  for (std::string_view key : {arch, std::string_view("any")}) {
    auto it = map.find(std::string(key));
    if (it != map.end()) return it->second;
  }
  return {};
}

bool fail(std::string* error, std::string msg) {
  if (error) *error = std::move(msg);
  return false;
}

bool read_string(const json::Value& obj, const char* key, std::string& out, const std::string& ctx,
                 std::string* error) {
  const json::Value* v = obj.find(key);
  if (!v) return true;
  if (!v->is_string()) return fail(error, ctx + ": \"" + key + "\" must be a string");
  out = v->as_string();
  return true;
}

bool read_bool(const json::Value& obj, const char* key, bool& out, const std::string& ctx, std::string* error) {
  const json::Value* v = obj.find(key);
  if (!v) return true;
  if (!v->is_bool()) return fail(error, ctx + ": \"" + key + "\" must be true or false");
  out = v->as_bool();
  return true;
}

bool read_arch_map(const json::Value& obj, const char* key, ArchMap& out, bool https_only, const std::string& ctx,
                   std::string* error) {
  const json::Value* v = obj.find(key);
  if (!v) return true;
  if (!v->is_object()) return fail(error, ctx + ": \"" + key + "\" must be an object");
  for (const auto& [arch, val] : v->as_object()) {
    if (!val.is_string() || val.as_string().empty()) {
      return fail(error, ctx + ": \"" + key + "." + arch + "\" must be a non-empty string");
    }
    if (https_only && val.as_string().rfind("https://", 0) != 0) {
      return fail(error, ctx + ": \"" + key + "." + arch + "\" must start with https://");
    }
    out[arch] = val.as_string();
  }
  return true;
}

bool parse_package(const std::string& id, const json::Value& v, Package& pkg, std::string* error) {
  const std::string ctx = "package \"" + id + "\"";
  if (!v.is_object()) return fail(error, ctx + " must be an object");
  pkg.id = id;
  pkg.kind = "redist";
  if (!read_string(v, "name", pkg.name, ctx, error) || !read_string(v, "infoUrl", pkg.info_url, ctx, error) ||
      !read_string(v, "signer", pkg.signer, ctx, error) || !read_string(v, "kind", pkg.kind, ctx, error) ||
      !read_arch_map(v, "winget", pkg.winget, false, ctx, error) ||
      !read_arch_map(v, "url", pkg.url, true, ctx, error)) {
    return false;
  }
  if (!pkg.info_url.empty() && pkg.info_url.rfind("https://", 0) != 0) {
    return fail(error, ctx + ": \"infoUrl\" must start with https://");
  }
  if (pkg.kind.empty()) return fail(error, ctx + ": \"kind\" must not be empty");
  return true;
}

bool parse_dll(const std::string& key, const json::Value& v, DllEntry& e, std::string* error) {
  const std::string ctx = "dll \"" + key + "\"";
  if (!v.is_object()) return fail(error, ctx + " must be an object");
  e.name = ascii_lower(key);
  if (!read_string(v, "package", e.package, ctx, error) || !read_bool(v, "debugOnly", e.debug_only, ctx, error) ||
      !read_bool(v, "programFile", e.program_file, ctx, error) ||
      !read_bool(v, "gpuDriver", e.gpu_driver, ctx, error)) {
    return false;
  }
  if (const json::Value* arch = v.find("arch")) {
    if (!arch->is_array()) return fail(error, ctx + ": \"arch\" must be an array");
    for (const json::Value& a : arch->as_array()) {
      if (!a.is_string()) return fail(error, ctx + ": \"arch\" entries must be strings");
      e.arch.push_back(a.as_string());
    }
  }
  if (e.package.empty() && !e.debug_only && !e.program_file && !e.gpu_driver) {
    return fail(error, ctx + " needs a \"package\" or one of debugOnly/programFile/gpuDriver");
  }
  return true;
}

}  // namespace

std::string Package::winget_for(std::string_view arch) const { return lookup(winget, arch); }
std::string Package::url_for(std::string_view arch) const { return lookup(url, arch); }

std::optional<KnowledgeBase> KnowledgeBase::from_json(std::string_view json_text, std::string* error) {
  std::string parse_error;
  auto root = json::parse(json_text, &parse_error);
  if (!root) {
    fail(error, "JSON: " + parse_error);
    return std::nullopt;
  }
  if (!root->is_object()) {
    fail(error, "top level must be an object");
    return std::nullopt;
  }
  const json::Value* dlls = root->find("dlls");
  const json::Value* packages = root->find("packages");
  if (!dlls || !dlls->is_object() || !packages || !packages->is_object()) {
    fail(error, "top level must contain \"dlls\" and \"packages\" objects");
    return std::nullopt;
  }

  KnowledgeBase kb;
  for (const auto& [id, value] : packages->as_object()) {
    Package pkg;
    if (id.empty()) {
      fail(error, "package id must not be empty");
      return std::nullopt;
    }
    if (!parse_package(id, value, pkg, error)) return std::nullopt;
    kb.packages_[id] = std::move(pkg);
  }
  for (const auto& [key, value] : dlls->as_object()) {
    DllEntry entry;
    if (!parse_dll(key, value, entry, error)) return std::nullopt;
    const std::size_t star = entry.name.find('*');
    if (entry.name.empty() || (star != std::string::npos && (star + 1 != entry.name.size() || star == 0))) {
      fail(error, "dll \"" + key + "\": '*' is only allowed as a suffix after a non-empty prefix");
      return std::nullopt;
    }
    if (!entry.package.empty() && !kb.packages_.count(entry.package)) {
      fail(error, "dll \"" + key + "\" references unknown package \"" + entry.package + "\"");
      return std::nullopt;
    }
    if (kb.dlls_.count(entry.name)) {
      fail(error, "dll \"" + key + "\" is defined twice (keys are case-insensitive)");
      return std::nullopt;
    }
    kb.dlls_[entry.name] = std::move(entry);
  }
  return kb;
}

const KnowledgeBase& KnowledgeBase::embedded() {
  static const KnowledgeBase instance = [] {
    std::string error;
    auto kb = from_json(
        std::string_view(reinterpret_cast<const char*>(detail::kEmbeddedKb), detail::kEmbeddedKbSize), &error);
    if (!kb) {
#ifndef NDEBUG
      std::fprintf(stderr, "FATAL: embedded runtimes.json is invalid: %s\n", error.c_str());
      std::abort();
#else
      return KnowledgeBase();
#endif
    }
    return std::move(*kb);
  }();
  return instance;
}

const DllEntry* KnowledgeBase::find_dll(std::string_view dll_name) const {
  const std::string name = ascii_lower(dll_name);
  if (auto it = dlls_.find(name); it != dlls_.end()) return &it->second;

  // Wildcards: the longest matching prefix wins (linear scan; the table is small).
  const DllEntry* best = nullptr;
  std::size_t best_len = 0;
  for (const auto& [key, entry] : dlls_) {
    if (key.empty() || key.back() != '*') continue;
    const std::size_t len = key.size() - 1;
    if (len > best_len && name.size() >= len && name.compare(0, len, key, 0, len) == 0) {
      best = &entry;
      best_len = len;
    }
  }
  return best;
}

const Package* KnowledgeBase::find_package(std::string_view id) const {
  auto it = packages_.find(std::string(id));
  return it == packages_.end() ? nullptr : &it->second;
}

}  // namespace neden::kb
