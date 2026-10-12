// Knowledge base: maps DLL names to the official package that provides them.
// Source of truth is data/runtimes.json, embedded into the binary at build time.
#pragma once

#include <map>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace neden::kb {

// Per-architecture string values. Keys are "x86", "x64", "arm64" or "any".
using ArchMap = std::map<std::string, std::string>;

struct Package {
  std::string id;               // key in "packages", e.g. "vcredist14"
  std::string name;             // display name
  ArchMap winget;               // winget package ids
  ArchMap url;                  // official direct download links (https only)
  std::string info_url;         // official page describing the package
  std::string signer;           // expected Authenticode signer, e.g. "Microsoft Corporation"
  std::string kind;             // "redist" (default), "windows-feature", "os-update", "driver", "program-file"

  // Looks up arch, then "any". Empty string if absent.
  std::string winget_for(std::string_view arch) const;
  std::string url_for(std::string_view arch) const;
};

struct DllEntry {
  std::string name;                // lower-case file name, e.g. "msvcp140.dll"
  std::string package;             // package id; empty for debugOnly / programFile entries
  std::vector<std::string> arch;   // empty = all architectures
  bool debug_only = false;         // debug runtime: no redistributable exists
  bool program_file = false;       // belongs to the program itself (e.g. steam_api64.dll)
  bool gpu_driver = false;         // provided by the graphics driver (vulkan-1.dll, nvcuda.dll)
};

class KnowledgeBase {
 public:
  // Parses JSON text. Returns std::nullopt and fills *error on failure.
  static std::optional<KnowledgeBase> from_json(std::string_view json, std::string* error = nullptr);

  // The copy embedded into the executable.
  static const KnowledgeBase& embedded();

  // Case-insensitive. Also matches wildcard entries whose key ends in '*'
  // (e.g. "api-ms-win-crt-*"); exact matches win over wildcards.
  const DllEntry* find_dll(std::string_view dll_name) const;
  const Package* find_package(std::string_view id) const;

  const std::map<std::string, DllEntry>& dlls() const { return dlls_; }
  const std::map<std::string, Package>& packages() const { return packages_; }

 private:
  std::map<std::string, DllEntry> dlls_;
  std::map<std::string, Package> packages_;
};

}  // namespace neden::kb
