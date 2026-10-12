// Static DLL resolution: imitates the Windows loader's search order without
// loading anything, and walks the dependency tree.
#pragma once

#include <filesystem>
#include <string>
#include <vector>

#include "neden/env.h"
#include "neden/pe.h"

namespace neden::resolve {

namespace fs = std::filesystem;

enum class Location {
  NotFound,
  KnownDll,    // HKLM\...\Session Manager\KnownDLLs, always mapped from the system dir
  ApiSet,      // api-ms-*/ext-ms-* virtual name redirected to a host DLL
  AppDir,      // directory of the executable
  SystemDir,   // System32 (or SysWOW64 for 32-bit programs on 64-bit Windows)
  WindowsDir,  // %windir%
  PathDir,     // a directory listed in PATH
  SxS,         // WinSxS side-by-side assembly (VC++ 2005/2008)
};

const char* location_name(Location l);

// A file with the requested name somewhere in the search order.
struct Candidate {
  fs::path path;
  Location location = Location::NotFound;
  pe::Machine machine = pe::Machine::Unknown;  // Unknown if the file isn't a valid PE
};

// An imported function that the resolved DLL does not export.
struct MissingFunction {
  std::string importer;  // lower-case module name that imports it
  std::string function;  // name, or "#<ordinal>"
};

struct Module {
  std::string name;              // lower-case requested name, e.g. "msvcp140.dll"
  std::string api_set_host;      // for ApiSet: lower-case host DLL name ("" if the set has no host)
  fs::path path;                 // resolved file; empty when not found
  Location location = Location::NotFound;
  pe::Machine machine = pe::Machine::Unknown;
  bool arch_mismatch = false;    // resolved file's machine is incompatible with the program
  bool invalid_image = false;    // resolved file exists but is not a valid PE
  std::string invalid_reason;
  bool delay_only = false;       // reached only through delay-load imports
  bool system_owned = false;     // lives in system dir/KnownDLLs/API set: part of Windows or a runtime
  int depth = 1;                 // 1 = imported directly by the program
  std::vector<std::string> importers;           // lower-case names, first is the shortest path
  std::vector<MissingFunction> missing_functions;
  std::vector<Candidate> candidates;            // every same-named file in search order (not for KnownDll/ApiSet)
};

struct Options {
  int max_modules = 400;
};

struct Result {
  fs::path target_path;
  pe::ParseResult target;        // parse of the program itself
  pe::Machine process_machine = pe::Machine::Unknown;  // machine the program's process will have
  fs::path system_dir;           // the system dir used for this program's bitness
  std::vector<Module> modules;   // breadth-first order; empty if the target failed to parse
  bool truncated_walk = false;   // stopped at Options::max_modules

  const Module* find(std::string_view lower_name) const;
};

Result resolve(const fs::path& program, const env::Environment& env, const Options& options = {});

// True if a DLL built for `dll` can be loaded into a process of `process`.
bool machine_compatible(pe::Machine process, pe::Machine dll);

}  // namespace neden::resolve
