// Abstraction over the machine being inspected: file system, registry and OS
// facts. Diagnosis logic only talks to this interface, so tests can simulate
// machines that lack a runtime (CI runners have every runtime installed).
#pragma once

#include <cstdint>
#include <filesystem>
#include <memory>
#include <optional>
#include <string>
#include <vector>

namespace neden::env {

namespace fs = std::filesystem;

struct OsInfo {
  bool is_64bit = true;            // 64-bit Windows (we may run as a WOW64 process)
  bool is_arm64 = false;           // ARM64 Windows (runs x86/x64 via emulation)
  std::uint32_t major = 10;
  std::uint32_t minor = 0;
  std::uint32_t build = 19045;
};

// One record of a Windows event log.
struct EventRecord {
  std::string channel;                // e.g. "Application"
  std::string provider;               // e.g. "Application Error"
  std::uint32_t id = 0;
  std::uint64_t time = 0;             // FILETIME (100 ns since 1601) as UTC
  std::vector<std::string> data;      // <EventData> values in order (UTF-8)
  std::vector<std::string> names;     // <Data Name="..."> per value; "" for unnamed (may be shorter than data)
};

class Environment {
 public:
  virtual ~Environment() = default;

  virtual OsInfo os() const = 0;

  // Directories as seen by a NATIVE process (no WOW64 redirection):
  // system_dir() is the 64-bit System32 on 64-bit Windows.
  virtual fs::path windows_dir() const = 0;
  virtual fs::path system_dir() const = 0;   // native System32
  virtual fs::path syswow64_dir() const = 0; // empty on 32-bit Windows
  virtual std::vector<fs::path> path_dirs() const = 0;

  virtual bool file_exists(const fs::path& p) const = 0;
  virtual bool dir_exists(const fs::path& p) const = 0;
  // Reads at most max_bytes. std::nullopt if the file can't be read.
  virtual std::optional<std::vector<std::uint8_t>> read_file(const fs::path& p, std::uint64_t max_bytes) const = 0;
  // File names (not full paths) in dir whose names start with prefix (case-insensitive).
  virtual std::vector<std::string> list_dir(const fs::path& dir, const std::string& prefix) const = 0;

  // Lower-case DLL names from HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs.
  virtual std::vector<std::string> known_dlls() const = 0;

  // Resolves an API set name ("api-ms-win-core-file-l1-2-0.dll") to its host
  // DLL ("kernelbase.dll"). std::nullopt if the set is unknown; "" if the set
  // exists but has no host on this machine.
  virtual std::optional<std::string> resolve_api_set(const std::string& name) const = 0;

  // .NET Framework detection (registry based).
  virtual bool netfx35_installed() const = 0;  // CLR 2.0 (.NET 2.0/3.0/3.5)
  virtual bool netfx4_installed() const = 0;   // CLR 4.x

  // Installed .NET (5+) shared frameworks, e.g. {"Microsoft.WindowsDesktop.App", "8.0.11", "x64"}.
  struct DotnetFramework {
    std::string name;
    std::string version;
    std::string arch;
  };
  virtual std::vector<DotnetFramework> dotnet_frameworks() const = 0;

  // Current time as FILETIME (UTC).
  virtual std::uint64_t now() const = 0;

  // Events of one log channel, most recent first: at most max_count records,
  // not older than max_age_days, with one of the given ids (empty = any id)
  // and, when provider is not empty, written by that provider. Unreadable or
  // missing channels yield an empty list. Read-only.
  virtual std::vector<EventRecord> events(const std::string& channel, const std::string& provider,
                                          const std::vector<std::uint32_t>& ids, int max_age_days,
                                          int max_count) const = 0;

  // Contents of the file's ":Zone.Identifier" alternate data stream (Mark of
  // the Web): an INI text with a "ZoneId=3" line. std::nullopt if there is none.
  virtual std::optional<std::string> zone_identifier(const fs::path& file) const = 0;

  // Smart App Control: 0 off, 1 on (enforcing), 2 evaluation mode, -1 unknown
  // (also: Windows older than 11 22H2, where the setting does not exist).
  virtual int smart_app_control_state() const = 0;
};

// The machine we are running on. Handles WOW64 (Sysnative, KEY_WOW64_64KEY).
std::unique_ptr<Environment> make_system_environment();

// In-memory machine for tests.
class FakeEnvironment : public Environment {
 public:
  FakeEnvironment();

  OsInfo os_info;
  fs::path windows = "C:\\Windows";
  std::vector<fs::path> path;
  std::vector<std::string> known;
  std::vector<std::pair<std::string, std::string>> api_sets;  // name prefix (without version suffix) -> host
  bool netfx35 = false;
  bool netfx4 = true;
  std::vector<DotnetFramework> dotnet;
  std::vector<EventRecord> event_log;                 // events()/now() are simulated from this
  std::uint64_t now_filetime = 134000000000000000ull;  // ~ mid 2025; tests set an explicit date
  int sac_state = -1;

  void add_file(const fs::path& p, std::vector<std::uint8_t> bytes);
  // Simulates a Zone.Identifier stream on a file.
  void set_zone_identifier(const fs::path& file, std::string contents);

  OsInfo os() const override { return os_info; }
  fs::path windows_dir() const override { return windows; }
  fs::path system_dir() const override { return windows / "System32"; }
  fs::path syswow64_dir() const override { return os_info.is_64bit ? windows / "SysWOW64" : fs::path(); }
  std::vector<fs::path> path_dirs() const override { return path; }
  bool file_exists(const fs::path& p) const override;
  bool dir_exists(const fs::path& p) const override;
  std::optional<std::vector<std::uint8_t>> read_file(const fs::path& p, std::uint64_t max_bytes) const override;
  std::vector<std::string> list_dir(const fs::path& dir, const std::string& prefix) const override;
  std::vector<std::string> known_dlls() const override { return known; }
  std::optional<std::string> resolve_api_set(const std::string& name) const override;
  bool netfx35_installed() const override { return netfx35; }
  bool netfx4_installed() const override { return netfx4; }
  std::vector<DotnetFramework> dotnet_frameworks() const override { return dotnet; }
  std::uint64_t now() const override { return now_filetime; }
  std::vector<EventRecord> events(const std::string& channel, const std::string& provider,
                                  const std::vector<std::uint32_t>& ids, int max_age_days,
                                  int max_count) const override;
  std::optional<std::string> zone_identifier(const fs::path& file) const override;
  int smart_app_control_state() const override { return sac_state; }

 private:
  std::vector<std::pair<std::wstring, std::string>> zones_;
  static std::wstring key(const fs::path& p);
  std::vector<std::pair<std::wstring, std::vector<std::uint8_t>>> files_;
};

}  // namespace neden::env
