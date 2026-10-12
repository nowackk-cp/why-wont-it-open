// Bounds-checked Portable Executable parser.
//
// The parser only reads bytes; it never maps or loads the image. Every offset
// read from the file is validated, so malformed or malicious input yields a
// ParseError (or warnings), never undefined behaviour.
#pragma once

#include <cstdint>
#include <filesystem>
#include <optional>
#include <span>
#include <string>
#include <vector>

namespace neden::pe {

enum class Machine : std::uint16_t {
  Unknown = 0,
  I386 = 0x014c,
  AMD64 = 0x8664,
  ARM64 = 0xAA64,
  ARMNT = 0x01c4,
  IA64 = 0x0200,
};

// "x86", "x64", "arm64", "arm", "ia64" or "unknown".
const char* machine_name(Machine m);

enum class ParseError {
  None,
  IoError,             // file could not be opened/read
  Empty,               // zero-length file
  NotMz,               // no "MZ" signature (not an executable at all)
  BadPeOffset,         // e_lfanew points outside the file
  NotPe,               // no "PE\0\0" signature (e.g. a 16-bit DOS/NE program)
  BadOptionalHeader,   // optional header magic/size invalid
  Truncated,           // headers or section table cut off
};

const char* parse_error_name(ParseError e);

struct Section {
  std::string name;  // up to 8 chars, NUL-trimmed
  std::uint32_t virtual_address = 0;
  std::uint32_t virtual_size = 0;
  std::uint32_t raw_offset = 0;
  std::uint32_t raw_size = 0;
  std::uint32_t characteristics = 0;
  double entropy = 0.0;  // Shannon entropy (0..8) of the raw bytes that are present in the file
};

struct ImportedFunction {
  std::string name;            // empty when imported by ordinal
  std::uint16_t ordinal = 0;   // valid when by_ordinal
  std::uint16_t hint = 0;
  bool by_ordinal = false;
};

struct ImportedDll {
  std::string name;  // as written in the file, e.g. "MSVCP140.dll"
  bool delay_load = false;
  std::vector<ImportedFunction> functions;
};

struct ExportedFunction {
  std::string name;              // empty for ordinal-only exports
  std::uint32_t ordinal = 0;     // biased ordinal (Base + index)
  std::string forwarder;         // non-empty for forwarded exports, e.g. "NTDLL.RtlAllocateHeap"
};

struct ClrInfo {
  std::uint16_t major_runtime_version = 0;  // from IMAGE_COR20_HEADER
  std::uint16_t minor_runtime_version = 0;
  std::uint32_t flags = 0;                  // COMIMAGE_FLAGS_*
  std::string metadata_version;             // e.g. "v2.0.50727", "v4.0.30319"; empty if unreadable

  bool il_only() const { return flags & 0x1; }
  bool requires_32bit() const { return (flags & 0x2) && !(flags & 0x20000); }
  bool prefers_32bit() const { return (flags & 0x2) && (flags & 0x20000); }
};

struct PeInfo {
  Machine machine = Machine::Unknown;
  bool pe32_plus = false;  // PE32+ (64-bit optional header)
  bool is_dll = false;
  std::uint16_t characteristics = 0;
  std::uint16_t subsystem = 0;  // IMAGE_SUBSYSTEM_*
  std::uint16_t dll_characteristics = 0;
  std::uint16_t major_subsystem_version = 0;
  std::uint16_t minor_subsystem_version = 0;
  std::uint64_t image_base = 0;
  std::uint32_t entry_point_rva = 0;
  std::uint32_t size_of_image = 0;
  std::uint32_t size_of_headers = 0;

  std::vector<Section> sections;
  std::vector<ImportedDll> imports;  // normal imports first, then delay-load imports

  std::string export_name;  // DLL name stored in the export directory
  std::vector<ExportedFunction> exports;

  std::optional<ClrInfo> clr;     // present for .NET assemblies
  std::string manifest;           // embedded RT_MANIFEST (resource id 1 or 2), raw UTF-8; empty if none

  // File-level observations.
  std::uint64_t file_size = 0;
  bool truncated = false;          // raw data of some section extends past end of file
  std::uint64_t overlay_size = 0;  // bytes after the last section's raw data

  // Non-fatal problems found while parsing (bad RVAs, cut-off tables, ...).
  std::vector<std::string> warnings;

  bool has_import(std::string_view dll_name) const;  // case-insensitive
};

struct ParseResult {
  ParseError error = ParseError::None;
  std::string detail;            // human readable detail for errors (English, for logs)
  std::optional<PeInfo> info;    // set when error == None

  bool ok() const { return error == ParseError::None && info.has_value(); }
};

// Parses an in-memory image. Never throws on malformed input.
ParseResult parse(std::span<const std::uint8_t> data);

// Reads the whole file (up to max_bytes) and parses it.
ParseResult parse_file(const std::filesystem::path& path, std::uint64_t max_bytes = 512ull * 1024 * 1024);

// Case-insensitive ASCII lower-casing used for DLL name comparisons.
std::string to_lower_ascii(std::string_view s);

}  // namespace neden::pe
