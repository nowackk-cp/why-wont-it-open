#include <windows.h>

#include <cstdio>
#include <filesystem>
#include <string>
#include <string_view>
#include <vector>

#include "neden/pe.h"
#include "neden/version.h"

namespace {

void print_usage() {
  std::puts(
      "Usage:\n"
      "  neden --version\n"
      "  neden info <file.exe> [--verbose]  show what the PE file contains\n"
      "  neden check <file.exe> [--json]    (planned, M2)");
}

std::string to_utf8(const std::wstring& w) {
  if (w.empty()) return {};
  const int n = WideCharToMultiByte(CP_UTF8, 0, w.data(), static_cast<int>(w.size()), nullptr, 0, nullptr, nullptr);
  if (n <= 0) return {};
  std::string out(static_cast<size_t>(n), '\0');
  WideCharToMultiByte(CP_UTF8, 0, w.data(), static_cast<int>(w.size()), out.data(), n, nullptr, nullptr);
  return out;
}

const char* subsystem_name(std::uint16_t s) {
  switch (s) {
    case 1: return "native";
    case 2: return "Windows GUI";
    case 3: return "Windows console";
    case 5: return "OS/2 console";
    case 7: return "POSIX console";
    case 9: return "Windows CE GUI";
    case 10: return "EFI application";
    case 14: return "Xbox";
    case 16: return "Windows boot application";
    default: return "unknown";
  }
}

void print_sections(const neden::pe::PeInfo& info) {
  std::printf("Sections (%zu):\n", info.sections.size());
  for (const auto& s : info.sections) {
    std::printf("  %-8s va=0x%08X vsize=0x%08X raw=0x%08X rsize=0x%08X entropy=%.2f\n", s.name.c_str(),
                s.virtual_address, s.virtual_size, s.raw_offset, s.raw_size, s.entropy);
  }
}

void print_imports(const neden::pe::PeInfo& info, bool verbose) {
  std::printf("Imports (%zu DLLs):\n", info.imports.size());
  for (const auto& d : info.imports) {
    std::printf("  %s%s  (%zu functions)\n", d.name.c_str(), d.delay_load ? " [delay]" : "", d.functions.size());
    if (!verbose) continue;
    for (const auto& f : d.functions) {
      if (f.by_ordinal) {
        std::printf("      #%u\n", static_cast<unsigned>(f.ordinal));
      } else {
        std::printf("      %s\n", f.name.c_str());
      }
    }
  }
}

void print_exports(const neden::pe::PeInfo& info, bool verbose) {
  size_t forwarded = 0;
  for (const auto& e : info.exports) forwarded += e.forwarder.empty() ? 0 : 1;
  std::printf("Exports: %zu (%zu forwarded)", info.exports.size(), forwarded);
  if (!info.export_name.empty()) std::printf(", name %s", info.export_name.c_str());
  std::puts("");
  if (!verbose) return;
  for (const auto& e : info.exports) {
    std::printf("      #%u %s", e.ordinal, e.name.empty() ? "(ordinal only)" : e.name.c_str());
    if (!e.forwarder.empty()) std::printf(" -> %s", e.forwarder.c_str());
    std::puts("");
  }
}

void print_clr(const neden::pe::ClrInfo& clr) {
  std::printf(".NET: runtime %u.%u, metadata \"%s\", flags 0x%X", static_cast<unsigned>(clr.major_runtime_version),
              static_cast<unsigned>(clr.minor_runtime_version), clr.metadata_version.c_str(), clr.flags);
  if (clr.il_only()) std::printf(" ILONLY");
  if (clr.requires_32bit()) std::printf(" 32BITREQUIRED");
  if (clr.prefers_32bit()) std::printf(" 32BITPREFERRED");
  std::puts("");
}

void print_info(const neden::pe::PeInfo& info, bool verbose) {
  std::printf("Machine:      %s (%s)\n", neden::pe::machine_name(info.machine), info.pe32_plus ? "PE32+" : "PE32");
  std::printf("Type:         %s\n", info.is_dll ? "DLL" : "executable");
  std::printf("Subsystem:    %s (%u), version %u.%u\n", subsystem_name(info.subsystem),
              static_cast<unsigned>(info.subsystem), static_cast<unsigned>(info.major_subsystem_version),
              static_cast<unsigned>(info.minor_subsystem_version));
  std::printf("Image base:   0x%llX\n", static_cast<unsigned long long>(info.image_base));
  std::printf("Entry point:  0x%08X\n", info.entry_point_rva);
  std::printf("Size:         file %llu bytes, image %u bytes, headers %u bytes\n",
              static_cast<unsigned long long>(info.file_size), info.size_of_image, info.size_of_headers);
  std::printf("DllChars:     0x%04X\n", static_cast<unsigned>(info.dll_characteristics));
  print_sections(info);
  print_imports(info, verbose);
  if (!info.exports.empty() || !info.export_name.empty()) print_exports(info, verbose);
  if (info.clr) print_clr(*info.clr);
  if (info.manifest.empty()) {
    std::puts("Manifest:     none");
  } else {
    std::printf("Manifest:     embedded (%zu bytes)\n", info.manifest.size());
    if (verbose) std::printf("%s\n", info.manifest.c_str());
  }
  if (info.truncated) std::puts("File is TRUNCATED: section data extends past the end of the file.");
  if (info.overlay_size != 0) {
    std::printf("Overlay:      %llu bytes after the last section\n", static_cast<unsigned long long>(info.overlay_size));
  }
  for (const auto& w : info.warnings) std::printf("warning: %s\n", w.c_str());
}

int run_info(const std::vector<std::wstring>& args) {
  bool verbose = false;
  std::wstring file;
  for (const auto& a : args) {
    if (a == L"--verbose" || a == L"-v") {
      verbose = true;
    } else if (file.empty()) {
      file = a;
    } else {
      print_usage();
      return 1;
    }
  }
  if (file.empty()) {
    print_usage();
    return 1;
  }
  const neden::pe::ParseResult r = neden::pe::parse_file(std::filesystem::path(file));
  if (!r.ok()) {
    std::fprintf(stderr, "error: %s: %s\n", neden::pe::parse_error_name(r.error), r.detail.c_str());
    return 2;
  }
  std::printf("File:         %s\n", to_utf8(file).c_str());
  print_info(*r.info, verbose);
  return 0;
}

}  // namespace

int wmain(int argc, wchar_t** argv) {
  SetConsoleOutputCP(CP_UTF8);
  if (argc < 2) {
    print_usage();
    return 1;
  }
  const std::wstring_view cmd = argv[1];
  if (cmd == L"--version" || cmd == L"-v") {
    std::printf("neden %.*s\n", static_cast<int>(neden::version().size()), neden::version().data());
    return 0;
  }
  if (cmd == L"info") {
    return run_info(std::vector<std::wstring>(argv + 2, argv + argc));
  }
  print_usage();
  return 1;
}
