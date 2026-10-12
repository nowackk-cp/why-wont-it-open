// Bounds-checked PE parser. See neden/pe.h for the contract.
//
// All integers are decoded byte-by-byte (little endian) from the input; file
// bytes are never reinterpreted as structs. Every offset, size and RVA that
// comes from the file is validated with 64-bit arithmetic before use.
#include "neden/pe.h"

#include <algorithm>
#include <array>
#include <cmath>
#include <cstring>
#include <fstream>
#include <limits>
#include <new>
#include <string_view>
#include <system_error>

namespace neden::pe {

namespace {

constexpr std::uint32_t kMaxSections = 96;
constexpr std::uint32_t kMaxImportedDlls = 4096;
constexpr std::uint32_t kMaxFunctionsPerDll = 65536;
constexpr std::uint32_t kMaxExports = 65536;
constexpr std::size_t kMaxStringLength = 4096;
constexpr std::uint32_t kMaxResourceEntries = 4096;
constexpr std::size_t kMaxManifestBytes = 1024 * 1024;
constexpr std::size_t kMaxWarnings = 200;

constexpr std::size_t kDirExport = 0;
constexpr std::size_t kDirImport = 1;
constexpr std::size_t kDirResource = 2;
constexpr std::size_t kDirDelayImport = 13;
constexpr std::size_t kDirClr = 14;

constexpr std::uint16_t kMagicPe32 = 0x10b;
constexpr std::uint16_t kMagicPe32Plus = 0x20b;

std::uint16_t le16(const std::uint8_t* p) {
  return static_cast<std::uint16_t>(p[0] | (p[1] << 8));
}

std::uint32_t le32(const std::uint8_t* p) {
  return static_cast<std::uint32_t>(p[0]) | (static_cast<std::uint32_t>(p[1]) << 8) |
         (static_cast<std::uint32_t>(p[2]) << 16) | (static_cast<std::uint32_t>(p[3]) << 24);
}

std::uint64_t le64(const std::uint8_t* p) {
  return static_cast<std::uint64_t>(le32(p)) | (static_cast<std::uint64_t>(le32(p + 4)) << 32);
}

ParseResult fail(ParseError e, std::string detail) {
  ParseResult r;
  r.error = e;
  r.detail = std::move(detail);
  return r;
}

struct DataDir {
  std::uint32_t rva = 0;
  std::uint32_t size = 0;
};

// A mapped location: file offset plus how many contiguous bytes may be read.
struct Mapping {
  bool valid = false;
  std::uint64_t offset = 0;
  std::uint64_t avail = 0;
};

double shannon_entropy(const std::uint8_t* p, std::uint64_t n) {
  if (n == 0) return 0.0;
  std::array<std::uint64_t, 256> hist{};
  for (std::uint64_t i = 0; i < n; ++i) ++hist[p[i]];
  double e = 0.0;
  const double total = static_cast<double>(n);
  for (const std::uint64_t c : hist) {
    if (c == 0) continue;
    const double f = static_cast<double>(c) / total;
    e -= f * std::log2(f);
  }
  return e < 0.0 ? 0.0 : e;
}

class Parser {
 public:
  Parser(std::span<const std::uint8_t> data, PeInfo& info) : d_(data), info_(info) {}

  // Parses everything after the section table. Never fails; only warns.
  void parse_directories(const std::array<DataDir, 16>& dirs) {
    dirs_ = dirs;
    parse_imports();
    parse_delay_imports();
    parse_exports();
    parse_clr();
    parse_manifest();
  }

  void warn(std::string msg) {
    if (info_.warnings.size() < kMaxWarnings) {
      info_.warnings.push_back(std::move(msg));
    } else if (info_.warnings.size() == kMaxWarnings) {
      info_.warnings.push_back("too many warnings; further warnings suppressed");
    }
  }

 private:
  std::span<const std::uint8_t> d_;
  PeInfo& info_;
  std::array<DataDir, 16> dirs_{};

  std::uint64_t fsize() const { return d_.size(); }

  // --- RVA mapping -------------------------------------------------------

  Mapping map(std::uint64_t rva) const {
    for (const Section& s : info_.sections) {
      const std::uint64_t span = std::max<std::uint64_t>(s.virtual_size, s.raw_size);
      if (rva < s.virtual_address) continue;
      const std::uint64_t rel = rva - s.virtual_address;
      if (rel >= span) continue;
      // The loader rounds PointerToRawData down to the sector size.
      const std::uint64_t raw = s.raw_offset & ~std::uint64_t{0x1FF};
      if (rel >= s.raw_size) return {};  // zero-filled tail: nothing in the file
      const std::uint64_t off = raw + rel;
      if (off >= fsize()) return {};
      return {true, off, std::min<std::uint64_t>(s.raw_size - rel, fsize() - off)};
    }
    // Headers are mapped at RVA 0.
    const std::uint64_t hdr = std::min<std::uint64_t>(info_.size_of_headers, fsize());
    if (rva < hdr) return {true, rva, hdr - rva};
    return {};
  }

  const std::uint8_t* bytes_at(std::uint64_t rva, std::uint64_t len) const {
    const Mapping m = map(rva);
    if (!m.valid || len > m.avail) return nullptr;
    return d_.data() + m.offset;
  }

  bool u16_at(std::uint64_t rva, std::uint16_t& out) const {
    const std::uint8_t* p = bytes_at(rva, 2);
    if (!p) return false;
    out = le16(p);
    return true;
  }

  bool u32_at(std::uint64_t rva, std::uint32_t& out) const {
    const std::uint8_t* p = bytes_at(rva, 4);
    if (!p) return false;
    out = le32(p);
    return true;
  }

  bool u64_at(std::uint64_t rva, std::uint64_t& out) const {
    const std::uint8_t* p = bytes_at(rva, 8);
    if (!p) return false;
    out = le64(p);
    return true;
  }

  // Reads a NUL-terminated string. Returns false if nothing is readable.
  bool cstr_at(std::uint64_t rva, std::string& out, const char* what) {
    out.clear();
    const Mapping m = map(rva);
    if (!m.valid || m.avail == 0) return false;
    const std::uint64_t limit = std::min<std::uint64_t>(m.avail, kMaxStringLength);
    const char* p = reinterpret_cast<const char*>(d_.data() + m.offset);
    const void* nul = std::memchr(p, 0, static_cast<std::size_t>(limit));
    if (nul) {
      out.assign(p, static_cast<const char*>(nul));
      return true;
    }
    out.assign(p, static_cast<std::size_t>(limit));
    if (limit == kMaxStringLength) {
      warn(std::string(what) + ": string longer than " + std::to_string(kMaxStringLength) +
           " bytes was truncated");
    } else {
      warn(std::string(what) + ": string is not NUL-terminated within the file");
    }
    return true;
  }

  // --- Imports -----------------------------------------------------------

  // Walks one import lookup table. `va_mode` means entries hold virtual
  // addresses rather than RVAs (legacy delay-load descriptors).
  void read_thunks(ImportedDll& dll, std::uint64_t table_rva, bool va_mode) {
    const std::uint64_t esize = info_.pe32_plus ? 8 : 4;
    for (std::uint32_t i = 0; i < kMaxFunctionsPerDll + 1; ++i) {
      if (i == kMaxFunctionsPerDll) {
        warn("imports of " + dll.name + ": more than " + std::to_string(kMaxFunctionsPerDll) +
             " functions; list truncated");
        return;
      }
      const std::uint64_t at = table_rva + i * esize;
      std::uint64_t v = 0;
      if (info_.pe32_plus) {
        if (!u64_at(at, v)) {
          warn("imports of " + dll.name + ": thunk table runs past mapped data");
          return;
        }
      } else {
        std::uint32_t v32 = 0;
        if (!u32_at(at, v32)) {
          warn("imports of " + dll.name + ": thunk table runs past mapped data");
          return;
        }
        v = v32;
      }
      if (v == 0) return;

      ImportedFunction fn;
      const std::uint64_t ordinal_flag = info_.pe32_plus ? (1ull << 63) : (1ull << 31);
      if (v & ordinal_flag) {
        fn.by_ordinal = true;
        fn.ordinal = static_cast<std::uint16_t>(v & 0xFFFF);
        dll.functions.push_back(std::move(fn));
        continue;
      }
      if (v > 0x7FFFFFFFull) {
        warn("imports of " + dll.name + ": bad hint/name RVA");
        continue;
      }
      std::uint64_t name_rva = v;
      if (va_mode && !va_to_rva(v, name_rva)) {
        warn("imports of " + dll.name + ": bad hint/name address");
        continue;
      }
      std::uint16_t hint = 0;
      std::string name;
      if (!u16_at(name_rva, hint) || !cstr_at(name_rva + 2, name, "import name")) {
        warn("imports of " + dll.name + ": hint/name entry is outside the file");
        continue;
      }
      fn.hint = hint;
      fn.name = std::move(name);
      dll.functions.push_back(std::move(fn));
    }
  }

  bool va_to_rva(std::uint64_t va, std::uint64_t& rva) const {
    if (va < info_.image_base) return false;
    rva = va - info_.image_base;
    return rva <= std::numeric_limits<std::uint32_t>::max();
  }

  void parse_imports() {
    const DataDir dir = dirs_[kDirImport];
    if (dir.rva == 0) return;
    for (std::uint32_t i = 0; i <= kMaxImportedDlls; ++i) {
      if (i == kMaxImportedDlls) {
        warn("more than " + std::to_string(kMaxImportedDlls) + " imported DLLs; list truncated");
        return;
      }
      const std::uint64_t at = std::uint64_t{dir.rva} + std::uint64_t{i} * 20;
      const std::uint8_t* p = bytes_at(at, 20);
      if (!p) {
        warn("import directory is cut off or points outside the file");
        return;
      }
      const std::uint32_t oft = le32(p), name_rva = le32(p + 12), ft = le32(p + 16);
      if (oft == 0 && name_rva == 0 && ft == 0 && le32(p + 4) == 0 && le32(p + 8) == 0) return;
      ImportedDll dll;
      if (name_rva == 0 || !cstr_at(name_rva, dll.name, "import DLL name")) {
        warn("import descriptor " + std::to_string(i) + " has an invalid DLL name RVA");
        continue;
      }
      const std::uint32_t table = oft != 0 ? oft : ft;
      if (table != 0) read_thunks(dll, table, false);
      info_.imports.push_back(std::move(dll));
    }
  }

  void parse_delay_imports() {
    const DataDir dir = dirs_[kDirDelayImport];
    if (dir.rva == 0) return;
    for (std::uint32_t i = 0; i <= kMaxImportedDlls; ++i) {
      if (i == kMaxImportedDlls) {
        warn("more than " + std::to_string(kMaxImportedDlls) + " delay-load DLLs; list truncated");
        return;
      }
      const std::uint64_t at = std::uint64_t{dir.rva} + std::uint64_t{i} * 32;
      const std::uint8_t* p = bytes_at(at, 32);
      if (!p) {
        warn("delay-load import directory is cut off or points outside the file");
        return;
      }
      const std::uint32_t attrs = le32(p);
      std::uint64_t name_rva = le32(p + 4);
      std::uint64_t int_rva = le32(p + 16);
      if (name_rva == 0) return;
      const bool va_mode = (attrs & 1) == 0;
      if (va_mode) {
        std::uint64_t n = 0, t = 0;
        if (!va_to_rva(name_rva, n) || (int_rva != 0 && !va_to_rva(int_rva, t))) {
          warn("delay-load descriptor " + std::to_string(i) + " has invalid virtual addresses");
          continue;
        }
        name_rva = n;
        int_rva = int_rva != 0 ? t : 0;
      }
      ImportedDll dll;
      dll.delay_load = true;
      if (!cstr_at(name_rva, dll.name, "delay-load DLL name")) {
        warn("delay-load descriptor " + std::to_string(i) + " has an invalid DLL name RVA");
        continue;
      }
      if (int_rva != 0) read_thunks(dll, int_rva, va_mode);
      info_.imports.push_back(std::move(dll));
    }
  }

  // --- Exports -----------------------------------------------------------

  void parse_exports() {
    const DataDir dir = dirs_[kDirExport];
    if (dir.rva == 0) return;
    const std::uint8_t* h = bytes_at(dir.rva, 40);
    if (!h) {
      warn("export directory is cut off or points outside the file");
      return;
    }
    const std::uint32_t name_rva = le32(h + 12);
    const std::uint32_t base = le32(h + 16);
    std::uint32_t nfuncs = le32(h + 20);
    std::uint32_t nnames = le32(h + 24);
    const std::uint32_t funcs_rva = le32(h + 28);
    const std::uint32_t names_rva = le32(h + 32);
    const std::uint32_t ords_rva = le32(h + 36);

    if (name_rva != 0) cstr_at(name_rva, info_.export_name, "export DLL name");
    if (nfuncs > kMaxExports) {
      warn("export directory lists " + std::to_string(nfuncs) + " functions; capped at " +
           std::to_string(kMaxExports));
      nfuncs = kMaxExports;
    }
    if (nnames > kMaxExports) {
      warn("export directory lists " + std::to_string(nnames) + " names; capped at " +
           std::to_string(kMaxExports));
      nnames = kMaxExports;
    }
    if (nfuncs == 0) return;

    const std::uint8_t* funcs = bytes_at(funcs_rva, std::uint64_t{nfuncs} * 4);
    if (!funcs) {
      warn("export address table is cut off or points outside the file");
      return;
    }
    const std::uint8_t* names = nullptr;
    const std::uint8_t* ords = nullptr;
    if (nnames != 0) {
      names = bytes_at(names_rva, std::uint64_t{nnames} * 4);
      ords = bytes_at(ords_rva, std::uint64_t{nnames} * 2);
      if (!names || !ords) {
        warn("export name/ordinal table is cut off or points outside the file");
        names = ords = nullptr;
        nnames = 0;
      }
    }

    std::vector<std::vector<std::string>> by_index(nfuncs);
    for (std::uint32_t i = 0; i < nnames; ++i) {
      const std::uint16_t idx = le16(ords + std::size_t{i} * 2);
      if (idx >= nfuncs) {
        warn("export ordinal index out of range");
        continue;
      }
      std::string nm;
      if (!cstr_at(le32(names + std::size_t{i} * 4), nm, "export name")) {
        warn("export name RVA is outside the file");
        continue;
      }
      by_index[idx].push_back(std::move(nm));
    }

    const std::uint64_t dir_end = std::uint64_t{dir.rva} + dir.size;
    for (std::uint32_t i = 0; i < nfuncs; ++i) {
      const std::uint32_t frva = le32(funcs + std::size_t{i} * 4);
      if (frva == 0) continue;  // unused slot
      std::string fwd;
      if (frva >= dir.rva && frva < dir_end) {
        if (!cstr_at(frva, fwd, "export forwarder")) warn("export forwarder RVA is outside the file");
      }
      const std::uint32_t ordinal = base + i;
      if (by_index[i].empty()) {
        ExportedFunction e;
        e.ordinal = ordinal;
        e.forwarder = fwd;
        info_.exports.push_back(std::move(e));
      }
      for (std::string& nm : by_index[i]) {
        ExportedFunction e;
        e.name = std::move(nm);
        e.ordinal = ordinal;
        e.forwarder = fwd;
        info_.exports.push_back(std::move(e));
      }
    }
  }

  // --- CLR ---------------------------------------------------------------

  void parse_clr() {
    const DataDir dir = dirs_[kDirClr];
    if (dir.rva == 0) return;
    const std::uint8_t* h = bytes_at(dir.rva, 20);
    if (!h) {
      warn("CLR header is cut off or points outside the file");
      return;
    }
    ClrInfo clr;
    clr.major_runtime_version = le16(h + 4);
    clr.minor_runtime_version = le16(h + 6);
    clr.flags = le32(h + 16);
    const std::uint32_t md_rva = le32(h + 8);
    const std::uint32_t md_size = le32(h + 12);
    const std::uint8_t* m = md_rva != 0 ? bytes_at(md_rva, 16) : nullptr;
    if (!m || le32(m) != 0x424A5342u) {
      warn("CLR metadata root is missing or has a bad signature");
    } else {
      std::uint64_t len = le32(m + 12);
      const Mapping vm = map(std::uint64_t{md_rva} + 16);
      if (!vm.valid) {
        warn("CLR metadata version string is outside the file");
      } else {
        if (len > kMaxStringLength) len = kMaxStringLength;
        if (md_size != 0 && len > md_size) len = md_size;
        len = std::min<std::uint64_t>(len, vm.avail);
        const char* p = reinterpret_cast<const char*>(d_.data() + vm.offset);
        const void* nul = len ? std::memchr(p, 0, static_cast<std::size_t>(len)) : nullptr;
        const std::size_t n = nul ? static_cast<std::size_t>(static_cast<const char*>(nul) - p)
                                  : static_cast<std::size_t>(len);
        clr.metadata_version.assign(p, n);
      }
    }
    info_.clr = std::move(clr);
  }

  // --- Manifest ----------------------------------------------------------

  struct ResEntry {
    std::uint32_t name = 0;  // id, or name-offset|0x80000000
    std::uint32_t offset = 0;
    bool is_dir() const { return (offset & 0x80000000u) != 0; }
    bool is_id() const { return (name & 0x80000000u) == 0; }
    std::uint32_t target() const { return offset & 0x7FFFFFFFu; }
  };

  // Reads the entries of the resource directory at `res_rva + dir_off`.
  bool res_entries(std::uint32_t dir_off, std::vector<ResEntry>& out) {
    out.clear();
    const std::uint64_t base = std::uint64_t{dirs_[kDirResource].rva} + dir_off;
    const std::uint8_t* h = bytes_at(base, 16);
    if (!h) return false;
    std::uint32_t count = std::uint32_t{le16(h + 12)} + le16(h + 14);
    if (count > kMaxResourceEntries) {
      warn("resource directory has too many entries; capped");
      count = kMaxResourceEntries;
    }
    const std::uint8_t* e = count ? bytes_at(base + 16, std::uint64_t{count} * 8) : nullptr;
    if (count && !e) {
      warn("resource directory entries run past mapped data");
      return false;
    }
    for (std::uint32_t i = 0; i < count; ++i) {
      out.push_back({le32(e + std::size_t{i} * 8), le32(e + std::size_t{i} * 8 + 4)});
    }
    return true;
  }

  void parse_manifest() {
    const DataDir dir = dirs_[kDirResource];
    if (dir.rva == 0) return;
    std::vector<ResEntry> level;
    // Depth 0: resource types.
    if (!res_entries(0, level)) {
      warn("resource directory is cut off or points outside the file");
      return;
    }
    const ResEntry* type = nullptr;
    for (const ResEntry& e : level) {
      if (e.is_id() && e.name == 24 && e.is_dir()) {
        type = &e;
        break;
      }
    }
    if (!type) return;
    // Depth 1: resource ids. Prefer 1, then 2, else the first.
    std::vector<ResEntry> ids;
    if (!res_entries(type->target(), ids) || ids.empty()) {
      warn("manifest resource directory is unreadable");
      return;
    }
    const ResEntry* pick = nullptr;
    for (const std::uint32_t want : {1u, 2u}) {
      for (const ResEntry& e : ids) {
        if (e.is_id() && e.name == want) {
          pick = &e;
          break;
        }
      }
      if (pick) break;
    }
    if (!pick) pick = &ids.front();
    if (!pick->is_dir()) {
      warn("manifest resource entry is not a directory");
      return;
    }
    // Depth 2: languages. Take the first.
    std::vector<ResEntry> langs;
    if (!res_entries(pick->target(), langs) || langs.empty()) {
      warn("manifest language directory is unreadable");
      return;
    }
    const ResEntry& leaf = langs.front();
    if (leaf.is_dir()) {
      warn("manifest resource tree is deeper than expected");
      return;
    }
    const std::uint8_t* de = bytes_at(std::uint64_t{dir.rva} + leaf.target(), 16);
    if (!de) {
      warn("manifest data entry is outside the file");
      return;
    }
    const std::uint32_t data_rva = le32(de);
    std::uint64_t size = le32(de + 4);
    if (size == 0) return;
    if (size > kMaxManifestBytes) {
      warn("manifest larger than 1 MB; truncated");
      size = kMaxManifestBytes;
    }
    const Mapping m = map(data_rva);
    if (!m.valid) {
      warn("manifest data is outside the file");
      return;
    }
    if (size > m.avail) {
      warn("manifest data is cut off by end of file/section");
      size = m.avail;
    }
    const char* p = reinterpret_cast<const char*>(d_.data() + m.offset);
    std::string_view text(p, static_cast<std::size_t>(size));
    if (text.size() >= 3 && static_cast<std::uint8_t>(text[0]) == 0xEF &&
        static_cast<std::uint8_t>(text[1]) == 0xBB && static_cast<std::uint8_t>(text[2]) == 0xBF) {
      text.remove_prefix(3);
    }
    info_.manifest.assign(text);
  }
};

ParseResult parse_impl(std::span<const std::uint8_t> data) {
  const std::uint64_t size = data.size();
  if (size == 0) return fail(ParseError::Empty, "file is empty");
  if (size < 2 || data[0] != 'M' || data[1] != 'Z') {
    return fail(ParseError::NotMz, "missing MZ signature");
  }
  if (size < 0x40) return fail(ParseError::Truncated, "DOS header is cut off");
  const std::uint64_t pe_off = le32(data.data() + 0x3C);
  if (pe_off > size || size - pe_off < 4) {
    return fail(ParseError::BadPeOffset, "e_lfanew (" + std::to_string(pe_off) + ") points outside the file");
  }
  if (std::memcmp(data.data() + pe_off, "PE\0\0", 4) != 0) {
    return fail(ParseError::NotPe, "missing PE signature (not a PE image)");
  }
  const std::uint64_t fh = pe_off + 4;
  if (size - fh < 20) return fail(ParseError::Truncated, "COFF file header is cut off");
  const std::uint8_t* f = data.data() + fh;
  PeInfo info;
  info.file_size = size;
  info.machine = static_cast<Machine>(le16(f));
  std::uint32_t nsections = le16(f + 2);
  const std::uint32_t opt_size = le16(f + 16);
  info.characteristics = le16(f + 18);
  info.is_dll = (info.characteristics & 0x2000) != 0;

  const std::uint64_t oh = fh + 20;
  if (size - std::min(size, oh) < 2) return fail(ParseError::Truncated, "optional header is cut off");
  const std::uint16_t magic = le16(data.data() + oh);
  if (magic != kMagicPe32 && magic != kMagicPe32Plus) {
    return fail(ParseError::BadOptionalHeader, "unknown optional header magic");
  }
  info.pe32_plus = magic == kMagicPe32Plus;
  const std::uint32_t fixed = info.pe32_plus ? 112 : 96;
  if (opt_size < fixed) {
    return fail(ParseError::BadOptionalHeader, "SizeOfOptionalHeader (" + std::to_string(opt_size) + ") is too small");
  }
  if (size - oh < opt_size) return fail(ParseError::Truncated, "optional header is cut off");
  const std::uint8_t* o = data.data() + oh;
  info.entry_point_rva = le32(o + 16);
  info.image_base = info.pe32_plus ? le64(o + 24) : le32(o + 28);
  info.major_subsystem_version = le16(o + 48);
  info.minor_subsystem_version = le16(o + 50);
  info.size_of_image = le32(o + 56);
  info.size_of_headers = le32(o + 60);
  info.subsystem = le16(o + 68);
  info.dll_characteristics = le16(o + 70);

  std::array<DataDir, 16> dirs{};
  std::uint32_t ndirs = le32(o + (info.pe32_plus ? 108 : 92));
  ndirs = std::min({ndirs, 16u, (opt_size - fixed) / 8});
  for (std::uint32_t i = 0; i < ndirs; ++i) {
    dirs[i].rva = le32(o + fixed + std::size_t{i} * 8);
    dirs[i].size = le32(o + fixed + std::size_t{i} * 8 + 4);
  }

  // Section table.
  Parser parser(data, info);
  if (nsections > kMaxSections) {
    parser.warn("file declares " + std::to_string(nsections) + " sections; only the first " +
                std::to_string(kMaxSections) + " are read");
    nsections = kMaxSections;
  }
  const std::uint64_t st = oh + opt_size;
  if (st > size || size - st < std::uint64_t{nsections} * 40) {
    return fail(ParseError::Truncated, "section table is cut off");
  }
  for (std::uint32_t i = 0; i < nsections; ++i) {
    const std::uint8_t* s = data.data() + st + std::size_t{i} * 40;
    Section sec;
    std::size_t n = 0;
    while (n < 8 && s[n] != 0) ++n;
    sec.name.assign(reinterpret_cast<const char*>(s), n);
    sec.virtual_size = le32(s + 8);
    sec.virtual_address = le32(s + 12);
    sec.raw_size = le32(s + 16);
    sec.raw_offset = le32(s + 20);
    sec.characteristics = le32(s + 36);
    const std::uint64_t raw = sec.raw_offset & ~std::uint64_t{0x1FF};
    if (sec.raw_size != 0 && raw < size) {
      const std::uint64_t len = std::min<std::uint64_t>(sec.raw_size, size - raw);
      sec.entropy = shannon_entropy(data.data() + raw, len);
    }
    info.sections.push_back(std::move(sec));
  }

  // File-level observations.
  std::uint64_t max_end = 0;
  bool any_raw = false;
  for (const Section& s : info.sections) {
    if (s.raw_size == 0) continue;
    const std::uint64_t end = std::uint64_t{s.raw_offset} + s.raw_size;
    any_raw = true;
    max_end = std::max(max_end, end);
    if (end > size) info.truncated = true;
  }
  if (!any_raw) max_end = info.size_of_headers;
  info.overlay_size = (!info.truncated && size > max_end) ? size - max_end : 0;

  parser.parse_directories(dirs);
  ParseResult r;
  r.info = std::move(info);
  return r;
}

}  // namespace

const char* machine_name(Machine m) {
  switch (m) {
    case Machine::I386: return "x86";
    case Machine::AMD64: return "x64";
    case Machine::ARM64: return "arm64";
    case Machine::ARMNT: return "arm";
    case Machine::IA64: return "ia64";
    case Machine::Unknown: break;
  }
  return "unknown";
}

const char* parse_error_name(ParseError e) {
  switch (e) {
    case ParseError::None: return "None";
    case ParseError::IoError: return "IoError";
    case ParseError::Empty: return "Empty";
    case ParseError::NotMz: return "NotMz";
    case ParseError::BadPeOffset: return "BadPeOffset";
    case ParseError::NotPe: return "NotPe";
    case ParseError::BadOptionalHeader: return "BadOptionalHeader";
    case ParseError::Truncated: return "Truncated";
  }
  return "Unknown";
}

std::string to_lower_ascii(std::string_view s) {
  std::string out(s);
  for (char& c : out) {
    if (c >= 'A' && c <= 'Z') c = static_cast<char>(c - 'A' + 'a');
  }
  return out;
}

bool PeInfo::has_import(std::string_view dll_name) const {
  const std::string want = to_lower_ascii(dll_name);
  for (const ImportedDll& d : imports) {
    if (to_lower_ascii(d.name) == want) return true;
  }
  return false;
}

ParseResult parse(std::span<const std::uint8_t> data) {
  try {
    return parse_impl(data);
  } catch (const std::exception& e) {
    return fail(ParseError::IoError, std::string("internal error while parsing: ") + e.what());
  }
}

ParseResult parse_file(const std::filesystem::path& path, std::uint64_t max_bytes) {
  try {
    std::error_code ec;
    if (std::filesystem::is_directory(path, ec)) return fail(ParseError::IoError, "path is a directory");
    std::ifstream f(path, std::ios::binary);
    if (!f) return fail(ParseError::IoError, "cannot open file");
    f.seekg(0, std::ios::end);
    const std::streamoff end = f.tellg();
    if (end < 0) return fail(ParseError::IoError, "cannot determine file size");
    f.seekg(0, std::ios::beg);
    const std::uint64_t total = static_cast<std::uint64_t>(end);
    const std::uint64_t want = std::min(total, max_bytes);
    std::vector<std::uint8_t> buf(static_cast<std::size_t>(want));
    if (want != 0) {
      f.read(reinterpret_cast<char*>(buf.data()), static_cast<std::streamsize>(want));
      if (f.bad()) return fail(ParseError::IoError, "read error");
      buf.resize(static_cast<std::size_t>(f.gcount()));
    }
    ParseResult r = parse(buf);
    if (r.info && total > want) {
      r.info->file_size = total;
      r.info->warnings.push_back("file is larger than the analysis limit; only the first " +
                                 std::to_string(want) + " bytes were read");
    }
    return r;
  } catch (const std::exception& e) {
    return fail(ParseError::IoError, std::string("cannot read file: ") + e.what());
  }
}

}  // namespace neden::pe
