// In-memory PE image builder for tests. Produces structurally valid (but not
// runnable) PE32 / PE32+ images with imports, delay imports, exports, a CLR
// header and an embedded manifest.
//
//   neden_test::PeBuilder b;
//   b.machine = neden::pe::Machine::AMD64;
//   b.imports = {{"KERNEL32.dll", {"ExitProcess", "#12"}}};
//   auto bytes = b.build();
//
// Export entries: "Name", "Name=OTHER.Target" (forwarder), "#" (ordinal-only
// slot), or "#=OTHER.Target" (unnamed forwarder).
#pragma once

#include <algorithm>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <optional>
#include <string>
#include <utility>
#include <vector>

#include "neden/pe.h"

namespace neden_test {

using DllImports = std::vector<std::pair<std::string, std::vector<std::string>>>;

struct PeBuilder {
  neden::pe::Machine machine = neden::pe::Machine::I386;  // PE32 for I386/ARMNT, PE32+ otherwise
  bool dll = false;
  std::uint16_t subsystem = 3;  // console
  DllImports imports;           // dll -> function names ("#12" = by ordinal 12)
  DllImports delay_imports;
  std::string export_name;
  std::vector<std::string> exports;
  std::uint32_t export_base = 1;
  std::optional<std::string> clr_metadata_version;
  std::uint32_t clr_flags = 1;
  std::string manifest;  // RT_MANIFEST id 1 when non-empty

  bool is_pe32_plus() const {
    return machine != neden::pe::Machine::I386 && machine != neden::pe::Machine::ARMNT;
  }

  std::vector<std::uint8_t> build() const;
};

inline bool write_file(const std::filesystem::path& path, const std::vector<std::uint8_t>& bytes) {
  std::ofstream f(path, std::ios::binary | std::ios::trunc);
  if (!f) return false;
  f.write(reinterpret_cast<const char*>(bytes.data()), static_cast<std::streamsize>(bytes.size()));
  return static_cast<bool>(f);
}

namespace detail {

using Bytes = std::vector<std::uint8_t>;

inline void put16(Bytes& b, std::size_t at, std::uint16_t v) {
  b[at] = static_cast<std::uint8_t>(v);
  b[at + 1] = static_cast<std::uint8_t>(v >> 8);
}
inline void put32(Bytes& b, std::size_t at, std::uint32_t v) {
  for (int i = 0; i < 4; ++i) b[at + i] = static_cast<std::uint8_t>(v >> (8 * i));
}
inline void put64(Bytes& b, std::size_t at, std::uint64_t v) {
  for (int i = 0; i < 8; ++i) b[at + i] = static_cast<std::uint8_t>(v >> (8 * i));
}
inline std::uint32_t align_up(std::uint32_t v, std::uint32_t a) { return (v + a - 1) / a * a; }

// Append-only data blob that lives at a known RVA.
struct Blob {
  std::uint32_t base_rva;
  Bytes data;

  explicit Blob(std::uint32_t rva) : base_rva(rva) {}
  std::uint32_t here() const { return base_rva + static_cast<std::uint32_t>(data.size()); }
  void pad(std::size_t a) {
    while (data.size() % a) data.push_back(0);
  }
  // Reserves zeroed space and returns its RVA.
  std::uint32_t reserve(std::size_t n) {
    const std::uint32_t rva = here();
    data.resize(data.size() + n, 0);
    return rva;
  }
  std::uint32_t string(const std::string& s) {
    const std::uint32_t rva = here();
    data.insert(data.end(), s.begin(), s.end());
    data.push_back(0);
    return rva;
  }
  void set32(std::uint32_t rva, std::uint32_t v) { put32(data, rva - base_rva, v); }
  void set16(std::uint32_t rva, std::uint16_t v) { put16(data, rva - base_rva, v); }
  void set64(std::uint32_t rva, std::uint64_t v) { put64(data, rva - base_rva, v); }
};

struct Dir {
  std::uint32_t rva = 0;
  std::uint32_t size = 0;
};

// Writes thunk tables + hint/name entries for one DLL; returns {ILT rva, IAT rva}.
inline std::pair<std::uint32_t, std::uint32_t> write_thunks(Blob& b, const std::vector<std::string>& fns,
                                                            bool plus) {
  const std::size_t esize = plus ? 8 : 4;
  b.pad(8);
  const std::uint32_t ilt = b.reserve((fns.size() + 1) * esize);
  const std::uint32_t iat = b.reserve((fns.size() + 1) * esize);
  for (std::size_t i = 0; i < fns.size(); ++i) {
    const std::string& f = fns[i];
    std::uint64_t value;
    if (!f.empty() && f[0] == '#') {
      const std::uint64_t ord = std::stoul(f.substr(1)) & 0xFFFF;
      value = ord | (plus ? (1ull << 63) : (1ull << 31));
    } else {
      b.pad(2);
      const std::uint32_t hn = b.reserve(2);
      b.set16(hn, static_cast<std::uint16_t>(i));  // hint
      b.string(f);
      value = hn;
    }
    const std::uint32_t at = static_cast<std::uint32_t>(i * esize);
    if (plus) {
      b.set64(ilt + at, value);
      b.set64(iat + at, value);
    } else {
      b.set32(ilt + at, static_cast<std::uint32_t>(value));
      b.set32(iat + at, static_cast<std::uint32_t>(value));
    }
  }
  return {ilt, iat};
}

inline Dir write_imports(Blob& b, const DllImports& list, bool plus) {
  if (list.empty()) return {};
  b.pad(4);
  const std::uint32_t table = b.reserve((list.size() + 1) * 20);
  for (std::size_t i = 0; i < list.size(); ++i) {
    const std::uint32_t name = b.string(list[i].first);
    const auto [ilt, iat] = write_thunks(b, list[i].second, plus);
    const std::uint32_t d = table + static_cast<std::uint32_t>(i * 20);
    b.set32(d, ilt);
    b.set32(d + 12, name);
    b.set32(d + 16, iat);
  }
  return {table, static_cast<std::uint32_t>((list.size() + 1) * 20)};
}

inline Dir write_delay_imports(Blob& b, const DllImports& list, bool plus) {
  if (list.empty()) return {};
  b.pad(4);
  const std::uint32_t table = b.reserve((list.size() + 1) * 32);
  for (std::size_t i = 0; i < list.size(); ++i) {
    const std::uint32_t name = b.string(list[i].first);
    b.pad(8);
    const std::uint32_t module = b.reserve(plus ? 8 : 4);
    const auto [ilt, iat] = write_thunks(b, list[i].second, plus);
    const std::uint32_t d = table + static_cast<std::uint32_t>(i * 32);
    b.set32(d, 1);  // attributes: RVAs
    b.set32(d + 4, name);
    b.set32(d + 8, module);
    b.set32(d + 12, iat);
    b.set32(d + 16, ilt);
  }
  return {table, static_cast<std::uint32_t>((list.size() + 1) * 32)};
}

inline Dir write_exports(Blob& b, const PeBuilder& pb) {
  if (pb.exports.empty() && pb.export_name.empty()) return {};
  b.pad(4);
  const std::uint32_t start = b.here();
  const std::size_t n = pb.exports.size();
  const std::uint32_t hdr = b.reserve(40);
  const std::uint32_t funcs = b.reserve(n * 4);
  struct Named {
    std::string name;
    std::uint16_t index;
  };
  std::vector<Named> named;
  std::vector<std::pair<std::string, bool>> bodies;  // forwarder text, is_forwarder
  for (std::size_t i = 0; i < n; ++i) {
    const std::string& e = pb.exports[i];
    const std::size_t eq = e.find('=');
    const std::string nm = e.substr(0, eq);
    if (!nm.empty() && nm[0] != '#') named.push_back({nm, static_cast<std::uint16_t>(i)});
    bodies.emplace_back(eq == std::string::npos ? std::string() : e.substr(eq + 1), eq != std::string::npos);
  }
  std::sort(named.begin(), named.end(), [](const Named& a, const Named& c) { return a.name < c.name; });
  const std::uint32_t names = b.reserve(named.size() * 4);
  const std::uint32_t ords = b.reserve(named.size() * 2);
  b.pad(4);
  const std::uint32_t dll_name = b.string(pb.export_name.empty() ? "test.dll" : pb.export_name);
  for (std::size_t i = 0; i < named.size(); ++i) {
    b.set32(names + static_cast<std::uint32_t>(i * 4), b.string(named[i].name));
    b.set16(ords + static_cast<std::uint32_t>(i * 2), named[i].index);
  }
  for (std::size_t i = 0; i < n; ++i) {
    // Forwarders point at a string inside the export directory; plain exports
    // point into .text.
    const std::uint32_t target = bodies[i].second ? b.string(bodies[i].first)
                                                  : 0x1000 + static_cast<std::uint32_t>(i) * 16;
    b.set32(funcs + static_cast<std::uint32_t>(i * 4), target);
  }
  b.set32(hdr + 12, dll_name);
  b.set32(hdr + 16, pb.export_base);
  b.set32(hdr + 20, static_cast<std::uint32_t>(n));
  b.set32(hdr + 24, static_cast<std::uint32_t>(named.size()));
  b.set32(hdr + 28, funcs);
  b.set32(hdr + 32, names);
  b.set32(hdr + 36, ords);
  return {start, b.here() - start};
}

inline Dir write_clr(Blob& b, const PeBuilder& pb) {
  if (!pb.clr_metadata_version) return {};
  b.pad(4);
  const std::uint32_t cor = b.reserve(72);
  b.pad(4);
  const std::uint32_t md = b.here();
  std::string ver = *pb.clr_metadata_version;
  ver.push_back('\0');
  while (ver.size() % 4) ver.push_back('\0');
  const std::uint32_t md_size = static_cast<std::uint32_t>(16 + ver.size() + 4);
  const std::uint32_t root = b.reserve(md_size);
  b.set32(root, 0x424A5342);
  b.set16(root + 4, 1);
  b.set16(root + 6, 1);
  b.set32(root + 12, static_cast<std::uint32_t>(ver.size()));
  std::copy(ver.begin(), ver.end(), b.data.begin() + (root + 16 - b.base_rva));
  b.set32(cor, 72);
  b.set16(cor + 4, 2);
  b.set16(cor + 6, 5);
  b.set32(cor + 8, md);
  b.set32(cor + 12, md_size);
  b.set32(cor + 16, pb.clr_flags);
  return {cor, 72};
}

// .rsrc: type dir -> id dir -> language dir -> data entry -> bytes.
inline Bytes build_rsrc(std::uint32_t rva, const std::string& manifest) {
  Blob b(rva);
  const std::uint32_t root = b.reserve(16 + 8);
  const std::uint32_t ids = b.reserve(16 + 8);
  const std::uint32_t langs = b.reserve(16 + 8);
  const std::uint32_t entry = b.reserve(16);
  const std::uint32_t data = b.here();
  b.data.insert(b.data.end(), manifest.begin(), manifest.end());
  b.set16(root + 14, 1);
  b.set32(root + 16, 24);
  b.set32(root + 20, 0x80000000u | (ids - rva));
  b.set16(ids + 14, 1);
  b.set32(ids + 16, 1);
  b.set32(ids + 20, 0x80000000u | (langs - rva));
  b.set16(langs + 14, 1);
  b.set32(langs + 16, 0x409);
  b.set32(langs + 20, entry - rva);
  b.set32(entry, data);
  b.set32(entry + 4, static_cast<std::uint32_t>(manifest.size()));
  return b.data;
}

}  // namespace detail

inline std::vector<std::uint8_t> PeBuilder::build() const {
  using namespace detail;
  constexpr std::uint32_t kFileAlign = 0x200, kSectAlign = 0x1000, kHeaders = 0x400;
  const bool plus = is_pe32_plus();

  // .rdata contents (RVA 0x2000).
  const std::uint32_t rdata_rva = 0x2000;
  Blob rdata(rdata_rva);
  rdata.reserve(16);  // keep RVA 0 style "empty" values away from real data
  Dir d_import = write_imports(rdata, imports, plus);
  Dir d_delay = write_delay_imports(rdata, delay_imports, plus);
  Dir d_export = write_exports(rdata, *this);
  Dir d_clr = write_clr(rdata, *this);
  rdata.pad(16);

  const std::uint32_t rdata_vsize = static_cast<std::uint32_t>(rdata.data.size());
  const std::uint32_t rsrc_rva = rdata_rva + align_up(rdata_vsize, kSectAlign);
  Bytes rsrc;
  if (!manifest.empty()) rsrc = build_rsrc(rsrc_rva, manifest);

  struct Sec {
    const char* name;
    std::uint32_t va, vsize;
    const Bytes* data;
    std::uint32_t chars;
  };
  Bytes text(0x40, 0xC3);  // a few `ret`s
  std::vector<Sec> secs;
  secs.push_back({".text", 0x1000, static_cast<std::uint32_t>(text.size()), &text, 0x60000020});
  secs.push_back({".rdata", rdata_rva, rdata_vsize, &rdata.data, 0x40000040});
  if (!rsrc.empty()) secs.push_back({".rsrc", rsrc_rva, static_cast<std::uint32_t>(rsrc.size()), &rsrc, 0x40000040});

  const std::uint32_t opt_size = plus ? 240 : 224;
  const std::uint32_t pe_off = 0x80;
  const std::uint32_t opt_off = pe_off + 4 + 20;
  const std::uint32_t sec_off = opt_off + opt_size;

  Bytes img(kHeaders, 0);
  img[0] = 'M';
  img[1] = 'Z';
  put32(img, 0x3C, pe_off);
  const char stub[] = "This program cannot be run in DOS mode.";
  std::copy(stub, stub + sizeof(stub) - 1, img.begin() + 0x4E);
  img[pe_off] = 'P';
  img[pe_off + 1] = 'E';
  put16(img, pe_off + 4, static_cast<std::uint16_t>(machine));
  put16(img, pe_off + 6, static_cast<std::uint16_t>(secs.size()));
  put16(img, pe_off + 4 + 16, static_cast<std::uint16_t>(opt_size));
  std::uint16_t chars = 0x0002 | (plus ? 0x0020 : 0x0100);
  if (dll) chars |= 0x2000;
  put16(img, pe_off + 4 + 18, chars);

  put16(img, opt_off, plus ? 0x20b : 0x10b);
  img[opt_off + 2] = 14;  // linker version
  put32(img, opt_off + 4, 0x200);   // SizeOfCode
  put32(img, opt_off + 16, 0x1000);  // entry point
  put32(img, opt_off + 20, 0x1000);  // BaseOfCode
  const std::uint32_t last_end = secs.back().va + align_up(secs.back().vsize, kSectAlign);
  if (plus) {
    put64(img, opt_off + 24, dll ? 0x180000000ull : 0x140000000ull);
  } else {
    put32(img, opt_off + 24, 0x2000);  // BaseOfData
    put32(img, opt_off + 28, dll ? 0x10000000u : 0x00400000u);
  }
  put32(img, opt_off + 32, kSectAlign);
  put32(img, opt_off + 36, kFileAlign);
  put16(img, opt_off + 40, 6);  // OS version
  put16(img, opt_off + 48, 6);  // subsystem version
  put32(img, opt_off + 56, last_end);
  put32(img, opt_off + 60, kHeaders);
  put16(img, opt_off + 68, subsystem);
  put16(img, opt_off + 70, 0x8140);  // dynamic base, NX, terminal server aware
  const std::uint32_t stack = plus ? 8 : 4;
  std::uint32_t o = opt_off + 72;
  for (const std::uint32_t v : {0x100000u, 0x1000u, 0x100000u, 0x1000u}) {
    if (stack == 8) put64(img, o, v); else put32(img, o, v);
    o += stack;
  }
  put32(img, o + 4, 16);  // NumberOfRvaAndSizes
  const std::uint32_t dirs = opt_off + (plus ? 112 : 96);
  auto set_dir = [&](std::size_t i, const Dir& d) {
    put32(img, dirs + static_cast<std::uint32_t>(i) * 8, d.rva);
    put32(img, dirs + static_cast<std::uint32_t>(i) * 8 + 4, d.size);
  };
  set_dir(0, d_export);
  set_dir(1, d_import);
  if (!rsrc.empty()) set_dir(2, {rsrc_rva, static_cast<std::uint32_t>(rsrc.size())});
  set_dir(13, d_delay);
  set_dir(14, d_clr);

  std::uint32_t raw = kHeaders;
  for (std::size_t i = 0; i < secs.size(); ++i) {
    const Sec& s = secs[i];
    const std::uint32_t raw_size = align_up(static_cast<std::uint32_t>(s.data->size()), kFileAlign);
    const std::uint32_t h = sec_off + static_cast<std::uint32_t>(i) * 40;
    for (std::size_t c = 0; s.name[c] && c < 8; ++c) img[h + c] = static_cast<std::uint8_t>(s.name[c]);
    put32(img, h + 8, s.vsize);
    put32(img, h + 12, s.va);
    put32(img, h + 16, raw_size);
    put32(img, h + 20, raw);
    put32(img, h + 36, s.chars);
    img.resize(static_cast<std::size_t>(raw) + raw_size, 0);
    std::copy(s.data->begin(), s.data->end(), img.begin() + raw);
    raw += raw_size;
  }
  return img;
}

}  // namespace neden_test
