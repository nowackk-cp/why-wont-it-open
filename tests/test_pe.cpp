#include <cstdint>
#include <filesystem>
#include <string>
#include <vector>

#include "neden/pe.h"
#include "pe_builder.h"
#include "test.h"

using neden::pe::Machine;
using neden::pe::ParseError;
using neden_test::PeBuilder;

namespace {

neden::pe::ParseResult parse_bytes(const std::vector<std::uint8_t>& b) { return neden::pe::parse(b); }

const neden::pe::ImportedDll* find_import(const neden::pe::PeInfo& info, const std::string& name, bool delay) {
  for (const auto& d : info.imports) {
    if (d.delay_load == delay && neden::pe::to_lower_ascii(d.name) == neden::pe::to_lower_ascii(name)) return &d;
  }
  return nullptr;
}

PeBuilder rich_builder(Machine m) {
  PeBuilder b;
  b.machine = m;
  b.imports = {{"KERNEL32.dll", {"ExitProcess", "GetLastError", "#12"}}, {"MSVCP140.dll", {"?foo@@YAXXZ"}}};
  b.delay_imports = {{"d3d9.dll", {"Direct3DCreate9"}}, {"oleaut32.dll", {"#2", "SysAllocString"}}};
  return b;
}

// Deterministic xorshift PRNG.
struct Rng {
  std::uint64_t s;
  std::uint64_t next() {
    s ^= s << 13;
    s ^= s >> 7;
    s ^= s << 17;
    return s;
  }
};

}  // namespace

TEST(pe_names) {
  CHECK(std::string(neden::pe::machine_name(Machine::I386)) == "x86");
  CHECK(std::string(neden::pe::machine_name(Machine::AMD64)) == "x64");
  CHECK(std::string(neden::pe::machine_name(Machine::ARM64)) == "arm64");
  CHECK(std::string(neden::pe::machine_name(Machine::ARMNT)) == "arm");
  CHECK(std::string(neden::pe::machine_name(Machine::IA64)) == "ia64");
  CHECK(std::string(neden::pe::machine_name(Machine::Unknown)) == "unknown");
  CHECK(std::string(neden::pe::parse_error_name(ParseError::NotMz)) == "NotMz");
  CHECK(neden::pe::to_lower_ascii("KeRnEl32.DLL") == "kernel32.dll");
}

TEST(pe_roundtrip_basic) {
  for (const Machine m : {Machine::I386, Machine::AMD64, Machine::ARM64, Machine::ARMNT}) {
    PeBuilder b = rich_builder(m);
    const auto img = b.build();
    const auto r = parse_bytes(img);
    REQUIRE(r.ok());
    const auto& i = *r.info;
    CHECK(i.machine == m);
    CHECK(i.pe32_plus == b.is_pe32_plus());
    CHECK(!i.is_dll);
    CHECK(i.subsystem == 3);
    CHECK(i.entry_point_rva == 0x1000);
    CHECK(i.size_of_headers == 0x400);
    CHECK(i.file_size == img.size());
    CHECK(!i.truncated);
    CHECK(i.overlay_size == 0);
    CHECK(i.sections.size() == 2);
    CHECK(i.sections[0].name == ".text");
    CHECK(i.sections[0].entropy >= 0.0 && i.sections[0].entropy < 1.0);
    CHECK(i.warnings.empty());
    CHECK(!i.clr.has_value());
    CHECK(i.manifest.empty());
    CHECK(i.exports.empty());
  }
}

TEST(pe_roundtrip_imports_x86_and_x64) {
  for (const Machine m : {Machine::I386, Machine::AMD64}) {
    const auto r = parse_bytes(rich_builder(m).build());
    REQUIRE(r.ok());
    const auto& i = *r.info;
    REQUIRE(i.imports.size() == 4);
    // Normal imports first, then delay imports.
    CHECK(!i.imports[0].delay_load);
    CHECK(!i.imports[1].delay_load);
    CHECK(i.imports[2].delay_load);
    CHECK(i.imports[3].delay_load);

    const auto* k = find_import(i, "kernel32.dll", false);
    REQUIRE(k != nullptr);
    CHECK(k->name == "KERNEL32.dll");
    REQUIRE(k->functions.size() == 3);
    CHECK(k->functions[0].name == "ExitProcess");
    CHECK(!k->functions[0].by_ordinal);
    CHECK(k->functions[0].hint == 0);
    CHECK(k->functions[1].name == "GetLastError");
    CHECK(k->functions[1].hint == 1);
    CHECK(k->functions[2].by_ordinal);
    CHECK(k->functions[2].ordinal == 12);
    CHECK(k->functions[2].name.empty());

    const auto* d3d = find_import(i, "D3D9.DLL", true);
    REQUIRE(d3d != nullptr);
    REQUIRE(d3d->functions.size() == 1);
    CHECK(d3d->functions[0].name == "Direct3DCreate9");
    CHECK(find_import(i, "d3d9.dll", false) == nullptr);

    const auto* ole = find_import(i, "oleaut32.dll", true);
    REQUIRE(ole != nullptr);
    REQUIRE(ole->functions.size() == 2);
    CHECK(ole->functions[0].by_ordinal && ole->functions[0].ordinal == 2);
    CHECK(ole->functions[1].name == "SysAllocString");

    CHECK(i.has_import("MSVCP140.DLL"));
    CHECK(i.has_import("d3d9.dll"));
    CHECK(!i.has_import("vcruntime140.dll"));
  }
}

TEST(pe_import_without_functions) {
  PeBuilder b;
  b.imports = {{"empty.dll", {}}};
  const auto r = parse_bytes(b.build());
  REQUIRE(r.ok());
  REQUIRE(r.info->imports.size() == 1);
  CHECK(r.info->imports[0].functions.empty());
}

TEST(pe_exports) {
  for (const Machine m : {Machine::I386, Machine::AMD64}) {
    PeBuilder b;
    b.machine = m;
    b.dll = true;
    b.export_name = "mylib.dll";
    b.export_base = 5;
    b.exports = {"Zeta", "Alpha", "#", "Fwd=NTDLL.RtlAllocateHeap", "#=api-ms-win-core-foo.Bar"};
    const auto r = parse_bytes(b.build());
    REQUIRE(r.ok());
    const auto& i = *r.info;
    CHECK(i.is_dll);
    CHECK(i.export_name == "mylib.dll");
    REQUIRE(i.exports.size() == 5);
    CHECK(i.exports[0].name == "Zeta");
    CHECK(i.exports[0].ordinal == 5);
    CHECK(i.exports[0].forwarder.empty());
    CHECK(i.exports[1].name == "Alpha");
    CHECK(i.exports[1].ordinal == 6);
    CHECK(i.exports[2].name.empty());
    CHECK(i.exports[2].ordinal == 7);
    CHECK(i.exports[2].forwarder.empty());
    CHECK(i.exports[3].name == "Fwd");
    CHECK(i.exports[3].ordinal == 8);
    CHECK(i.exports[3].forwarder == "NTDLL.RtlAllocateHeap");
    CHECK(i.exports[4].name.empty());
    CHECK(i.exports[4].forwarder == "api-ms-win-core-foo.Bar");
    CHECK(i.warnings.empty());
  }
}

TEST(pe_clr) {
  PeBuilder b;
  b.imports = {{"mscoree.dll", {"_CorExeMain"}}};
  b.clr_metadata_version = "v4.0.30319";
  b.clr_flags = 0x3;
  const auto r = parse_bytes(b.build());
  REQUIRE(r.ok());
  REQUIRE(r.info->clr.has_value());
  const auto& c = *r.info->clr;
  CHECK(c.metadata_version == "v4.0.30319");
  CHECK(c.major_runtime_version == 2);
  CHECK(c.minor_runtime_version == 5);
  CHECK(c.flags == 3);
  CHECK(c.il_only());
  CHECK(c.requires_32bit());
  CHECK(!c.prefers_32bit());
  CHECK(r.info->warnings.empty());

  b.clr_metadata_version = "v2.0.50727";
  b.clr_flags = 0x20003;
  const auto r2 = parse_bytes(b.build());
  REQUIRE(r2.ok() && r2.info->clr.has_value());
  CHECK(r2.info->clr->metadata_version == "v2.0.50727");
  CHECK(r2.info->clr->prefers_32bit());
}

TEST(pe_manifest) {
  PeBuilder b;
  b.machine = Machine::AMD64;
  const std::string xml = "<?xml version=\"1.0\"?><assembly><trustInfo/></assembly>";
  b.manifest = xml;
  const auto r = parse_bytes(b.build());
  REQUIRE(r.ok());
  CHECK(r.info->manifest == xml);
  CHECK(r.info->sections.size() == 3);
  CHECK(r.info->sections[2].name == ".rsrc");

  b.manifest = "\xEF\xBB\xBF" + xml;  // BOM is stripped
  const auto r2 = parse_bytes(b.build());
  REQUIRE(r2.ok());
  CHECK(r2.info->manifest == xml);
}

TEST(pe_everything_at_once) {
  PeBuilder b = rich_builder(Machine::AMD64);
  b.dll = true;
  b.export_name = "all.dll";
  b.exports = {"One", "Two"};
  b.clr_metadata_version = "v4.0.30319";
  b.manifest = "<assembly/>";
  const auto r = parse_bytes(b.build());
  REQUIRE(r.ok());
  CHECK(r.info->imports.size() == 4);
  CHECK(r.info->exports.size() == 2);
  CHECK(r.info->clr.has_value());
  CHECK(r.info->manifest == "<assembly/>");
  CHECK(r.info->warnings.empty());
}

TEST(pe_overlay) {
  auto img = rich_builder(Machine::I386).build();
  img.insert(img.end(), 1000, 0xAB);
  const auto r = parse_bytes(img);
  REQUIRE(r.ok());
  CHECK(r.info->overlay_size == 1000);
  CHECK(!r.info->truncated);
}

TEST(pe_error_empty_and_not_mz) {
  CHECK(parse_bytes({}).error == ParseError::Empty);
  CHECK(parse_bytes({'M'}).error == ParseError::NotMz);
  CHECK(parse_bytes({'Z', 'M', 0, 0}).error == ParseError::NotMz);
  CHECK(parse_bytes(std::vector<std::uint8_t>(100, 0x41)).error == ParseError::NotMz);
  CHECK(!parse_bytes({}).ok());
  CHECK(!parse_bytes({}).detail.empty());
}

TEST(pe_error_short_dos_header) {
  std::vector<std::uint8_t> v(0x30, 0);
  v[0] = 'M';
  v[1] = 'Z';
  CHECK(parse_bytes(v).error == ParseError::Truncated);
}

TEST(pe_error_bad_pe_offset) {
  auto img = rich_builder(Machine::I386).build();
  neden_test::detail::put32(img, 0x3C, static_cast<std::uint32_t>(img.size()));
  CHECK(parse_bytes(img).error == ParseError::BadPeOffset);
  neden_test::detail::put32(img, 0x3C, 0xFFFFFFFFu);
  CHECK(parse_bytes(img).error == ParseError::BadPeOffset);
  neden_test::detail::put32(img, 0x3C, static_cast<std::uint32_t>(img.size() - 2));
  CHECK(parse_bytes(img).error == ParseError::BadPeOffset);
}

TEST(pe_error_not_pe) {
  auto img = rich_builder(Machine::I386).build();
  img[0x80] = 'N';  // "NE\0\0"
  img[0x81] = 'E';
  const auto r = parse_bytes(img);
  CHECK(r.error == ParseError::NotPe);
  CHECK(!r.detail.empty());
}

TEST(pe_error_bad_optional_header) {
  auto img = rich_builder(Machine::I386).build();
  auto bad_magic = img;
  neden_test::detail::put16(bad_magic, 0x80 + 24, 0x107);
  CHECK(parse_bytes(bad_magic).error == ParseError::BadOptionalHeader);
  auto small = img;
  neden_test::detail::put16(small, 0x80 + 4 + 16, 40);
  CHECK(parse_bytes(small).error == ParseError::BadOptionalHeader);
}

TEST(pe_error_truncated_headers) {
  const auto img = rich_builder(Machine::AMD64).build();
  // Cut inside the COFF header, optional header and section table.
  for (const std::size_t len : {std::size_t{0x80 + 8}, std::size_t{0x80 + 24 + 1}, std::size_t{0x80 + 24 + 100},
                                std::size_t{0x80 + 24 + 240 + 10}}) {
    std::vector<std::uint8_t> cut(img.begin(), img.begin() + static_cast<std::ptrdiff_t>(len));
    const auto r = parse_bytes(cut);
    CHECK(r.error == ParseError::Truncated);
    CHECK(!r.detail.empty());
  }
}

TEST(pe_truncated_section_data) {
  auto img = rich_builder(Machine::I386).build();
  img.resize(img.size() - 0x100);
  const auto r = parse_bytes(img);
  REQUIRE(r.ok());
  CHECK(r.info->truncated);
  CHECK(r.info->overlay_size == 0);
  CHECK(r.info->file_size == img.size());
}

TEST(pe_cut_directory_data_warns_but_succeeds) {
  auto img = rich_builder(Machine::I386).build();
  img.resize(0x600 + 0x20);  // keep only the start of .rdata
  const auto r = parse_bytes(img);
  REQUIRE(r.ok());
  CHECK(r.info->truncated);
  CHECK(!r.info->warnings.empty());
}

TEST(pe_too_many_sections_is_capped) {
  auto img = rich_builder(Machine::I386).build();
  neden_test::detail::put16(img, 0x80 + 6, 5000);
  const auto r = parse_bytes(img);
  // Section table runs past the headers/file: structural failure, not UB.
  CHECK(!r.ok() || r.info->sections.size() <= 96);
}

TEST(pe_zero_sized_section_and_va_overlap) {
  auto img = rich_builder(Machine::I386).build();
  const std::size_t sec1 = 0x80 + 24 + 224 + 40;  // .rdata header
  neden_test::detail::put32(img, sec1 + 8, 0);    // virtual_size = 0
  const auto r = parse_bytes(img);
  REQUIRE(r.ok());
  CHECK(r.info->imports.size() == 4);  // raw_size is used instead
  neden_test::detail::put32(img, sec1 + 16, 0);  // raw_size = 0 too
  const auto r2 = parse_bytes(img);
  REQUIRE(r2.ok());  // data is simply unreachable
  CHECK(r2.info->imports.empty());
  CHECK(!r2.info->warnings.empty());
}

TEST(pe_random_corruption_does_not_crash) {
  PeBuilder b = rich_builder(Machine::AMD64);
  b.dll = true;
  b.export_name = "x.dll";
  b.exports = {"A", "B", "C=KERNEL32.Foo"};
  b.clr_metadata_version = "v4.0.30319";
  b.manifest = "<assembly/>";
  const auto img64 = b.build();
  b.machine = Machine::I386;
  const auto img32 = b.build();
  Rng rng{0x9E3779B97F4A7C15ull};
  int parsed_ok = 0;
  for (int iter = 0; iter < 6000; ++iter) {
    auto img = (iter & 1) ? img32 : img64;
    const int edits = 1 + static_cast<int>(rng.next() % 4);
    for (int e = 0; e < edits; ++e) {
      // Concentrate on the headers and directory data, where it matters.
      const std::size_t pos = (rng.next() % 3 == 0) ? rng.next() % img.size() : rng.next() % 0x700 + 0;
      if (pos >= img.size()) continue;
      switch (rng.next() % 4) {
        case 0: img[pos] = static_cast<std::uint8_t>(rng.next()); break;
        case 1: img[pos] = 0xFF; break;
        case 2: img[pos] = 0; break;
        default: img[pos] ^= static_cast<std::uint8_t>(1u << (rng.next() % 8)); break;
      }
    }
    if (rng.next() % 8 == 0) img.resize(rng.next() % img.size());
    const auto r = neden::pe::parse(img);
    if (r.ok()) ++parsed_ok;
  }
  CHECK(parsed_ok > 0);
}

TEST(pe_parse_file_errors_and_roundtrip) {
  namespace fs = std::filesystem;
  CHECK(neden::pe::parse_file(fs::temp_directory_path() / "neden_no_such_file.exe").error == ParseError::IoError);
  CHECK(neden::pe::parse_file(fs::temp_directory_path()).error == ParseError::IoError);

  const fs::path p = fs::temp_directory_path() / L"neden_test_\u00e9\u011f.exe";  // Unicode name
  REQUIRE(neden_test::write_file(p, rich_builder(Machine::I386).build()));
  const auto r = neden::pe::parse_file(p);
  CHECK(r.ok());
  CHECK(r.ok() && r.info->has_import("kernel32.dll"));

  REQUIRE(neden_test::write_file(p, {}));
  CHECK(neden::pe::parse_file(p).error == ParseError::Empty);
  std::error_code ec;
  fs::remove(p, ec);
}

TEST(pe_real_system_files) {
  namespace fs = std::filesystem;
  const fs::path k32 = "C:\\Windows\\System32\\kernel32.dll";
  if (fs::exists(k32)) {
    const auto r = neden::pe::parse_file(k32);
    REQUIRE(r.ok());
    CHECK(r.info->is_dll);
    CHECK(r.info->exports.size() > 500);
    CHECK(!r.info->sections.empty());
    CHECK(r.info->has_import("ntdll.dll") || !r.info->imports.empty());
    bool saw_forwarder = false;
    for (const auto& e : r.info->exports) saw_forwarder |= !e.forwarder.empty();
    CHECK(saw_forwarder);
  }
  const fs::path wow = "C:\\Windows\\SysWOW64\\kernel32.dll";
  if (fs::exists(wow)) {
    const auto r = neden::pe::parse_file(wow);
    REQUIRE(r.ok());
    CHECK(r.info->machine == Machine::I386);
    CHECK(!r.info->pe32_plus);
    CHECK(r.info->is_dll);
  }
  const fs::path sysnative = "C:\\Windows\\Sysnative\\kernel32.dll";
  if (fs::exists(sysnative)) {
    const auto r = neden::pe::parse_file(sysnative);
    REQUIRE(r.ok());
    CHECK(r.info->machine == Machine::AMD64);
    CHECK(r.info->pe32_plus);
  }
}
