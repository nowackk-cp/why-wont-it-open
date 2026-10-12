// Writes a handful of small, valid PE images (via tests/pe_builder.h) as fuzz seeds.
// Usage: gen_seeds <output dir>
#include <cstdio>
#include <filesystem>

#include "pe_builder.h"

int main(int argc, char** argv) {
  if (argc < 2) {
    std::fputs("usage: gen_seeds <output dir>\n", stderr);
    return 1;
  }
  const std::filesystem::path out = argv[1];
  std::filesystem::create_directories(out);
  using neden::pe::Machine;

  neden_test::PeBuilder exe32;
  exe32.imports = {{"KERNEL32.dll", {"ExitProcess", "#12"}}, {"MSVCP140.dll", {"?x@@YAXXZ"}}};
  exe32.delay_imports = {{"d3d9.dll", {"Direct3DCreate9"}}};
  exe32.manifest = "<assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\"/>";

  neden_test::PeBuilder dll64;
  dll64.machine = Machine::AMD64;
  dll64.dll = true;
  dll64.export_name = "lib.dll";
  dll64.exports = {"Alpha", "Beta", "#", "Fwd=NTDLL.RtlAllocateHeap"};
  dll64.imports = {{"ntdll.dll", {"RtlAllocateHeap"}}};

  neden_test::PeBuilder net;
  net.imports = {{"mscoree.dll", {"_CorExeMain"}}};
  net.clr_metadata_version = "v4.0.30319";

  bool ok = neden_test::write_file(out / "exe32.bin", exe32.build());
  ok &= neden_test::write_file(out / "dll64.bin", dll64.build());
  ok &= neden_test::write_file(out / "net.bin", net.build());
  return ok ? 0 : 1;
}
