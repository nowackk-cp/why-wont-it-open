// Writes synthetic PE files for exercising the GUI by hand:
//   gen_testdata <out-dir>
// Produces many_findings.exe (lots of missing DLLs), vcredist_only.exe and not_a_pe.exe.
// The files are structurally valid PE images but are never meant to be run.
#include <cstdio>
#include <filesystem>
#include <fstream>

#include "pe_builder.h"

int main(int argc, char** argv) {
  const std::filesystem::path dir = argc > 1 ? argv[1] : ".";
  std::filesystem::create_directories(dir);

  neden_test::PeBuilder many;
  many.machine = neden::pe::Machine::I386;
  many.subsystem = 2;
  many.imports = {{"KERNEL32.dll", {"ExitProcess"}},
                  {"MSVCP140.dll", {"?_Xlength_error@std@@YAXPBD@Z"}},
                  {"VCRUNTIME140D.dll", {"memcpy"}},
                  {"steam_api.dll", {"SteamAPI_Init"}},
                  {"foo.dll", {"Foo"}},
                  {"api-ms-win-core-nonexistent-l1-1-0.dll", {"Bar"}},
                  {"d3dx9_43.dll", {"D3DXCreateFont"}},
                  {"MSVCR100.dll", {"printf"}},
                  {"vulkan-1.dll", {"vkCreateInstance"}},
                  {"MSVCP120.dll", {"x"}}};
  neden_test::write_file(dir / "many_findings.exe", many.build());

  neden_test::PeBuilder one;
  one.imports = {{"KERNEL32.dll", {"ExitProcess"}}, {"MSVCP140.dll", {"x"}}};
  neden_test::write_file(dir / "vcredist_only.exe", one.build());

  // A typical case for screenshots: an older 32-bit game built with VC++ 2010.
  neden_test::PeBuilder game;
  game.subsystem = 2;
  game.imports = {{"KERNEL32.dll", {"ExitProcess", "GetTickCount"}},
                  {"MSVCR100.dll", {"malloc", "free", "_beginthreadex"}},
                  {"MSVCP100.dll", {"?_Xlength_error@std@@YAXPBD@Z"}},
                  {"d3d9.dll", {"Direct3DCreate9"}}};
  neden_test::write_file(dir / "OldGame.exe", game.build());

  std::ofstream(dir / "not_a_pe.exe", std::ios::binary) << "this is definitely not a program";
  std::printf("wrote test files to %s\n", dir.string().c_str());
  return 0;
}
