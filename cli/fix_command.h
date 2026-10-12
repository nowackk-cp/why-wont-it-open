// `neden fix <file.exe> [--yes]`: diagnose a program and apply the official fixes.
#pragma once

#include <string>
#include <vector>

// args are the arguments after "fix". Returns the process exit code
// (0 = nothing to fix or everything fixed, 1 = a fix failed, 2 = bad usage).
int run_fix_command(const std::vector<std::wstring>& args);
