// Helpers shared by the diagnosis rule files (diagnose.cpp, events.cpp).
#pragma once

#include <filesystem>
#include <initializer_list>
#include <string>
#include <vector>

#include "neden/diagnose.h"
#include "neden/env.h"
#include "neden/kb.h"
#include "neden/resolve.h"
#include "util/text.h"

namespace neden::diagnose::detail {

// Picks the string for the report language.
struct Tr {
  const char* en;
  const char* tr;
  std::string operator()(Lang lang) const { return lang == Lang::Tr ? tr : en; }
};

// Replaces {0}, {1}, ... in pattern.
std::string format(std::string pattern, std::initializer_list<std::string> args);

inline std::string u8(const std::filesystem::path& p) { return util::wide_to_utf8(p.wstring()); }

// The package fix for `pkg` as the program's architecture `arch` ("x86", "x64", ...).
Fix make_package_fix(const kb::Package& pkg, const std::string& arch, const env::Environment& env, Lang lang);

// Everything the machine-level rules (event log, Mark of the Web, Defender,
// Smart App Control) need to know about the analysis so far.
struct SystemRulesInput {
  const env::Environment& env;
  const kb::KnowledgeBase& kb;
  Lang lang;
  std::filesystem::path program;
  const resolve::Result& resolution;
  std::string arch;  // architecture of the process the program would start as; "" if unknown
};

// Rules 8 and 9. Appends findings; may add evidence to (or upgrade) findings the
// static analysis already produced, so call it after the static rules.
void apply_system_rules(const SystemRulesInput& in, std::vector<Finding>& findings);

}  // namespace neden::diagnose::detail
