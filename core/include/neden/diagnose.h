// Turns a resolution result into human findings with official fixes.
//
// Principle: a wrong diagnosis kills trust. Rules only fire on clear evidence,
// and the report says so explicitly when the tool cannot be sure.
#pragma once

#include <filesystem>
#include <optional>
#include <string>
#include <vector>

#include "neden/env.h"
#include "neden/kb.h"
#include "neden/resolve.h"

namespace neden::diagnose {

enum class Lang { En, Tr };
enum class Severity { Error, Warning, Info };

const char* severity_name(Severity s);

// Language of the current user's Windows UI (Turkish -> Tr, otherwise En).
Lang default_lang();

struct Fix {
  std::string package_id;   // knowledge-base package id, if any
  std::string package_name; // display name of the package
  std::string arch;         // "x86", "x64", "arm64" — which flavour to install
  std::string winget_id;    // winget package id, if any
  std::string url;          // official direct download (https), if any
  std::string info_url;     // official page, if any
  std::string command;      // a command the user can run (e.g. DISM), if any
  std::string steps;        // localized instructions (always set)
};

struct Finding {
  std::string rule;          // stable id, e.g. "missing-dll" (see diagnose.cpp)
  Severity severity = Severity::Error;
  bool certain = true;       // false: the tool is guessing and says so
  std::string title;         // localized one-liner
  std::string explanation;   // localized paragraph
  std::vector<std::string> evidence;  // file names / paths / chains that support the finding
  std::optional<Fix> fix;
};

struct Report {
  std::filesystem::path program;
  std::string program_arch;   // "x86", "x64", ... (machine of the process that would run)
  std::string os;             // e.g. "Windows 10.0.19045 x64"
  Lang lang = Lang::En;
  std::vector<Finding> findings;  // most severe first
  resolve::Result resolution;

  bool has_errors() const;
};

Report diagnose(const std::filesystem::path& program, const env::Environment& env, const kb::KnowledgeBase& kb,
                Lang lang);

// Machine-readable output for `neden check --json`.
std::string to_json(const Report& report);

// Plain-text/Markdown report suitable for pasting into forums.
std::string to_text(const Report& report);

}  // namespace neden::diagnose
