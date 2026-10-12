// One-click fixes (milestone M5).
//
// Safety rules:
//  - The tool itself never asks for administrator rights (asInvoker); an
//    installer raises its own UAC prompt.
//  - Only https URLs on an allow-list of official vendor hosts are downloaded.
//  - Nothing is executed unless its Authenticode signature is valid AND the
//    signer matches the expected publisher from the knowledge base.
#pragma once

#include <cstdint>
#include <filesystem>
#include <functional>
#include <string>

namespace neden::fix {

struct Outcome {
  bool ok = false;
  std::uint32_t exit_code = 0;  // installer / winget exit code when it ran
  std::string message;          // English, for logs and the GUI's details line
};

// True if winget.exe (App Installer) is available for the current user.
bool winget_available();

// Runs `winget install --id <id> --exact --source winget` in a new, visible
// console window so the user sees progress and any license prompts. Blocks
// until winget exits. Agreements are NOT auto-accepted.
Outcome install_with_winget(const std::string& winget_id);

// True if url is https and its host is on the official allow-list
// (microsoft.com and subdomains, aka.ms, visualstudio.microsoft.com,
// dotnet.microsoft.com, nvidia.com and subdomains, ...).
bool is_allowed_url(const std::string& url);

struct SignatureInfo {
  bool valid = false;        // WinVerifyTrust succeeded (embedded signature, chain trusted)
  std::string signer;        // subject common name of the leaf signing certificate
  std::uint32_t status = 0;  // HRESULT from WinVerifyTrust
};

// Verifies the file's embedded Authenticode signature (no UI, revocation
// check of the whole chain, network allowed).
SignatureInfo verify_signature(const std::filesystem::path& file);

// Progress callback: bytes received, total bytes (0 if unknown). Return false to cancel.
using Progress = std::function<bool(std::uint64_t received, std::uint64_t total)>;

// Downloads url to a fresh per-run folder under %TEMP%, verifies that the
// signature is valid and the signer equals expected_signer (case-insensitive),
// then starts it with ShellExecuteEx and waits for it to exit.
// The downloaded file is deleted afterwards.
Outcome download_verify_run(const std::string& url, const std::string& expected_signer, const Progress& progress = {});

}  // namespace neden::fix
