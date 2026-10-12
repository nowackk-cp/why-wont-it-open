// Tiny string table: every UI string exists in English and Turkish.
#pragma once

#include <initializer_list>
#include <string>

#include "neden/diagnose.h"

namespace gui {

enum class S {
  WindowTitle,
  DropPrompt,
  DropHint,
  ChooseFile,
  Analysing,
  CopyReport,
  Copied,
  AnalyseAnother,
  About,
  ResultsName,
  BuiltFor,       // "%s program"
  NotCertain,
  HowToFix,
  InstallWinget,
  DownloadInstall,
  OfficialPage,
  CopyCommand,
  ConfirmTitle,
  ConfirmWinget,   // %1 name, %2 arch, %3 winget id
  ConfirmDownload, // %1 name, %2 arch, %3 host, %4 signer
  Install,
  Cancel,
  Installing,
  Downloading,     // %d percent
  DownloadingUnknown,
  FixOk,
  FixFailed,       // %s message
  AnalysisFailed,  // %s message
  OpenTitle,
  FilterPrograms,
  FilterAll,
  AboutTitle,
  AboutBody,       // %s version
  Close,
  ClipboardFailed,
  ReportUnknown,
  ConfirmReport,   // %s list of DLL names
  NetworkPathRefused,  // %1 path
  Count_
};

void set_language(neden::diagnose::Lang lang);
neden::diagnose::Lang language();
const wchar_t* tr(S id);

// printf-style helper over a translated format string.
std::wstring trf(S id, ...);

// Replaces %1..%9 in a translated string.
std::wstring subst(S id, std::initializer_list<std::wstring> args);

std::wstring widen(const std::string& utf8);
std::string narrow(const std::wstring& wide);

}  // namespace gui
