// Why Won't It Open? - GUI entry point.
//
//   WhyWontItOpen.exe [--lang tr|en] [file.exe]
//   WhyWontItOpen.exe --register-shell | --unregister-shell   (Explorer right-click entry, per user)
//
// The analysed program is only ever read by neden_core; this file never loads
// or starts it.
#include <windows.h>

#include <commctrl.h>
#include <objbase.h>
#include <shellapi.h>

#include <string>

#include "shell_menu.h"
#include "strings.h"
#include "theme.h"
#include "window.h"

namespace {

struct Args {
  std::wstring file;
  bool has_lang = false;
  int shell_menu = 0;  // 1 register, -1 unregister
  neden::diagnose::Lang lang = neden::diagnose::Lang::En;
};

Args parse_args() {
  Args a;
  int argc = 0;
  LPWSTR* argv = CommandLineToArgvW(GetCommandLineW(), &argc);
  if (!argv) return a;
  for (int i = 1; i < argc; ++i) {
    const std::wstring arg = argv[i];
    if ((arg == L"--lang" || arg == L"/lang") && i + 1 < argc) {
      const std::wstring v = argv[++i];
      if (_wcsicmp(v.c_str(), L"tr") == 0) {
        a.has_lang = true;
        a.lang = neden::diagnose::Lang::Tr;
      } else if (_wcsicmp(v.c_str(), L"en") == 0) {
        a.has_lang = true;
        a.lang = neden::diagnose::Lang::En;
      }
    } else if (arg == L"--register-shell") {
      a.shell_menu = 1;
    } else if (arg == L"--unregister-shell") {
      a.shell_menu = -1;
    } else if (arg == L"--theme" && i + 1 < argc) {
      const std::wstring v = argv[++i];
      gui::g_theme_override = _wcsicmp(v.c_str(), L"dark") == 0 ? 1 : (_wcsicmp(v.c_str(), L"light") == 0 ? 0 : -1);
    } else if (arg.rfind(L"--lang=", 0) == 0) {
      const std::wstring v = arg.substr(7);
      a.has_lang = true;
      a.lang = _wcsicmp(v.c_str(), L"tr") == 0 ? neden::diagnose::Lang::Tr : neden::diagnose::Lang::En;
    } else if (a.file.empty() && !arg.empty() && arg[0] != L'-') {
      a.file = arg;
    }
  }
  LocalFree(argv);
  return a;
}

}  // namespace

int WINAPI wWinMain(HINSTANCE hinst, HINSTANCE, PWSTR, int show) {
  const Args args = parse_args();
  gui::set_language(args.has_lang ? args.lang : neden::diagnose::default_lang());

  if (args.shell_menu != 0) {
    const bool ok = args.shell_menu > 0 ? gui::register_shell_menu() : gui::unregister_shell_menu();
    return ok ? 0 : 1;
  }

  if (FAILED(CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED | COINIT_DISABLE_OLE1DDE))) return 1;
  INITCOMMONCONTROLSEX icc{sizeof(icc), ICC_STANDARD_CLASSES | ICC_PROGRESS_CLASS | ICC_LINK_CLASS};
  InitCommonControlsEx(&icc);

  int exit_code = 1;
  if (gui::MainWindow::register_class(hinst)) {
    gui::MainWindow window;
    if (window.create(hinst, show, args.file)) {
      MSG msg;
      while (GetMessageW(&msg, nullptr, 0, 0) > 0) {
        if (IsDialogMessageW(window.hwnd(), &msg)) continue;
        TranslateMessage(&msg);
        DispatchMessageW(&msg);
      }
      exit_code = static_cast<int>(msg.wParam);
    }
  }
  // Worker threads (analysis, installers) may still be running: leave without
  // running static destructors that they could race with.
  ExitProcess(static_cast<UINT>(exit_code));
}
