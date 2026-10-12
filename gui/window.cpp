#include "window.h"

#include <commctrl.h>
#include <shellapi.h>
#include <shlobj.h>
#include <shobjidl.h>
#include <windowsx.h>

#include <algorithm>
#include <cctype>
#include <cstdio>
#include <string>
#include <vector>
#include <memory>
#include <thread>

#include "fix_actions.h"
#include "neden/env.h"
#include "neden/kb.h"
#include "neden/version.h"
#include "resource.h"
#include "strings.h"

namespace gui {
namespace {

constexpr wchar_t kClassName[] = L"NedenMainWindow";
constexpr wchar_t kRepoUrl[] = L"https://github.com/nowackk-cp/why-wont-it-open";

enum : int { IDC_CHOOSE = 101, IDC_COPY, IDC_ANOTHER, IDC_ABOUT, IDC_VIEW, IDC_PROGRESS };
enum : UINT_PTR { TIMER_COPIED = 1, TIMER_STATUS = 2 };

constexpr int kMinClientW = 520, kMinClientH = 480;
constexpr int kDefClientW = 760, kDefClientH = 640;

std::atomic<bool> g_closing{false};

struct DiagResult {
  bool ok = false;
  neden::diagnose::Report report;
  std::wstring error;
  bool winget = false;
};

struct FixResult {
  size_t card = 0;
  neden::fix::Outcome outcome;
};

std::wstring window_text(HWND h) {
  const int n = GetWindowTextLengthW(h);
  std::wstring s(static_cast<size_t>(n) + 1, L'\0');
  GetWindowTextW(h, s.data(), n + 1);
  s.resize(static_cast<size_t>(n));
  return s;
}

std::wstring to_crlf(const std::wstring& s) {
  std::wstring out;
  out.reserve(s.size() + s.size() / 20);
  for (size_t i = 0; i < s.size(); ++i) {
    if (s[i] == L'\n' && (i == 0 || s[i - 1] != L'\r')) out += L'\r';
    out += s[i];
  }
  return out;
}

bool set_clipboard(HWND owner, const std::wstring& text) {
  if (!OpenClipboard(owner)) return false;
  bool ok = false;
  EmptyClipboard();
  HGLOBAL mem = GlobalAlloc(GMEM_MOVEABLE, (text.size() + 1) * sizeof(wchar_t));
  if (mem) {
    if (void* p = GlobalLock(mem)) {
      memcpy(p, text.c_str(), (text.size() + 1) * sizeof(wchar_t));
      GlobalUnlock(mem);
      ok = SetClipboardData(CF_UNICODETEXT, mem) != nullptr;
    }
    if (!ok) GlobalFree(mem);
  }
  CloseClipboard();
  return ok;
}

bool ends_with_nocase(const std::wstring& s, const wchar_t* suffix) {
  const size_t n = wcslen(suffix);
  return s.size() >= n && _wcsicmp(s.c_str() + s.size() - n, suffix) == 0;
}

// True for UNC paths (\\server\share, \\?\UNC\...) and for drives that are mapped network shares.
// The tool only analyses local files: reading from a share would be slow, can hang, and the file could
// change underneath the analysis.
bool is_network_path(const std::wstring& path) {
  std::wstring full = path;
  wchar_t buf[MAX_PATH * 4];
  const DWORD n = GetFullPathNameW(path.c_str(), static_cast<DWORD>(_countof(buf)), buf, nullptr);
  if (n > 0 && n < _countof(buf)) full.assign(buf, n);
  if (full.size() >= 2 && (full[0] == L'\\' || full[0] == L'/') && (full[1] == L'\\' || full[1] == L'/')) {
    // "\\?\C:\x" and "\\.\C:\x" are local device-style paths; "\\?\UNC\..." and "\\server\..." are not.
    const bool device_prefix = full.size() >= 4 && (full[2] == L'?' || full[2] == L'.') &&
                               (full[3] == L'\\' || full[3] == L'/');
    if (!device_prefix) return true;
    const std::wstring rest = full.substr(4);
    if (rest.size() >= 4 && _wcsnicmp(rest.c_str(), L"UNC", 3) == 0 && (rest[3] == L'\\' || rest[3] == L'/')) return true;
    full = rest;
  }
  if (full.size() >= 2 && full[1] == L':' && iswalpha(full[0])) {
    const wchar_t root[4] = {full[0], L':', L'\\', L'\0'};
    return GetDriveTypeW(root) == DRIVE_REMOTE;
  }
  return false;
}

// Resolves a .lnk shortcut to its target. Returns the input when it can't.
std::wstring resolve_shortcut(const std::wstring& lnk) {
  std::wstring result = lnk;
  IShellLinkW* link = nullptr;
  if (SUCCEEDED(CoCreateInstance(CLSID_ShellLink, nullptr, CLSCTX_INPROC_SERVER, IID_PPV_ARGS(&link)))) {
    IPersistFile* file = nullptr;
    if (SUCCEEDED(link->QueryInterface(IID_PPV_ARGS(&file)))) {
      if (SUCCEEDED(file->Load(lnk.c_str(), STGM_READ))) {
        link->Resolve(nullptr, SLR_NO_UI | SLR_NOUPDATE | SLR_NOSEARCH);
        wchar_t target[32768];
        target[0] = L'\0';
        if (SUCCEEDED(link->GetPath(target, static_cast<int>(_countof(target)), nullptr, 0)) && target[0]) {
          result = target;
        }
      }
      file->Release();
    }
    link->Release();
  }
  return result;
}

bool confirm_install(HWND owner, const std::wstring& text) {
  const TASKDIALOG_BUTTON buttons[] = {{IDOK, tr(S::Install)}, {IDCANCEL, tr(S::Cancel)}};
  TASKDIALOGCONFIG cfg{};
  cfg.cbSize = sizeof(cfg);
  cfg.hwndParent = owner;
  cfg.dwFlags = TDF_ALLOW_DIALOG_CANCELLATION | TDF_POSITION_RELATIVE_TO_WINDOW;
  cfg.pszWindowTitle = tr(S::WindowTitle);
  cfg.pszMainInstruction = tr(S::ConfirmTitle);
  cfg.pszContent = text.c_str();
  cfg.pszMainIcon = TD_INFORMATION_ICON;
  cfg.pButtons = buttons;
  cfg.cButtons = _countof(buttons);
  cfg.nDefaultButton = IDCANCEL;
  int pressed = 0;
  return SUCCEEDED(TaskDialogIndirect(&cfg, &pressed, nullptr, nullptr)) && pressed == IDOK;
}

HRESULT CALLBACK about_callback(HWND, UINT msg, WPARAM, LPARAM lp, LONG_PTR) {
  if (msg == TDN_HYPERLINK_CLICKED) {
    const wchar_t* href = reinterpret_cast<const wchar_t*>(lp);
    if (href && wcscmp(href, kRepoUrl) == 0) ShellExecuteW(nullptr, L"open", href, nullptr, nullptr, SW_SHOWNORMAL);
  }
  return S_OK;
}

}  // namespace

bool MainWindow::register_class(HINSTANCE hinst) {
  WNDCLASSEXW wc{};
  wc.cbSize = sizeof(wc);
  wc.lpfnWndProc = &MainWindow::static_proc;
  wc.hInstance = hinst;
  wc.hCursor = LoadCursorW(nullptr, IDC_ARROW);
  wc.hIcon = static_cast<HICON>(LoadImageW(hinst, MAKEINTRESOURCEW(IDI_APP), IMAGE_ICON, GetSystemMetrics(SM_CXICON),
                                           GetSystemMetrics(SM_CYICON), LR_DEFAULTCOLOR));
  wc.hIconSm = static_cast<HICON>(LoadImageW(hinst, MAKEINTRESOURCEW(IDI_APP), IMAGE_ICON,
                                             GetSystemMetrics(SM_CXSMICON), GetSystemMetrics(SM_CYSMICON),
                                             LR_DEFAULTCOLOR));
  wc.lpszClassName = kClassName;
  return RegisterClassExW(&wc) != 0 && ResultsView::register_class(hinst);
}

bool MainWindow::create(HINSTANCE hinst, int show, const std::wstring& initial_file) {
  hinst_ = hinst;
  hwnd_ = CreateWindowExW(WS_EX_ACCEPTFILES, kClassName, tr(S::WindowTitle),
                          WS_OVERLAPPEDWINDOW | WS_CLIPCHILDREN, CW_USEDEFAULT, CW_USEDEFAULT, 800, 700, nullptr,
                          nullptr, hinst, this);
  if (!hwnd_) return false;
  place_window(show);
  if (!initial_file.empty()) open_file(initial_file);
  return true;
}

LRESULT CALLBACK MainWindow::static_proc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp) {
  MainWindow* self = nullptr;
  if (msg == WM_NCCREATE) {
    self = static_cast<MainWindow*>(reinterpret_cast<CREATESTRUCTW*>(lp)->lpCreateParams);
    self->hwnd_ = hwnd;
    SetWindowLongPtrW(hwnd, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(self));
  } else {
    self = reinterpret_cast<MainWindow*>(GetWindowLongPtrW(hwnd, GWLP_USERDATA));
  }
  return self ? self->proc(msg, wp, lp) : DefWindowProcW(hwnd, msg, wp, lp);
}

SIZE MainWindow::window_size_for_client(int client_w, int client_h) const {
  RECT r{0, 0, style_.px(client_w), style_.px(client_h)};
  using Fn = BOOL(WINAPI*)(LPRECT, DWORD, BOOL, DWORD, UINT);
  static const Fn adjust = reinterpret_cast<Fn>(
      reinterpret_cast<void*>(GetProcAddress(GetModuleHandleW(L"user32.dll"), "AdjustWindowRectExForDpi")));
  const DWORD style = static_cast<DWORD>(GetWindowLongPtrW(hwnd_, GWL_STYLE));
  const DWORD ex = static_cast<DWORD>(GetWindowLongPtrW(hwnd_, GWL_EXSTYLE));
  if (adjust) {
    adjust(&r, style, FALSE, ex, style_.dpi);
  } else {
    AdjustWindowRectEx(&r, style, FALSE, ex);
  }
  return SIZE{r.right - r.left, r.bottom - r.top};
}

void MainWindow::place_window(int show) {
  const SIZE sz = window_size_for_client(kDefClientW, kDefClientH);
  MONITORINFO mi{sizeof(mi)};
  GetMonitorInfoW(MonitorFromWindow(hwnd_, MONITOR_DEFAULTTOPRIMARY), &mi);
  const RECT wa = mi.rcWork;
  const int w = std::min<int>(sz.cx, wa.right - wa.left);
  const int h = std::min<int>(sz.cy, wa.bottom - wa.top);
  SetWindowPos(hwnd_, nullptr, wa.left + (wa.right - wa.left - w) / 2, wa.top + (wa.bottom - wa.top - h) / 2, w, h,
               SWP_NOZORDER | SWP_NOACTIVATE);
  ShowWindow(hwnd_, show);
  UpdateWindow(hwnd_);
}

void MainWindow::reload_icon() {
  if (icon_zone_) DestroyIcon(icon_zone_);
  const int s = style_.px(64);
  icon_zone_ = static_cast<HICON>(LoadImageW(hinst_, MAKEINTRESOURCEW(IDI_APP), IMAGE_ICON, s, s, LR_DEFAULTCOLOR));
}

void MainWindow::create_controls() {
  auto make = [&](const wchar_t* cls, const wchar_t* text, DWORD style, int id) {
    return CreateWindowExW(0, cls, text, WS_CHILD | style, 0, 0, 10, 10, hwnd_,
                           reinterpret_cast<HMENU>(static_cast<INT_PTR>(id)), hinst_, nullptr);
  };
  prompt_ = make(L"STATIC", tr(S::DropPrompt), SS_CENTER | SS_NOPREFIX, 0);
  hint_ = make(L"STATIC", tr(S::DropHint), SS_CENTER | SS_NOPREFIX, 0);
  choose_ = make(L"BUTTON", tr(S::ChooseFile), WS_TABSTOP | BS_PUSHBUTTON, IDC_CHOOSE);
  progress_ = make(PROGRESS_CLASSW, L"", PBS_MARQUEE | PBS_SMOOTH, IDC_PROGRESS);
  head_name_ = make(L"STATIC", L"", SS_LEFT | SS_NOPREFIX | SS_ENDELLIPSIS | SS_PATHELLIPSIS, 0);
  head_sub_ = make(L"STATIC", L"", SS_LEFT | SS_NOPREFIX | SS_ENDELLIPSIS, 0);
  view_.set_style(&style_);
  view_.create(hwnd_, hinst_, IDC_VIEW);
  ShowWindow(view_.hwnd(), SW_HIDE);
  copy_ = make(L"BUTTON", tr(S::CopyReport), WS_TABSTOP | BS_PUSHBUTTON, IDC_COPY);
  another_ = make(L"BUTTON", tr(S::AnalyseAnother), WS_TABSTOP | BS_PUSHBUTTON, IDC_ANOTHER);
  const std::wstring link = std::wstring(L"<a>") + tr(S::About) + L"</a>";
  about_ = make(WC_LINK, link.c_str(), WS_TABSTOP | LWS_TRANSPARENT, IDC_ABOUT);
  SendMessageW(progress_, PBM_SETMARQUEE, TRUE, 30);
}

void MainWindow::apply_fonts() {
  const Fonts& f = style_.fonts;
  auto set = [](HWND h, HFONT font) { SendMessageW(h, WM_SETFONT, reinterpret_cast<WPARAM>(font), TRUE); };
  set(prompt_, f.big);
  set(hint_, f.small_);
  set(choose_, f.normal);
  set(head_name_, f.big);
  set(head_sub_, f.normal);
  set(copy_, f.normal);
  set(another_, f.normal);
  set(about_, f.normal);
}

void MainWindow::apply_theme(bool dark) {
  style_.colors = make_colors(dark);
  if (bg_brush_) DeleteObject(bg_brush_);
  if (card_brush_) DeleteObject(card_brush_);
  bg_brush_ = CreateSolidBrush(style_.colors.bg);
  card_brush_ = CreateSolidBrush(style_.colors.card);
  apply_window_theme(hwnd_, dark);
  for (HWND h : {choose_, copy_, another_}) apply_control_theme(h, dark);
  view_.refresh_style();
  RedrawWindow(hwnd_, nullptr, nullptr, RDW_INVALIDATE | RDW_ERASE | RDW_ALLCHILDREN);
}

void MainWindow::on_create() {
  style_.dpi = dpi_for_window(hwnd_);
  style_.fonts.create(style_.dpi);
  create_controls();
  apply_fonts();
  reload_icon();
  apply_theme(system_uses_dark_mode());
  set_mode(Mode::Home);
}

void MainWindow::set_mode(Mode m) {
  mode_ = m;
  const bool zone = m != Mode::Results;
  if (m == Mode::Home) {
    SetWindowTextW(prompt_, tr(S::DropPrompt));
    SetWindowTextW(hint_, tr(S::DropHint));
  } else if (m == Mode::Busy) {
    SetWindowTextW(prompt_, tr(S::Analysing));
    const std::filesystem::path p(program_path_);
    SetWindowTextW(hint_, p.filename().c_str());
  }
  ShowWindow(prompt_, zone ? SW_SHOW : SW_HIDE);
  ShowWindow(hint_, zone ? SW_SHOW : SW_HIDE);
  ShowWindow(choose_, m == Mode::Home ? SW_SHOW : SW_HIDE);
  ShowWindow(progress_, m == Mode::Busy ? SW_SHOW : SW_HIDE);
  for (HWND h : {head_name_, head_sub_, view_.hwnd(), copy_, another_, about_}) {
    ShowWindow(h, m == Mode::Results ? SW_SHOW : SW_HIDE);
  }
  layout();
  RedrawWindow(hwnd_, nullptr, nullptr, RDW_INVALIDATE | RDW_ERASE | RDW_ALLCHILDREN);
}

void MainWindow::layout() {
  if (!hwnd_ || !prompt_) return;
  RECT rc;
  GetClientRect(hwnd_, &rc);
  const int cw = rc.right, ch = rc.bottom;
  HDC dc = GetDC(hwnd_);
  const Style& st = style_;

  if (mode_ != Mode::Results) {
    const int m = st.px(20);
    zone_ = RECT{m, m, std::max<int>(cw - m, m + 10), std::max<int>(ch - m, m + 10)};
    const int zw = zone_.right - zone_.left, zh = zone_.bottom - zone_.top;
    const int tw = std::min(zw - st.px(48), st.px(520));
    const int icon = st.px(64);
    const int ph = measure_text_height(dc, st.fonts.big, window_text(prompt_).c_str(), tw) + st.px(4);
    const int hh = measure_text_height(dc, st.fonts.small_, window_text(hint_).c_str(), tw) + st.px(2);
    const int ctl_h = mode_ == Mode::Home ? st.px(34) : st.px(6);
    const int total = icon + st.px(16) + ph + st.px(8) + hh + st.px(22) + ctl_h;
    int y = zone_.top + std::max(st.px(12), (zh - total) / 2);
    const int cx = zone_.left + zw / 2;
    icon_rect_ = RECT{cx - icon / 2, y, cx + icon / 2, y + icon};
    y += icon + st.px(16);
    SetWindowPos(prompt_, nullptr, cx - tw / 2, y, tw, ph, SWP_NOZORDER | SWP_NOACTIVATE);
    y += ph + st.px(8);
    SetWindowPos(hint_, nullptr, cx - tw / 2, y, tw, hh, SWP_NOZORDER | SWP_NOACTIVATE);
    y += hh + st.px(22);
    if (mode_ == Mode::Home) {
      const int bw = std::max(measure_text_width(dc, st.fonts.normal, tr(S::ChooseFile)) + st.px(44), st.px(150));
      SetWindowPos(choose_, nullptr, cx - bw / 2, y, bw, ctl_h, SWP_NOZORDER | SWP_NOACTIVATE);
    } else {
      const int pw = std::min(tw, st.px(260));
      SetWindowPos(progress_, nullptr, cx - pw / 2, y, pw, ctl_h, SWP_NOZORDER | SWP_NOACTIVATE);
    }
  } else {
    const int m = st.px(20);
    const int bar_h = st.px(60);
    bar_top_ = ch - bar_h;
    const int name_h = measure_text_height(dc, st.fonts.big, L"Ag", 1000) + st.px(2);
    const int sub_h = measure_text_height(dc, st.fonts.normal, L"Ag", 1000) + st.px(2);
    int y = st.px(14);
    SetWindowPos(head_name_, nullptr, m, y, cw - 2 * m, name_h, SWP_NOZORDER | SWP_NOACTIVATE);
    y += name_h + st.px(2);
    SetWindowPos(head_sub_, nullptr, m, y, cw - 2 * m, sub_h, SWP_NOZORDER | SWP_NOACTIVATE);
    y += sub_h + st.px(10);
    SetWindowPos(view_.hwnd(), nullptr, 0, y, cw, std::max(bar_top_ - y, 10), SWP_NOZORDER | SWP_NOACTIVATE);

    const int bh = st.px(34), by = bar_top_ + (bar_h - bh) / 2;
    const int pad = st.px(32);
    const int cw1 = std::max(measure_text_width(dc, st.fonts.normal, tr(S::CopyReport)),
                             measure_text_width(dc, st.fonts.normal, tr(S::Copied))) + pad;
    const int cw2 = measure_text_width(dc, st.fonts.normal, tr(S::AnalyseAnother)) + pad;
    const int about_w = measure_text_width(dc, st.fonts.normal, tr(S::About)) + st.px(8);
    int x = m;
    SetWindowPos(copy_, nullptr, x, by, cw1, bh, SWP_NOZORDER | SWP_NOACTIVATE);
    x += cw1 + st.px(10);
    SetWindowPos(another_, nullptr, x, by, cw2, bh, SWP_NOZORDER | SWP_NOACTIVATE);
    const int lh = measure_text_height(dc, st.fonts.normal, L"Ag", 1000) + st.px(2);
    SetWindowPos(about_, nullptr, cw - m - about_w, bar_top_ + (bar_h - lh) / 2, about_w, lh,
                 SWP_NOZORDER | SWP_NOACTIVATE);
  }
  ReleaseDC(hwnd_, dc);
}

void MainWindow::paint(HDC dc, const RECT& client) {
  const Colors& col = style_.colors;
  FillRect(dc, &client, bg_brush_);
  if (mode_ != Mode::Results) {
    LOGBRUSH lb{BS_SOLID, col.accent, 0};
    HPEN pen = ExtCreatePen(PS_GEOMETRIC | PS_DASH | PS_ENDCAP_FLAT | PS_JOIN_ROUND, static_cast<DWORD>(style_.px(2)), &lb,
                            0, nullptr);
    HGDIOBJ op = SelectObject(dc, pen);
    HGDIOBJ ob = SelectObject(dc, card_brush_);
    const int r = style_.px(18);
    RoundRect(dc, zone_.left, zone_.top, zone_.right, zone_.bottom, r, r);
    SelectObject(dc, op);
    SelectObject(dc, ob);
    DeleteObject(pen);
    if (icon_zone_) {
      DrawIconEx(dc, icon_rect_.left, icon_rect_.top, icon_zone_, icon_rect_.right - icon_rect_.left,
                 icon_rect_.bottom - icon_rect_.top, 0, nullptr, DI_NORMAL);
    }
  } else {
    HPEN pen = CreatePen(PS_SOLID, 1, col.border);
    HGDIOBJ op = SelectObject(dc, pen);
    MoveToEx(dc, 0, bar_top_, nullptr);
    LineTo(dc, client.right, bar_top_);
    SelectObject(dc, op);
    DeleteObject(pen);
  }
}

void MainWindow::set_busy_inputs(bool busy) {
  EnableWindow(choose_, !busy);
  EnableWindow(copy_, !busy);
  EnableWindow(another_, !busy);
  view_.set_enabled(!busy);
}

void MainWindow::update_header() {
  const std::filesystem::path p = report_.program;
  SetWindowTextW(head_name_, p.filename().c_str());
  std::wstring sub;
  if (!report_.program_arch.empty()) sub = trf(S::BuiltFor, widen(report_.program_arch).c_str());
  if (!report_.os.empty()) sub += (sub.empty() ? L"" : L"  ·  ") + widen(report_.os);
  SetWindowTextW(head_sub_, sub.c_str());
}

void MainWindow::choose_file() {
  IFileOpenDialog* dlg = nullptr;
  if (FAILED(CoCreateInstance(CLSID_FileOpenDialog, nullptr, CLSCTX_INPROC_SERVER, IID_PPV_ARGS(&dlg)))) return;
  const COMDLG_FILTERSPEC filters[] = {{tr(S::FilterPrograms), L"*.exe;*.dll"}, {tr(S::FilterAll), L"*.*"}};
  dlg->SetFileTypes(_countof(filters), filters);
  dlg->SetFileTypeIndex(1);
  dlg->SetTitle(tr(S::OpenTitle));
  DWORD opts = 0;
  dlg->GetOptions(&opts);
  dlg->SetOptions(opts | FOS_FORCEFILESYSTEM | FOS_FILEMUSTEXIST | FOS_PATHMUSTEXIST);
  if (SUCCEEDED(dlg->Show(hwnd_))) {
    IShellItem* item = nullptr;
    if (SUCCEEDED(dlg->GetResult(&item))) {
      PWSTR path = nullptr;
      if (SUCCEEDED(item->GetDisplayName(SIGDN_FILESYSPATH, &path))) {
        open_file(path);
        CoTaskMemFree(path);
      }
      item->Release();
    }
  }
  dlg->Release();
}

void MainWindow::open_file(std::wstring path) {
  if (mode_ == Mode::Busy || fix_busy_) return;
  if (is_network_path(path)) {
    refuse_network_path(path);
    return;
  }
  if (ends_with_nocase(path, L".lnk")) {
    path = resolve_shortcut(path);
    if (is_network_path(path)) {  // the shortcut points to a share
      refuse_network_path(path);
      return;
    }
  }
  start_diagnosis(path);
}

void MainWindow::refuse_network_path(const std::wstring& path) {
  MessageBoxW(hwnd_, subst(S::NetworkPathRefused, {path}).c_str(), tr(S::WindowTitle), MB_OK | MB_ICONINFORMATION);
}

void MainWindow::start_diagnosis(const std::wstring& path) {
  program_path_ = path;
  mode_before_busy_ = mode_;
  set_busy_inputs(true);
  set_mode(Mode::Busy);
  const HWND hwnd = hwnd_;
  const auto lang = language();
  std::thread([hwnd, path, lang] {
    auto* result = new DiagResult;
    try {
      auto env = neden::env::make_system_environment();
      result->report = neden::diagnose::diagnose(std::filesystem::path(path), *env, neden::kb::KnowledgeBase::embedded(), lang);
      result->winget = fixes::winget_available();
      result->ok = true;
    } catch (const std::exception& e) {
      result->error = widen(e.what());
    } catch (...) {
      result->error = L"unknown error";
    }
    if (!PostMessageW(hwnd, WM_APP_DIAG_DONE, 0, reinterpret_cast<LPARAM>(result))) delete result;
  }).detach();
}

void MainWindow::on_diagnosis_done(LPARAM lp) {
  std::unique_ptr<DiagResult> r(reinterpret_cast<DiagResult*>(lp));
  set_busy_inputs(false);
  if (!r->ok) {
    set_mode(has_report_ ? Mode::Results : Mode::Home);
    MessageBoxW(hwnd_, trf(S::AnalysisFailed, r->error.c_str()).c_str(), tr(S::WindowTitle), MB_OK | MB_ICONERROR);
    return;
  }
  report_ = std::move(r->report);
  has_report_ = true;
  winget_ok_ = r->winget;
  report_text_ = to_crlf(widen(neden::diagnose::to_text(report_)));
  update_header();
  view_.set_report(report_, winget_ok_);
  SetWindowTextW(copy_, tr(S::CopyReport));
  set_mode(Mode::Results);
  SetFocus(view_.hwnd());
}

void MainWindow::copy_report() {
  if (!set_clipboard(hwnd_, report_text_)) {
    MessageBoxW(hwnd_, tr(S::ClipboardFailed), tr(S::WindowTitle), MB_OK | MB_ICONWARNING);
    return;
  }
  SetWindowTextW(copy_, tr(S::Copied));
  SetTimer(hwnd_, TIMER_COPIED, 2000, nullptr);
}

void MainWindow::show_about() {
  const std::wstring ver = widen(std::string(neden::version()));
  std::wstring body = trf(S::AboutBody, ver.c_str());
  const size_t at = body.find(kRepoUrl);
  if (at != std::wstring::npos) {
    body.replace(at, wcslen(kRepoUrl), std::wstring(L"<a href=\"") + kRepoUrl + L"\">" + kRepoUrl + L"</a>");
  }
  const TASKDIALOG_BUTTON buttons[] = {{IDOK, tr(S::Close)}};
  TASKDIALOGCONFIG cfg{};
  cfg.cbSize = sizeof(cfg);
  cfg.hwndParent = hwnd_;
  cfg.dwFlags = TDF_ENABLE_HYPERLINKS | TDF_ALLOW_DIALOG_CANCELLATION | TDF_POSITION_RELATIVE_TO_WINDOW;
  cfg.pszWindowTitle = tr(S::AboutTitle);
  cfg.pszMainInstruction = tr(S::WindowTitle);
  cfg.pszContent = body.c_str();
  cfg.hMainIcon = icon_zone_;
  cfg.dwFlags |= TDF_USE_HICON_MAIN;
  cfg.pButtons = buttons;
  cfg.cButtons = _countof(buttons);
  cfg.pfCallback = about_callback;
  TaskDialogIndirect(&cfg, nullptr, nullptr, nullptr);
}

void MainWindow::on_action(size_t card, Action action) {
  const neden::diagnose::Finding* f = view_.finding(card);
  if (!f || !f->fix || fix_busy_) return;
  const auto& fx = *f->fix;
  switch (action) {
    case Action::OpenPage:
      if (fx.info_url.rfind("https://", 0) == 0) {
        ShellExecuteW(hwnd_, L"open", widen(fx.info_url).c_str(), nullptr, nullptr, SW_SHOWNORMAL);
      }
      break;
    case Action::CopyCommand:
      if (set_clipboard(hwnd_, widen(fx.command))) {
        if (status_clear_card_ != static_cast<size_t>(-1)) view_.set_card_status(status_clear_card_, L"");
        status_clear_card_ = card;
        view_.set_card_status(card, tr(S::Copied));
        SetTimer(hwnd_, TIMER_STATUS, 2000, nullptr);
      } else {
        MessageBoxW(hwnd_, tr(S::ClipboardFailed), tr(S::WindowTitle), MB_OK | MB_ICONWARNING);
      }
      break;
    case Action::ReportUnknown: report_unknown(*f); break;
    case Action::InstallWinget: start_fix(card, true); break;
    case Action::DownloadInstall: start_fix(card, false); break;
  }
}

// Opens a pre-filled GitHub issue that contains nothing but the DLL names.
void MainWindow::report_unknown(const neden::diagnose::Finding& f) {
  constexpr size_t kMaxReported = 10;
  std::vector<std::string> names;
  for (const std::string& e : f.evidence) {
    if (names.size() >= kMaxReported) break;
    const std::string name = e.substr(0, e.find(' '));
    const bool plausible = name.size() > 4 && name.size() < 100 &&
                           _stricmp(name.c_str() + name.size() - 4, ".dll") == 0 &&
                           name.find_first_of("\\/:%") == std::string::npos;
    if (plausible && std::find(names.begin(), names.end(), name) == names.end()) names.push_back(name);
  }
  if (names.empty()) return;

  std::string list;
  for (const std::string& n : names) list += (list.empty() ? "" : "\n") + n;
  // Built as a std::wstring (no fixed buffer): replace the "%s" of the translated text by hand.
  std::wstring msg = tr(S::ConfirmReport);
  const size_t at = msg.find(L"%s");
  if (at != std::wstring::npos) msg.replace(at, 2, widen(list));
  if (MessageBoxW(hwnd_, msg.c_str(), tr(S::ReportUnknown), MB_OKCANCEL | MB_ICONINFORMATION) != IDOK) return;

  auto encode = [](const std::string& s) {
    std::string out;
    for (const unsigned char c : s) {
      if (std::isalnum(c) || c == '-' || c == '_' || c == '.' || c == '~') {
        out += static_cast<char>(c);
      } else {
        char buf[4];
        std::snprintf(buf, sizeof(buf), "%%%02X", c);
        out += buf;
      }
    }
    return out;
  };
  std::string title = "Unknown DLL: " + names.front();
  if (names.size() > 1) title += " (+" + std::to_string(names.size() - 1) + ")";
  std::string body = "The tool did not know which package provides these DLLs:\n\n";
  for (const std::string& n : names) body += "- `" + n + "`\n";
  body += "\nWhich program or package do they belong to (if you know)?\n";
  const std::string url = "https://github.com/nowackk-cp/why-wont-it-open/issues/new?labels=unknown-dll&title=" +
                          encode(title) + "&body=" + encode(body);
  ShellExecuteW(hwnd_, L"open", widen(url).c_str(), nullptr, nullptr, SW_SHOWNORMAL);
}

void MainWindow::start_fix(size_t card, bool winget) {
  const neden::diagnose::Finding* f = view_.finding(card);
  if (!f || !f->fix) return;
  const neden::diagnose::Fix fx = *f->fix;  // copy: the view may rebuild while the worker runs
  const std::wstring name = widen(fx.package_name.empty() ? fx.package_id : fx.package_name);
  const std::wstring arch = widen(fx.arch);

  std::string signer;
  if (!winget) {
    if (const auto* pkg = neden::kb::KnowledgeBase::embedded().find_package(fx.package_id)) signer = pkg->signer;
    if (signer.empty() || fixes::url_host(fx.url).empty()) return;  // never run an installer we can't verify
  }
  const std::wstring text =
      winget ? subst(S::ConfirmWinget, {name, arch, widen(fx.winget_id)})
             : subst(S::ConfirmDownload, {name, arch, widen(fixes::url_host(fx.url)), widen(signer)});
  if (!confirm_install(hwnd_, text)) return;

  fix_busy_ = true;
  last_percent_ = -2;
  set_busy_inputs(true);
  view_.set_card_status(card, winget ? tr(S::Installing) : tr(S::Downloading));
  const HWND hwnd = hwnd_;
  std::thread([hwnd, card, winget, fx, signer] {
    CoInitializeEx(nullptr, COINIT_MULTITHREADED);
    auto* res = new FixResult;
    res->card = card;
    try {
      if (winget) {
        res->outcome = fixes::install_with_winget(fx.winget_id);
      } else {
        int last = -2;
        res->outcome = fixes::download_and_install(fx.url, signer, [&](int percent) {
          if (percent != last) {
            last = percent;
            PostMessageW(hwnd, WM_APP_FIX_PROGRESS, static_cast<WPARAM>(percent + 1), static_cast<LPARAM>(card));
          }
          return !g_closing.load();
        });
      }
    } catch (const std::exception& e) {
      res->outcome = {false, 0, e.what()};
    }
    CoUninitialize();
    if (!PostMessageW(hwnd, WM_APP_FIX_DONE, 0, reinterpret_cast<LPARAM>(res))) delete res;
  }).detach();
}

void MainWindow::on_fix_done(LPARAM lp) {
  std::unique_ptr<FixResult> r(reinterpret_cast<FixResult*>(lp));
  fix_busy_ = false;
  if (r->outcome.ok) {
    view_.set_card_status(r->card, tr(S::FixOk));
    start_diagnosis(program_path_);
    return;
  }
  set_busy_inputs(false);
  view_.set_card_status(r->card, trf(S::FixFailed, widen(r->outcome.message).c_str()));
}

LRESULT MainWindow::proc(UINT msg, WPARAM wp, LPARAM lp) {
  switch (msg) {
    case WM_CREATE: on_create(); return 0;
    case WM_ERASEBKGND:
      // WM_PAINT draws everything double buffered. Themed child controls ask the
      // parent to draw their background with their own DC: serve that request.
      if (WindowFromDC(reinterpret_cast<HDC>(wp)) != hwnd_) {
        RECT rc;
        GetClientRect(hwnd_, &rc);
        paint(reinterpret_cast<HDC>(wp), rc);
      }
      return 1;
    case WM_PRINTCLIENT: {
      RECT rc;
      GetClientRect(hwnd_, &rc);
      paint(reinterpret_cast<HDC>(wp), rc);
      return 0;
    }
    case WM_PAINT: {
      PAINTSTRUCT ps;
      HDC dc = BeginPaint(hwnd_, &ps);
      RECT rc;
      GetClientRect(hwnd_, &rc);
      HDC mem = CreateCompatibleDC(dc);
      HBITMAP bmp = CreateCompatibleBitmap(dc, rc.right, rc.bottom);
      HGDIOBJ old = SelectObject(mem, bmp);
      paint(mem, rc);
      BitBlt(dc, 0, 0, rc.right, rc.bottom, mem, 0, 0, SRCCOPY);
      SelectObject(mem, old);
      DeleteObject(bmp);
      DeleteDC(mem);
      EndPaint(hwnd_, &ps);
      return 0;
    }
    case WM_SIZE:
      if (wp != SIZE_MINIMIZED) layout();
      return 0;
    case WM_GETMINMAXINFO: {
      if (style_.dpi) {
        const SIZE s = window_size_for_client(kMinClientW, kMinClientH);
        reinterpret_cast<MINMAXINFO*>(lp)->ptMinTrackSize = POINT{s.cx, s.cy};
      }
      return 0;
    }
    case WM_DPICHANGED: {
      style_.dpi = LOWORD(wp);
      style_.fonts.create(style_.dpi);
      apply_fonts();
      reload_icon();
      const RECT* r = reinterpret_cast<const RECT*>(lp);
      SetWindowPos(hwnd_, nullptr, r->left, r->top, r->right - r->left, r->bottom - r->top, SWP_NOZORDER | SWP_NOACTIVATE);
      view_.refresh_style();
      layout();
      RedrawWindow(hwnd_, nullptr, nullptr, RDW_INVALIDATE | RDW_ERASE | RDW_ALLCHILDREN);
      return 0;
    }
    case WM_SETTINGCHANGE:
      if (lp && wcscmp(reinterpret_cast<const wchar_t*>(lp), L"ImmersiveColorSet") == 0) {
        apply_theme(system_uses_dark_mode());
      }
      break;
    case WM_DROPFILES: {
      HDROP drop = reinterpret_cast<HDROP>(wp);
      wchar_t path[32768];
      path[0] = L'\0';
      const UINT n = DragQueryFileW(drop, 0, path, static_cast<UINT>(_countof(path)));
      DragFinish(drop);
      if (n > 0) open_file(path);
      return 0;
    }
    case WM_MOUSEWHEEL:
      if (mode_ == Mode::Results) return SendMessageW(view_.hwnd(), WM_MOUSEWHEEL, wp, lp);
      break;
    case WM_CTLCOLORSTATIC: {
      HDC dc = reinterpret_cast<HDC>(wp);
      HWND h = reinterpret_cast<HWND>(lp);
      const bool zone = mode_ != Mode::Results;
      const Colors& c = style_.colors;
      SetBkColor(dc, zone ? c.card : c.bg);
      SetTextColor(dc, (h == hint_ || h == head_sub_) ? c.muted : c.text);
      return reinterpret_cast<LRESULT>(zone ? card_brush_ : bg_brush_);
    }
    case WM_COMMAND:
      switch (LOWORD(wp)) {
        case IDC_CHOOSE: if (HIWORD(wp) == BN_CLICKED) choose_file(); return 0;
        case IDC_COPY: if (HIWORD(wp) == BN_CLICKED) copy_report(); return 0;
        case IDC_ANOTHER: if (HIWORD(wp) == BN_CLICKED) choose_file(); return 0;
        default: break;
      }
      break;
    case WM_NOTIFY: {
      const NMHDR* nm = reinterpret_cast<const NMHDR*>(lp);
      if (nm->idFrom == IDC_ABOUT && (nm->code == NM_CLICK || nm->code == NM_RETURN)) {
        show_about();
        return 0;
      }
      break;
    }
    case WM_APP_ACTION: on_action(static_cast<size_t>(wp), static_cast<Action>(lp)); return 0;
    case WM_APP_DIAG_DONE: on_diagnosis_done(lp); return 0;
    case WM_APP_FIX_DONE: on_fix_done(lp); return 0;
    case WM_APP_FIX_PROGRESS: {
      const int percent = static_cast<int>(wp) - 1;
      view_.set_card_status(static_cast<size_t>(lp),
                            percent >= 0 ? trf(S::Downloading, percent) : std::wstring(tr(S::DownloadingUnknown)));
      return 0;
    }
    case WM_TIMER:
      if (wp == TIMER_COPIED) {
        KillTimer(hwnd_, TIMER_COPIED);
        SetWindowTextW(copy_, tr(S::CopyReport));
      } else if (wp == TIMER_STATUS) {
        KillTimer(hwnd_, TIMER_STATUS);
        if (status_clear_card_ != static_cast<size_t>(-1)) view_.set_card_status(status_clear_card_, L"");
        status_clear_card_ = static_cast<size_t>(-1);
      }
      return 0;
    case WM_DESTROY:
      g_closing = true;
      style_.fonts.destroy();
      if (bg_brush_) DeleteObject(bg_brush_);
      if (card_brush_) DeleteObject(card_brush_);
      if (icon_zone_) DestroyIcon(icon_zone_);
      PostQuitMessage(0);
      return 0;
    default: break;
  }
  return DefWindowProcW(hwnd_, msg, wp, lp);
}

}  // namespace gui
