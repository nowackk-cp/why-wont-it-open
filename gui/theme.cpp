#include "theme.h"

#include <dwmapi.h>
#include <uxtheme.h>

#include <string>

namespace gui {

Colors make_colors(bool dark) {
  Colors c;
  c.dark = dark;
  if (dark) {
    c.bg = RGB(32, 32, 32);
    c.card = RGB(44, 44, 46);
    c.text = RGB(240, 240, 240);
    c.muted = RGB(168, 168, 172);
    c.border = RGB(84, 84, 88);
    c.accent = RGB(96, 165, 250);
    c.bar_error = RGB(239, 83, 80);
    c.bar_warning = RGB(255, 183, 77);
    c.bar_info = RGB(96, 165, 250);
    c.warn_text = RGB(255, 196, 102);
  } else {
    c.bg = RGB(243, 244, 246);
    c.card = RGB(255, 255, 255);
    c.text = RGB(26, 26, 28);
    c.muted = RGB(96, 100, 108);
    c.border = RGB(200, 204, 210);
    c.accent = RGB(37, 99, 235);
    c.bar_error = RGB(211, 47, 47);
    c.bar_warning = RGB(237, 137, 0);
    c.bar_info = RGB(37, 99, 235);
    c.warn_text = RGB(166, 90, 0);
  }
  return c;
}

int g_theme_override = -1;

bool system_uses_dark_mode() {
  if (g_theme_override >= 0) return g_theme_override == 1;
  DWORD value = 1, size = sizeof(value);
  const LSTATUS st = RegGetValueW(HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\CurrentVersion\\Themes\\Personalize",
                                  L"AppsUseLightTheme", RRF_RT_REG_DWORD, nullptr, &value, &size);
  return st == ERROR_SUCCESS && value == 0;
}

namespace {

HFONT make_font(const wchar_t* face, int points_x10, int weight, UINT dpi) {
  LOGFONTW lf{};
  lf.lfHeight = -MulDiv(points_x10, static_cast<int>(dpi), 720);
  lf.lfWeight = weight;
  lf.lfCharSet = DEFAULT_CHARSET;
  lf.lfQuality = CLEARTYPE_QUALITY;
  wcscpy_s(lf.lfFaceName, face);
  return CreateFontIndirectW(&lf);
}

}  // namespace

void Fonts::create(UINT dpi) {
  destroy();
  normal = make_font(L"Segoe UI", 95, FW_NORMAL, dpi);
  bold = make_font(L"Segoe UI", 95, FW_SEMIBOLD, dpi);
  title = make_font(L"Segoe UI", 120, FW_SEMIBOLD, dpi);
  big = make_font(L"Segoe UI", 145, FW_SEMIBOLD, dpi);
  small_ = make_font(L"Segoe UI", 85, FW_NORMAL, dpi);
  mono = make_font(L"Consolas", 85, FW_NORMAL, dpi);
}

void Fonts::destroy() {
  for (HFONT* f : {&normal, &bold, &title, &big, &small_, &mono}) {
    if (*f) DeleteObject(*f);
    *f = nullptr;
  }
}

UINT dpi_for_window(HWND hwnd) {
  using Fn = UINT(WINAPI*)(HWND);
  static const Fn fn = reinterpret_cast<Fn>(reinterpret_cast<void*>(GetProcAddress(GetModuleHandleW(L"user32.dll"), "GetDpiForWindow")));
  if (fn && hwnd) {
    const UINT d = fn(hwnd);
    if (d) return d;
  }
  HDC dc = GetDC(nullptr);
  const int d = GetDeviceCaps(dc, LOGPIXELSX);
  ReleaseDC(nullptr, dc);
  return d > 0 ? static_cast<UINT>(d) : 96;
}

void apply_window_theme(HWND hwnd, bool dark) {
  const BOOL on = dark ? TRUE : FALSE;
  // DWMWA_USE_IMMERSIVE_DARK_MODE: 20 on Win10 20H1+/11, 19 on earlier Win10 builds. Harmless if unsupported.
  DwmSetWindowAttribute(hwnd, 20, &on, sizeof(on));
  DwmSetWindowAttribute(hwnd, 19, &on, sizeof(on));
}

void apply_control_theme(HWND control, bool dark) {
  SetWindowTheme(control, dark ? L"DarkMode_Explorer" : L"Explorer", nullptr);
}

int measure_text_height(HDC dc, HFONT font, const wchar_t* text, int width) {
  HGDIOBJ old = SelectObject(dc, font);
  RECT rc{0, 0, width > 1 ? width : 1, 0};
  DrawTextW(dc, text, -1, &rc, DT_CALCRECT | DT_WORDBREAK | DT_NOPREFIX | DT_EXPANDTABS);
  SelectObject(dc, old);
  return rc.bottom - rc.top;
}

int measure_text_width(HDC dc, HFONT font, const wchar_t* text) {
  HGDIOBJ old = SelectObject(dc, font);
  RECT rc{0, 0, 0, 0};
  DrawTextW(dc, text, -1, &rc, DT_CALCRECT | DT_SINGLELINE | DT_NOPREFIX);
  SelectObject(dc, old);
  return rc.right - rc.left;
}

}  // namespace gui
