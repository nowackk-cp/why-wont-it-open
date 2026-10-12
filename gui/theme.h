// Colors, fonts and DPI helpers shared by the GUI windows.
#pragma once

#include <windows.h>

namespace gui {

// Custom window messages.
constexpr UINT WM_APP_DIAG_DONE = WM_APP + 1;  // lParam: DiagResult* (owned by the receiver)
constexpr UINT WM_APP_FIX_PROGRESS = WM_APP + 2;  // wParam: percent (-1 unknown), lParam: card index
constexpr UINT WM_APP_FIX_DONE = WM_APP + 3;      // lParam: FixResult* (owned by the receiver)
constexpr UINT WM_APP_ACTION = WM_APP + 4;        // results view -> main: wParam card index, lParam Action

enum class Action { InstallWinget = 0, DownloadInstall = 1, OpenPage = 2, CopyCommand = 3 };

struct Colors {
  bool dark = false;
  COLORREF bg, card, text, muted, border, accent, bar_error, bar_warning, bar_info, warn_text;
};

Colors make_colors(bool dark);
// -1: follow Windows, 0: force light, 1: force dark (command line --theme, for testing).
extern int g_theme_override;
bool system_uses_dark_mode();

struct Fonts {
  HFONT normal = nullptr;  // body text
  HFONT bold = nullptr;    // small headings
  HFONT title = nullptr;   // card titles
  HFONT big = nullptr;     // drop zone prompt / header
  HFONT small_ = nullptr;  // hints
  HFONT mono = nullptr;    // evidence
  void create(UINT dpi);
  void destroy();
};

struct Style {
  Colors colors = make_colors(false);
  Fonts fonts;
  UINT dpi = 96;
  int px(int logical) const { return MulDiv(logical, static_cast<int>(dpi), 96); }
};

// Win10+ per-window DPI when available, system DPI otherwise.
UINT dpi_for_window(HWND hwnd);

// Applies the dark/light immersive title bar and control themes.
void apply_window_theme(HWND hwnd, bool dark);
void apply_control_theme(HWND control, bool dark);

// Width/height of text laid out in `width` pixels (word wrapped) with `font`.
int measure_text_height(HDC dc, HFONT font, const wchar_t* text, int width);
int measure_text_width(HDC dc, HFONT font, const wchar_t* text);

}  // namespace gui
