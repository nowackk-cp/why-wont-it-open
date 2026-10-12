#include "results_view.h"

#include <windowsx.h>

#include <algorithm>

#include "strings.h"

namespace gui {
namespace {

constexpr wchar_t kClassName[] = L"NedenResultsView";

enum Slot { kTitle = 0, kTag, kExplain, kEvidence, kStepsLabel, kSteps, kStatus, kButtonBase = 8 };
constexpr int kIdBase = 1000;
constexpr size_t kMaxEvidenceLines = 14;

int control_id(size_t card, int slot) { return kIdBase + static_cast<int>(card) * 16 + slot; }

std::wstring window_text(HWND h) {
  const int n = GetWindowTextLengthW(h);
  std::wstring s(static_cast<size_t>(n) + 1, L'\0');
  GetWindowTextW(h, s.data(), n + 1);
  s.resize(static_cast<size_t>(n));
  return s;
}

std::wstring join_evidence(const std::vector<std::string>& lines) {
  std::wstring out;
  const size_t shown = std::min(lines.size(), kMaxEvidenceLines);
  for (size_t i = 0; i < shown; ++i) {
    if (i) out += L"\r\n";
    out += widen(lines[i]);
  }
  if (lines.size() > shown) out += L"\r\n… +" + std::to_wstring(lines.size() - shown);
  return out;
}

}  // namespace

bool ResultsView::register_class(HINSTANCE hinst) {
  WNDCLASSEXW wc{};
  wc.cbSize = sizeof(wc);
  wc.style = CS_DBLCLKS;
  wc.lpfnWndProc = &ResultsView::static_proc;
  wc.hInstance = hinst;
  wc.hCursor = LoadCursorW(nullptr, IDC_ARROW);
  wc.lpszClassName = kClassName;
  return RegisterClassExW(&wc) != 0;
}

HWND ResultsView::create(HWND parent, HINSTANCE hinst, int control_id_) {
  hwnd_ = CreateWindowExW(WS_EX_CONTROLPARENT, kClassName, tr(S::ResultsName),
                          WS_CHILD | WS_VISIBLE | WS_VSCROLL | WS_CLIPCHILDREN | WS_TABSTOP, 0, 0, 100, 100, parent,
                          reinterpret_cast<HMENU>(static_cast<INT_PTR>(control_id_)), hinst, this);
  return hwnd_;
}

LRESULT CALLBACK ResultsView::static_proc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp) {
  ResultsView* self = nullptr;
  if (msg == WM_NCCREATE) {
    self = static_cast<ResultsView*>(reinterpret_cast<CREATESTRUCTW*>(lp)->lpCreateParams);
    self->hwnd_ = hwnd;
    SetWindowLongPtrW(hwnd, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(self));
  } else {
    self = reinterpret_cast<ResultsView*>(GetWindowLongPtrW(hwnd, GWLP_USERDATA));
  }
  if (!self) return DefWindowProcW(hwnd, msg, wp, lp);
  if (msg == WM_NCDESTROY) {
    LRESULT r = self->proc(msg, wp, lp);
    SetWindowLongPtrW(hwnd, GWLP_USERDATA, 0);
    return r;
  }
  return self->proc(msg, wp, lp);
}

COLORREF ResultsView::static_color(int slot) const {
  const Colors& c = style_->colors;
  switch (slot) {
    case kTag: return c.warn_text;
    case kEvidence:
    case kStepsLabel: return c.muted;
    case kStatus: return c.accent;
    default: return c.text;
  }
}

void ResultsView::recreate_brush() {
  if (card_brush_) DeleteObject(card_brush_);
  card_brush_ = style_ ? CreateSolidBrush(style_->colors.card) : nullptr;
}

LRESULT ResultsView::proc(UINT msg, WPARAM wp, LPARAM lp) {
  switch (msg) {
    case WM_ERASEBKGND:
      // WM_PAINT paints everything (double buffered). Children that ask their
      // parent to draw their background (themed buttons) get the full paint.
      if (WindowFromDC(reinterpret_cast<HDC>(wp)) != hwnd_ && style_) {
        RECT rc;
        GetClientRect(hwnd_, &rc);
        paint(reinterpret_cast<HDC>(wp), rc);
      }
      return 1;
    case WM_PAINT: {
      PAINTSTRUCT ps;
      HDC dc = BeginPaint(hwnd_, &ps);
      if (style_) {
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
      }
      EndPaint(hwnd_, &ps);
      return 0;
    }
    case WM_SIZE:
      if (style_) relayout();
      return 0;
    case WM_VSCROLL: {
      SCROLLINFO si{sizeof(si), SIF_ALL};
      GetScrollInfo(hwnd_, SB_VERT, &si);
      int pos = scroll_;
      const int line = style_ ? style_->px(32) : 32;
      switch (LOWORD(wp)) {
        case SB_LINEUP: pos -= line; break;
        case SB_LINEDOWN: pos += line; break;
        case SB_PAGEUP: pos -= static_cast<int>(si.nPage) - line; break;
        case SB_PAGEDOWN: pos += static_cast<int>(si.nPage) - line; break;
        case SB_THUMBTRACK:
        case SB_THUMBPOSITION: pos = si.nTrackPos; break;
        case SB_TOP: pos = 0; break;
        case SB_BOTTOM: pos = content_height_; break;
        default: break;
      }
      scroll_to(pos);
      return 0;
    }
    case WM_MOUSEWHEEL: {
      const int delta = GET_WHEEL_DELTA_WPARAM(wp);
      UINT lines = 3;
      SystemParametersInfoW(SPI_GETWHEELSCROLLLINES, 0, &lines, 0);
      if (lines == WHEEL_PAGESCROLL) lines = 10;
      const int line = style_ ? style_->px(20) : 20;
      scroll_to(scroll_ - delta * static_cast<int>(lines) * line / WHEEL_DELTA);
      return 0;
    }
    case WM_GETDLGCODE: return DLGC_WANTARROWS;
    case WM_KEYDOWN: {
      RECT rc;
      GetClientRect(hwnd_, &rc);
      const int line = style_ ? style_->px(32) : 32;
      switch (wp) {
        case VK_UP: scroll_to(scroll_ - line); return 0;
        case VK_DOWN: scroll_to(scroll_ + line); return 0;
        case VK_PRIOR: scroll_to(scroll_ - (rc.bottom - line)); return 0;
        case VK_NEXT: scroll_to(scroll_ + (rc.bottom - line)); return 0;
        case VK_HOME: scroll_to(0); return 0;
        case VK_END: scroll_to(content_height_); return 0;
        default: break;
      }
      break;
    }
    case WM_LBUTTONDOWN: SetFocus(hwnd_); return 0;
    case WM_SETFOCUS:
    case WM_KILLFOCUS: return 0;
    case WM_CTLCOLORSTATIC:
    case WM_CTLCOLORBTN: {
      if (!style_) break;
      HDC dc = reinterpret_cast<HDC>(wp);
      const int id = GetDlgCtrlID(reinterpret_cast<HWND>(lp));
      SetBkColor(dc, style_->colors.card);
      SetTextColor(dc, static_color((id - kIdBase) & 15));
      return reinterpret_cast<LRESULT>(card_brush_);
    }
    case WM_COMMAND: {
      const int id = LOWORD(wp);
      if (id < kIdBase) break;
      const size_t card = static_cast<size_t>((id - kIdBase) >> 4);
      const int slot = (id - kIdBase) & 15;
      if (HIWORD(wp) == BN_CLICKED && slot >= kButtonBase) {
        SendMessageW(GetParent(hwnd_), WM_APP_ACTION, card, slot - kButtonBase);
      } else if (HIWORD(wp) == BN_SETFOCUS) {
        ensure_visible(reinterpret_cast<HWND>(lp));
      }
      return 0;
    }
    case WM_NCDESTROY:
      if (card_brush_) DeleteObject(card_brush_);
      card_brush_ = nullptr;
      break;
    default: break;
  }
  return DefWindowProcW(hwnd_, msg, wp, lp);
}

HWND ResultsView::make_static(const std::wstring& text, int id, HFONT font) {
  HWND h = CreateWindowExW(0, L"STATIC", text.c_str(), WS_CHILD | WS_VISIBLE | SS_LEFT | SS_NOPREFIX, 0, 0, 10, 10,
                           hwnd_, reinterpret_cast<HMENU>(static_cast<INT_PTR>(id)), GetModuleHandleW(nullptr), nullptr);
  SendMessageW(h, WM_SETFONT, reinterpret_cast<WPARAM>(font), FALSE);
  return h;
}

HWND ResultsView::make_button(const std::wstring& text, int id) {
  HWND h = CreateWindowExW(0, L"BUTTON", text.c_str(),
                           WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_PUSHBUTTON | BS_NOTIFY, 0, 0, 10, 10, hwnd_,
                           reinterpret_cast<HMENU>(static_cast<INT_PTR>(id)), GetModuleHandleW(nullptr), nullptr);
  SendMessageW(h, WM_SETFONT, reinterpret_cast<WPARAM>(style_->fonts.normal), FALSE);
  apply_control_theme(h, style_->colors.dark);
  EnableWindow(h, enabled_ ? TRUE : FALSE);
  return h;
}

void ResultsView::clear() {
  for (Card& c : cards_) {
    for (HWND h : c.statics) if (h) DestroyWindow(h);
    for (HWND h : c.buttons) DestroyWindow(h);
  }
  cards_.clear();
  scroll_ = 0;
  content_height_ = 0;
  if (hwnd_ && style_) relayout();
}

void ResultsView::set_report(const neden::diagnose::Report& report, bool winget_available) {
  using neden::diagnose::Finding;
  clear();
  recreate_brush();
  const Fonts& f = style_->fonts;
  cards_.reserve(report.findings.size());
  for (size_t i = 0; i < report.findings.size(); ++i) {
    const Finding& fd = report.findings[i];
    cards_.emplace_back();
    Card& c = cards_.back();
    c.finding = fd;
    c.statics.assign(7, nullptr);
    c.statics[kTitle] = make_static(widen(fd.title), control_id(i, kTitle), f.title);
    if (!fd.certain) c.statics[kTag] = make_static(tr(S::NotCertain), control_id(i, kTag), f.small_);
    if (!fd.explanation.empty()) {
      c.statics[kExplain] = make_static(widen(fd.explanation), control_id(i, kExplain), f.normal);
    }
    if (!fd.evidence.empty()) {
      c.statics[kEvidence] = make_static(join_evidence(fd.evidence), control_id(i, kEvidence), f.mono);
    }
    if (fd.fix && !fd.fix->steps.empty()) {
      c.statics[kStepsLabel] = make_static(tr(S::HowToFix), control_id(i, kStepsLabel), f.bold);
      c.statics[kSteps] = make_static(widen(fd.fix->steps), control_id(i, kSteps), f.normal);
    }
    c.statics[kStatus] = make_static(L"", control_id(i, kStatus), f.bold);
    ShowWindow(c.statics[kStatus], SW_HIDE);
    if (fd.fix) {
      const auto& fx = *fd.fix;
      auto add = [&](Action a, S label) {
        c.buttons.push_back(make_button(tr(label), control_id(i, kButtonBase + static_cast<int>(a))));
      };
      if (!fx.winget_id.empty() && winget_available) {
        add(Action::InstallWinget, S::InstallWinget);
      } else if (!fx.url.empty()) {
        add(Action::DownloadInstall, S::DownloadInstall);
      }
      if (fx.info_url.rfind("https://", 0) == 0) add(Action::OpenPage, S::OfficialPage);
      if (!fx.command.empty()) add(Action::CopyCommand, S::CopyCommand);
      if (fd.rule == "missing-program-file" && !fd.certain) add(Action::ReportUnknown, S::ReportUnknown);
    }
  }
  relayout();
}

void ResultsView::set_enabled(bool enabled) {
  enabled_ = enabled;
  for (Card& c : cards_) for (HWND b : c.buttons) EnableWindow(b, enabled ? TRUE : FALSE);
}

const neden::diagnose::Finding* ResultsView::finding(size_t card) const {
  return card < cards_.size() ? &cards_[card].finding : nullptr;
}

void ResultsView::set_card_status(size_t card, const std::wstring& text) {
  if (card >= cards_.size()) return;
  Card& c = cards_[card];
  c.status = text;
  SetWindowTextW(c.statics[kStatus], text.c_str());
  ShowWindow(c.statics[kStatus], text.empty() ? SW_HIDE : SW_SHOW);
  relayout();
}

void ResultsView::refresh_style() {
  if (!style_) return;
  recreate_brush();
  const Fonts& f = style_->fonts;
  for (Card& c : cards_) {
    const HFONT fonts[7] = {f.title, f.small_, f.normal, f.mono, f.bold, f.normal, f.bold};
    for (size_t s = 0; s < 7; ++s) if (c.statics[s]) SendMessageW(c.statics[s], WM_SETFONT, reinterpret_cast<WPARAM>(fonts[s]), FALSE);
    for (HWND b : c.buttons) {
      SendMessageW(b, WM_SETFONT, reinterpret_cast<WPARAM>(f.normal), FALSE);
      apply_control_theme(b, style_->colors.dark);
    }
  }
  relayout();
}

void ResultsView::layout_pass(int cw) {
  const Style& st = *style_;
  HDC dc = GetDC(hwnd_);
  const int margin = st.px(12), pad = st.px(14), bar = st.px(5);
  const int card_w = std::max(cw - 2 * margin, st.px(100));
  const int tx = margin + bar + pad;
  const int tw = card_w - bar - 2 * pad;
  const HFONT fonts[7] = {st.fonts.title, st.fonts.small_, st.fonts.normal, st.fonts.mono,
                          st.fonts.bold,  st.fonts.normal, st.fonts.bold};
  const int gaps[7] = {0, st.px(2), st.px(8), st.px(10), st.px(10), st.px(2), st.px(8)};

  int y = margin;
  for (Card& c : cards_) {
    c.items.clear();
    c.top = y;
    int cy = y + pad;
    bool first = true;
    for (int s = 0; s < 7; ++s) {
      HWND h = c.statics[static_cast<size_t>(s)];
      if (!h || (s == kStatus && c.status.empty())) continue;
      const std::wstring text = window_text(h);
      const int th = measure_text_height(dc, fonts[s], text.c_str(), tw) + st.px(2);
      if (!first) cy += gaps[s];
      first = false;
      c.items.push_back({h, RECT{tx, cy, tx + tw, cy + th}});
      cy += th;
    }
    if (!c.buttons.empty()) {
      const int bh = st.px(30), hgap = st.px(8), vgap = st.px(8);
      cy += first ? 0 : st.px(12);
      int x = tx;
      for (HWND b : c.buttons) {
        const std::wstring text = window_text(b);
        const int bw = measure_text_width(dc, st.fonts.normal, text.c_str()) + st.px(32);
        if (x > tx && x + bw > tx + tw) {
          x = tx;
          cy += bh + vgap;
        }
        c.items.push_back({b, RECT{x, cy, x + bw, cy + bh}});
        x += bw + hgap;
      }
      cy += bh;
    }
    cy += pad;
    c.height = cy - y;
    y = cy + st.px(10);
  }
  content_height_ = cards_.empty() ? 0 : y - st.px(10) + margin;
  ReleaseDC(hwnd_, dc);
}

void ResultsView::update_scrollbar() {
  RECT rc;
  GetClientRect(hwnd_, &rc);
  scroll_ = std::max(0, std::min(scroll_, std::max(0, content_height_ - static_cast<int>(rc.bottom))));
  SCROLLINFO si{sizeof(si), SIF_RANGE | SIF_PAGE | SIF_POS};
  si.nMin = 0;
  si.nMax = std::max(0, content_height_ - 1);
  si.nPage = static_cast<UINT>(rc.bottom);
  si.nPos = scroll_;
  SetScrollInfo(hwnd_, SB_VERT, &si, TRUE);
}

void ResultsView::apply_positions() {
  int count = 0;
  for (const Card& c : cards_) count += static_cast<int>(c.items.size());
  if (count == 0) return;
  HDWP dwp = BeginDeferWindowPos(count);
  for (const Card& c : cards_) {
    for (const Item& it : c.items) {
      if (!dwp) break;
      dwp = DeferWindowPos(dwp, it.hwnd, nullptr, it.rect.left, it.rect.top - scroll_, it.rect.right - it.rect.left,
                           it.rect.bottom - it.rect.top, SWP_NOZORDER | SWP_NOACTIVATE);
    }
  }
  if (dwp) EndDeferWindowPos(dwp);
}

void ResultsView::relayout() {
  if (!style_ || !hwnd_) return;
  RECT rc;
  GetClientRect(hwnd_, &rc);
  layout_pass(rc.right);
  update_scrollbar();
  RECT rc2;
  GetClientRect(hwnd_, &rc2);  // a scroll bar may have appeared or vanished
  if (rc2.right != rc.right) {
    layout_pass(rc2.right);
    update_scrollbar();
  }
  apply_positions();
  RedrawWindow(hwnd_, nullptr, nullptr, RDW_INVALIDATE | RDW_ERASE | RDW_ALLCHILDREN);
}

void ResultsView::scroll_to(int pos) {
  RECT rc;
  GetClientRect(hwnd_, &rc);
  pos = std::max(0, std::min(pos, std::max(0, content_height_ - static_cast<int>(rc.bottom))));
  if (pos == scroll_) return;
  const int delta = scroll_ - pos;
  scroll_ = pos;
  SCROLLINFO si{sizeof(si), SIF_POS};
  si.nPos = pos;
  SetScrollInfo(hwnd_, SB_VERT, &si, TRUE);
  ScrollWindowEx(hwnd_, 0, delta, nullptr, nullptr, nullptr, nullptr, SW_SCROLLCHILDREN | SW_INVALIDATE | SW_ERASE);
  UpdateWindow(hwnd_);
}

void ResultsView::ensure_visible(HWND child) {
  RECT r, rc;
  GetWindowRect(child, &r);
  MapWindowPoints(nullptr, hwnd_, reinterpret_cast<POINT*>(&r), 2);
  GetClientRect(hwnd_, &rc);
  const int m = style_->px(12);
  if (r.top < 0) {
    scroll_to(scroll_ + r.top - m);
  } else if (r.bottom > rc.bottom) {
    scroll_to(scroll_ + r.bottom - rc.bottom + m);
  }
}

void ResultsView::paint(HDC dc, const RECT& client) {
  const Colors& col = style_->colors;
  HBRUSH bg = CreateSolidBrush(col.bg);
  FillRect(dc, &client, bg);
  DeleteObject(bg);

  const int margin = style_->px(12);
  const int radius = style_->px(10);
  const int bar = style_->px(5);
  HPEN pen = CreatePen(PS_SOLID, 1, col.border);
  HBRUSH fill = CreateSolidBrush(col.card);
  HGDIOBJ old_pen = SelectObject(dc, pen);
  HGDIOBJ old_brush = SelectObject(dc, fill);
  for (const Card& c : cards_) {
    const int top = c.top - scroll_;
    if (top > client.bottom || top + c.height < 0) continue;
    const RECT cr{margin, top, client.right - margin, top + c.height};
    RoundRect(dc, cr.left, cr.top, cr.right, cr.bottom, radius, radius);
    COLORREF barc = col.bar_info;
    if (c.finding.severity == neden::diagnose::Severity::Error) barc = col.bar_error;
    if (c.finding.severity == neden::diagnose::Severity::Warning) barc = col.bar_warning;
    HRGN rgn = CreateRoundRectRgn(cr.left + 1, cr.top + 1, cr.right, cr.bottom, radius, radius);
    SelectClipRgn(dc, rgn);
    HBRUSH bb = CreateSolidBrush(barc);
    const RECT br{cr.left, cr.top, cr.left + bar + 1, cr.bottom};
    FillRect(dc, &br, bb);
    DeleteObject(bb);
    SelectClipRgn(dc, nullptr);
    DeleteObject(rgn);
  }
  SelectObject(dc, old_pen);
  SelectObject(dc, old_brush);
  DeleteObject(pen);
  DeleteObject(fill);
}

}  // namespace gui
