// Scrollable list of finding "cards".
//
// Design: the card background and the colored severity bar are painted by this
// window, but every piece of text is a real STATIC control and every action a
// real BUTTON. UI Automation / MSAA therefore expose the text and the buttons
// natively (screen readers read them in creation order), tab order and
// Enter/Space activation come for free, and no custom accessibility provider
// is needed.
#pragma once

#include <windows.h>

#include <string>
#include <vector>

#include "neden/diagnose.h"
#include "theme.h"

namespace gui {

class ResultsView {
 public:
  static bool register_class(HINSTANCE hinst);

  HWND create(HWND parent, HINSTANCE hinst, int control_id);
  HWND hwnd() const { return hwnd_; }

  // `style` must outlive the view; call refresh_style() after it changed (DPI, fonts, theme).
  void set_style(const Style* style) { style_ = style; }
  void refresh_style();

  void set_report(const neden::diagnose::Report& report, bool winget_available);
  void clear();
  void set_enabled(bool enabled);
  void set_card_status(size_t card, const std::wstring& text);
  const neden::diagnose::Finding* finding(size_t card) const;

 private:
  struct Item {
    HWND hwnd = nullptr;
    RECT rect{};  // in content coordinates (scroll offset not applied)
  };
  struct Card {
    neden::diagnose::Finding finding;
    std::vector<HWND> statics;  // title, tag, explanation, evidence, steps label, steps, status (nullable)
    std::vector<HWND> buttons;
    std::wstring status;
    int top = 0, height = 0;
    std::vector<Item> items;
  };

  static LRESULT CALLBACK static_proc(HWND, UINT, WPARAM, LPARAM);
  LRESULT proc(UINT msg, WPARAM wp, LPARAM lp);

  HWND make_static(const std::wstring& text, int id, HFONT font);
  HWND make_button(const std::wstring& text, int id);
  void relayout();
  void layout_pass(int client_width);
  void apply_positions();
  void update_scrollbar();
  void scroll_to(int pos);
  void ensure_visible(HWND child);
  void paint(HDC dc, const RECT& client);
  COLORREF static_color(int slot) const;
  void recreate_brush();

  HWND hwnd_ = nullptr;
  const Style* style_ = nullptr;
  std::vector<Card> cards_;
  int scroll_ = 0;
  int content_height_ = 0;
  HBRUSH card_brush_ = nullptr;
  bool enabled_ = true;
};

}  // namespace gui
