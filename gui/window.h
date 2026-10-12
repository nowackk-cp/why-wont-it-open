#pragma once

#include <windows.h>

#include <atomic>
#include <string>

#include "neden/diagnose.h"
#include "results_view.h"
#include "theme.h"

namespace gui {

class MainWindow {
 public:
  static bool register_class(HINSTANCE hinst);
  bool create(HINSTANCE hinst, int show, const std::wstring& initial_file);
  HWND hwnd() const { return hwnd_; }

 private:
  enum class Mode { Home, Busy, Results };

  static LRESULT CALLBACK static_proc(HWND, UINT, WPARAM, LPARAM);
  LRESULT proc(UINT msg, WPARAM wp, LPARAM lp);

  void on_create();
  void create_controls();
  void apply_fonts();
  void apply_theme(bool dark);
  void set_mode(Mode m);
  void layout();
  void paint(HDC dc, const RECT& client);
  void reload_icon();
  void place_window(int show);
  SIZE window_size_for_client(int client_w, int client_h) const;

  void choose_file();
  void open_file(std::wstring path);
  void start_diagnosis(const std::wstring& path);
  void on_diagnosis_done(LPARAM lp);
  void on_action(size_t card, Action action);
  void on_fix_done(LPARAM lp);
  void start_fix(size_t card, bool winget);
  void copy_report();
  void show_about();
  void set_busy_inputs(bool busy);
  void update_header();

  HWND hwnd_ = nullptr;
  HINSTANCE hinst_ = nullptr;
  Style style_;
  Mode mode_ = Mode::Home;
  Mode mode_before_busy_ = Mode::Home;
  bool fix_busy_ = false;

  HWND prompt_ = nullptr, hint_ = nullptr, choose_ = nullptr, progress_ = nullptr;
  HWND head_name_ = nullptr, head_sub_ = nullptr, copy_ = nullptr, another_ = nullptr, about_ = nullptr;
  ResultsView view_;

  HBRUSH bg_brush_ = nullptr, card_brush_ = nullptr;
  HICON icon_big_ = nullptr, icon_zone_ = nullptr;
  RECT zone_{}, icon_rect_{};
  int bar_top_ = 0;

  std::wstring program_path_;
  neden::diagnose::Report report_;
  bool has_report_ = false;
  bool winget_ok_ = false;
  std::wstring report_text_;  // CRLF, ready for the clipboard
  size_t status_clear_card_ = static_cast<size_t>(-1);
  int last_percent_ = -2;
  bool dragging_hint_ = false;
};

}  // namespace gui
