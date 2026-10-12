#include "strings.h"

#include <windows.h>

#include <cstdarg>
#include <cstdio>

namespace gui {
namespace {

struct Entry {
  const wchar_t* en;
  const wchar_t* tr;
};

neden::diagnose::Lang g_lang = neden::diagnose::Lang::En;

// Order must match enum class S.
const Entry kTable[] = {
    {L"Why Won't It Open?", L"Neden Açılmıyor?"},
    {L"Drag the program that won't open here",
     L"Açılmayan programı buraya sürükleyin"},
    {L"The file is only read, never run. Nothing is sent anywhere.",
     L"Dosya yalnızca okunur, asla çalıştırılmaz. Hiçbir şey gönderilmez."},
    {L"Choose file…", L"Dosya seç…"},
    {L"Analysing…", L"İnceleniyor…"},
    {L"Copy report", L"Raporu kopyala"},
    {L"Copied!", L"Kopyalandı!"},
    {L"Analyse another…", L"Başka dosya incele…"},
    {L"About", L"Hakkında"},
    {L"Results", L"Sonuçlar"},
    {L"%s program", L"%s program"},
    {L"(not certain)", L"(kesin değil)"},
    {L"What to do", L"Ne yapmalı"},
    {L"Install with winget", L"winget ile kur"},
    {L"Download && install", L"İndir ve kur"},
    {L"Official page", L"Resmi sayfa"},
    {L"Copy command", L"Komutu kopyala"},
    {L"Install component", L"Bileşeni kur"},
    {L"Install %1 (%2) with winget?\n\nSource: winget, package \"%3\".\n\nA console window shows the progress. "
     L"Windows may ask for administrator permission. Afterwards the program is checked again.",
     L"%1 (%2), winget ile kurulsun mu?\n\nKaynak: winget, paket \"%3\".\n\nİlerleme bir konsol penceresinde "
     L"gösterilir. Windows yönetici izni isteyebilir. Ardından program yeniden incelenir."},
    {L"Download and install %1 (%2)?\n\nSource: %3 (official download).\n\nThe file is only started if its digital "
     L"signature is valid and was issued to \"%4\". Windows may ask for administrator permission. Afterwards the "
     L"program is checked again.",
     L"%1 (%2) indirilip kurulsun mu?\n\nKaynak: %3 (resmi indirme).\n\nDosya yalnızca dijital imzası geçerliyse "
     L"ve \"%4\" adına verilmişse başlatılır. Windows yönetici izni isteyebilir. Ardından "
     L"program yeniden incelenir."},
    {L"Install", L"Kur"},
    {L"Cancel", L"Vazgeç"},
    {L"Installing… follow the installer window.",
     L"Kuruluyor… kurulum penceresini izleyin."},
    {L"Downloading… %d%%", L"İndiriliyor… %%%d"},
    {L"Downloading…", L"İndiriliyor…"},
    {L"Done. Checking the program again…", L"Tamamlandı. Program yeniden inceleniyor…"},
    {L"That did not work: %s", L"Olmadı: %s"},
    {L"The analysis failed: %s", L"İnceleme başarısız oldu: %s"},
    {L"Choose the program that won't open", L"Açılmayan programı seçin"},
    {L"Programs (*.exe, *.dll)", L"Programlar (*.exe, *.dll)"},
    {L"All files (*.*)", L"Tüm dosyalar (*.*)"},
    {L"About Why Won't It Open?", L"Neden Açılmıyor? Hakkında"},
    {L"Version %s\n\nFinds out why a Windows program won't start - by reading the file only. It never runs the "
     L"program and sends nothing anywhere.\n\nhttps://github.com/nowackk-cp/why-wont-it-open",
     L"Sürüm %s\n\nBir Windows programının neden açılmadığını yalnızca dosyayı "
     L"okuyarak bulur. Programı asla çalıştırmaz, hiçbir yere bir şey göndermez.\n\n"
     L"https://github.com/nowackk-cp/why-wont-it-open"},
    {L"Close", L"Kapat"},
    {L"The clipboard could not be opened.", L"Panoya erişilemedi."},
    {L"Report unknown DLL", L"Bilinmeyen DLL'i bildir"},
    {L"This opens a new GitHub issue in your browser so the DLL can be added to the knowledge base.\n\n"
     L"Only these file names are included - nothing else about you or your computer:\n\n%s\n\n"
     L"You can review and edit the issue before submitting it.",
     L"Bu, DLL'in bilgi tabanına eklenebilmesi için tarayıcınızda yeni bir GitHub issue açar.\n\n"
     L"Yalnızca şu dosya adları eklenir; sizinle ya da bilgisayarınızla ilgili başka hiçbir şey eklenmez:\n\n%s\n\n"
     L"Göndermeden önce issue'yu inceleyip düzenleyebilirsiniz."},
};
static_assert(sizeof(kTable) / sizeof(kTable[0]) == static_cast<size_t>(S::Count_), "string table out of sync");

}  // namespace

void set_language(neden::diagnose::Lang lang) { g_lang = lang; }
neden::diagnose::Lang language() { return g_lang; }

const wchar_t* tr(S id) {
  const Entry& e = kTable[static_cast<size_t>(id)];
  return g_lang == neden::diagnose::Lang::Tr ? e.tr : e.en;
}

std::wstring trf(S id, ...) {
  va_list args;
  va_start(args, id);
  wchar_t buf[1024];
  _vsnwprintf_s(buf, _countof(buf), _TRUNCATE, tr(id), args);
  va_end(args);
  return buf;
}

std::wstring subst(S id, std::initializer_list<std::wstring> args) {
  const std::wstring fmt = tr(id);
  std::wstring out;
  for (size_t i = 0; i < fmt.size(); ++i) {
    if (fmt[i] == L'%' && i + 1 < fmt.size() && fmt[i + 1] >= L'1' && fmt[i + 1] <= L'9') {
      const size_t idx = static_cast<size_t>(fmt[i + 1] - L'1');
      if (idx < args.size()) out += *(args.begin() + idx);
      ++i;
    } else {
      out += fmt[i];
    }
  }
  return out;
}

std::wstring widen(const std::string& utf8) {
  if (utf8.empty()) return {};
  const int n = MultiByteToWideChar(CP_UTF8, 0, utf8.data(), static_cast<int>(utf8.size()), nullptr, 0);
  if (n <= 0) return {};
  std::wstring out(static_cast<size_t>(n), L'\0');
  MultiByteToWideChar(CP_UTF8, 0, utf8.data(), static_cast<int>(utf8.size()), out.data(), n);
  return out;
}

std::string narrow(const std::wstring& wide) {
  if (wide.empty()) return {};
  const int n = WideCharToMultiByte(CP_UTF8, 0, wide.data(), static_cast<int>(wide.size()), nullptr, 0, nullptr, nullptr);
  if (n <= 0) return {};
  std::string out(static_cast<size_t>(n), '\0');
  WideCharToMultiByte(CP_UTF8, 0, wide.data(), static_cast<int>(wide.size()), out.data(), n, nullptr, nullptr);
  return out;
}

}  // namespace gui
