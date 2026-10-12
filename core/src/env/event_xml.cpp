#include "env/event_xml.h"

#include <cctype>
#include <cstdlib>
#include <string>

namespace neden::env {

namespace {

// Days from 1601-01-01 to y-m-d (proleptic Gregorian).
std::int64_t days_from_civil(std::int64_t y, unsigned m, unsigned d) {
  y -= m <= 2;
  const std::int64_t era = (y >= 0 ? y : y - 399) / 400;
  const unsigned yoe = static_cast<unsigned>(y - era * 400);
  const unsigned doy = (153 * (m > 2 ? m - 3 : m + 9) + 2) / 5 + d - 1;
  const unsigned doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
  const std::int64_t days_since_1970 = era * 146097 + static_cast<std::int64_t>(doe) - 719468;
  return days_since_1970 + 134774;  // 1601-01-01 .. 1970-01-01
}

void append_utf8(std::string& out, unsigned long cp) {
  if (cp < 0x80) {
    out += static_cast<char>(cp);
  } else if (cp < 0x800) {
    out += static_cast<char>(0xC0 | (cp >> 6));
    out += static_cast<char>(0x80 | (cp & 0x3F));
  } else if (cp < 0x10000) {
    out += static_cast<char>(0xE0 | (cp >> 12));
    out += static_cast<char>(0x80 | ((cp >> 6) & 0x3F));
    out += static_cast<char>(0x80 | (cp & 0x3F));
  } else if (cp <= 0x10FFFF) {
    out += static_cast<char>(0xF0 | (cp >> 18));
    out += static_cast<char>(0x80 | ((cp >> 12) & 0x3F));
    out += static_cast<char>(0x80 | ((cp >> 6) & 0x3F));
    out += static_cast<char>(0x80 | (cp & 0x3F));
  }
}

std::string decode_entities(std::string_view s) {
  std::string out;
  out.reserve(s.size());
  for (std::size_t i = 0; i < s.size(); ++i) {
    if (s[i] != '&') {
      out += s[i];
      continue;
    }
    const std::size_t semi = s.find(';', i);
    if (semi == std::string_view::npos || semi - i > 10) {
      out += s[i];
      continue;
    }
    const std::string_view ent = s.substr(i + 1, semi - i - 1);
    if (ent == "amp") {
      out += '&';
    } else if (ent == "lt") {
      out += '<';
    } else if (ent == "gt") {
      out += '>';
    } else if (ent == "quot") {
      out += '"';
    } else if (ent == "apos") {
      out += '\'';
    } else if (ent.size() > 1 && ent[0] == '#') {
      const bool hex = ent[1] == 'x' || ent[1] == 'X';
      const std::string num(ent.substr(hex ? 2 : 1));
      char* end = nullptr;
      const unsigned long cp = std::strtoul(num.c_str(), &end, hex ? 16 : 10);
      if (num.empty() || *end != '\0') {
        out += s[i];
        continue;
      }
      append_utf8(out, cp);
    } else {
      out += s[i];
      continue;
    }
    i = semi;
  }
  return out;
}

// Value of attribute `name` inside a tag's text; handles ' and ".
std::string attribute(std::string_view tag, std::string_view name) {
  std::size_t pos = 0;
  while ((pos = tag.find(name, pos)) != std::string_view::npos) {
    const bool boundary = pos == 0 || std::isspace(static_cast<unsigned char>(tag[pos - 1]));
    std::size_t p = pos + name.size();
    pos = p;
    if (!boundary) continue;
    while (p < tag.size() && std::isspace(static_cast<unsigned char>(tag[p]))) ++p;
    if (p >= tag.size() || tag[p] != '=') continue;
    ++p;
    while (p < tag.size() && std::isspace(static_cast<unsigned char>(tag[p]))) ++p;
    if (p >= tag.size() || (tag[p] != '\'' && tag[p] != '"')) continue;
    const char quote = tag[p++];
    const std::size_t end = tag.find(quote, p);
    if (end == std::string_view::npos) return {};
    return decode_entities(tag.substr(p, end - p));
  }
  return {};
}

// Finds "<name" (followed by space, '>' or '/') at or after `from`; npos if none.
std::size_t find_open_tag(std::string_view xml, std::string_view name, std::size_t from) {
  const std::string needle = "<" + std::string(name);
  while (true) {
    const std::size_t p = xml.find(needle, from);
    if (p == std::string_view::npos) return p;
    const std::size_t after = p + needle.size();
    if (after >= xml.size()) return std::string_view::npos;
    const char c = xml[after];
    if (c == ' ' || c == '>' || c == '/' || c == '\t' || c == '\r' || c == '\n') return p;
    from = after;
  }
}

}  // namespace

std::uint64_t parse_system_time(std::string_view iso) {
  // YYYY-MM-DDTHH:MM:SS[.fffffff]Z
  if (iso.size() < 19) return 0;
  auto num = [&](std::size_t at, std::size_t len) -> int {
    int v = 0;
    for (std::size_t i = 0; i < len; ++i) {
      const char c = iso[at + i];
      if (c < '0' || c > '9') return -1;
      v = v * 10 + (c - '0');
    }
    return v;
  };
  const int y = num(0, 4), mo = num(5, 2), d = num(8, 2), h = num(11, 2), mi = num(14, 2), s = num(17, 2);
  if (y < 1601 || mo < 1 || mo > 12 || d < 1 || d > 31 || h < 0 || h > 23 || mi < 0 || mi > 59 || s < 0 || s > 60) {
    return 0;
  }
  std::uint64_t ticks = 0;
  if (iso.size() > 20 && iso[19] == '.') {
    std::uint64_t scale = 1000000;  // first digit = 1e-1 s = 1e6 ticks
    for (std::size_t i = 20; i < iso.size() && iso[i] >= '0' && iso[i] <= '9' && scale > 0; ++i) {
      ticks += static_cast<std::uint64_t>(iso[i] - '0') * scale;
      scale /= 10;
    }
  }
  const std::int64_t days = days_from_civil(y, static_cast<unsigned>(mo), static_cast<unsigned>(d));
  const std::uint64_t secs =
      static_cast<std::uint64_t>(days) * 86400ull + static_cast<std::uint64_t>(h * 3600 + mi * 60 + s);
  return secs * 10000000ull + ticks;
}

bool parse_event_xml(std::string_view xml, EventRecord& out) {
  const std::size_t sys_end = xml.find("</System>");
  const std::string_view sys = xml.substr(0, sys_end == std::string_view::npos ? xml.size() : sys_end);

  if (const std::size_t p = find_open_tag(sys, "Provider", 0); p != std::string_view::npos) {
    const std::size_t e = sys.find('>', p);
    if (e != std::string_view::npos) out.provider = attribute(sys.substr(p, e - p), "Name");
  }
  if (const std::size_t p = find_open_tag(sys, "EventID", 0); p != std::string_view::npos) {
    const std::size_t gt = sys.find('>', p);
    const std::size_t lt = gt == std::string_view::npos ? gt : sys.find('<', gt);
    if (gt == std::string_view::npos || lt == std::string_view::npos) return false;
    const std::string text(sys.substr(gt + 1, lt - gt - 1));
    char* end = nullptr;
    const unsigned long id = std::strtoul(text.c_str(), &end, 10);
    if (text.empty() || end == text.c_str()) return false;
    out.id = static_cast<std::uint32_t>(id);
  } else {
    return false;
  }
  if (const std::size_t p = find_open_tag(sys, "TimeCreated", 0); p != std::string_view::npos) {
    const std::size_t e = sys.find('>', p);
    if (e != std::string_view::npos) out.time = parse_system_time(attribute(sys.substr(p, e - p), "SystemTime"));
  }
  if (const std::size_t p = sys.find("<Channel>"); p != std::string_view::npos) {
    const std::size_t e = sys.find("</Channel>", p);
    if (e != std::string_view::npos) out.channel = decode_entities(sys.substr(p + 9, e - p - 9));
  }

  // <EventData>: every <Data ...>value</Data> / <Data/> in order.
  out.data.clear();
  out.names.clear();
  std::size_t from = sys_end == std::string_view::npos ? 0 : sys_end;
  while (true) {
    const std::size_t p = find_open_tag(xml, "Data", from);
    if (p == std::string_view::npos) break;
    const std::size_t gt = xml.find('>', p);
    if (gt == std::string_view::npos) break;
    const std::string_view tag = xml.substr(p, gt - p);
    const std::string name = attribute(tag, "Name");
    if (!tag.empty() && tag.back() == '/') {
      out.data.emplace_back();
      out.names.push_back(name);
      from = gt + 1;
      continue;
    }
    const std::size_t close = xml.find("</Data>", gt);
    if (close == std::string_view::npos) break;
    out.data.push_back(decode_entities(xml.substr(gt + 1, close - gt - 1)));
    out.names.push_back(name);
    from = close + 7;
  }
  return true;
}

}  // namespace neden::env
