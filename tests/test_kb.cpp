#include <string>

#include "kb/json.h"
#include "neden/kb.h"
#include "test.h"

using neden::kb::KnowledgeBase;
namespace json = neden::json;

namespace {

std::string parse_error(const std::string& text) {
  std::string err;
  auto v = json::parse(text, &err);
  CHECK(!v.has_value());
  CHECK(!err.empty());
  return err;
}

const char* kMini = R"({
  "dlls": {
    "MSVCP140.dll": { "package": "vc" },
    "vcruntime140_1.dll": { "package": "vc", "arch": ["x64"] },
    "api-ms-win-crt-*": { "package": "ucrt" },
    "api-ms-win-crt-runtime-l1-1-0.dll": { "package": "vc" },
    "api-ms-win-*": { "package": "ucrt" },
    "ucrtbased.dll": { "debugOnly": true },
    "steam_api.dll": { "programFile": true },
    "vulkan-1.dll": { "gpuDriver": true }
  },
  "packages": {
    "vc": { "name": "VC", "winget": { "x86": "A.x86", "any": "A.any" },
            "url": { "x64": "https://example.com/x64.exe" }, "infoUrl": "https://example.com/", "signer": "S" },
    "ucrt": { "name": "UCRT", "kind": "windows-feature", "extra": [1, 2, {"a": null}] }
  },
  "$comment": "ignored"
})";

}  // namespace

TEST(json_scalars_and_containers) {
  auto v = json::parse(R"( {"a": [1, -2.5e2, true, false, null, "x"], "b": {}} )");
  REQUIRE(v.has_value());
  REQUIRE(v->is_object());
  const json::Value* a = v->find("a");
  REQUIRE(a && a->is_array());
  REQUIRE(a->as_array().size() == 6);
  CHECK(a->as_array()[0].as_number() == 1.0);
  CHECK(a->as_array()[1].as_number() == -250.0);
  CHECK(a->as_array()[2].as_bool());
  CHECK(a->as_array()[3].is_bool() && !a->as_array()[3].as_bool());
  CHECK(a->as_array()[4].is_null());
  CHECK(a->as_array()[5].as_string() == "x");
  CHECK(v->find("b")->is_object());
  CHECK(v->find("missing") == nullptr);
  // Wrong-type accessors are neutral.
  CHECK(a->as_string().empty());
  CHECK(a->as_object().empty());
}

TEST(json_string_escapes) {
  auto v = json::parse(R"("a\"b\\c\/d\b\f\n\r\t")");
  REQUIRE(v.has_value());
  CHECK(v->as_string() == "a\"b\\c/d\b\f\n\r\t");
}

TEST(json_unicode_escapes) {
  auto v = json::parse(R"("Aé€😀")");
  REQUIRE(v.has_value());
  CHECK(v->as_string() == "A\xC3\xA9\xE2\x82\xAC\xF0\x9F\x98\x80");
  CHECK(json::parse(R"("\u0000")")->as_string().size() == 1);
  // Raw UTF-8 passes through.
  CHECK(json::parse("\"\xC3\xA9\"")->as_string() == "\xC3\xA9");
}

TEST(json_bad_unicode_escapes) {
  parse_error(R"("\ud83d")");        // lone high surrogate
  parse_error(R"("\ud83dx")");
  parse_error(R"("\ud83dA")");  // high followed by non-low
  parse_error(R"("\ude00")");        // lone low surrogate
  parse_error(R"("\u12")");          // truncated
  parse_error(R"("\u12G4")");        // bad hex
}

TEST(json_bad_strings) {
  parse_error(R"("abc)");              // unterminated
  parse_error("\"a\nb\"");             // raw control character
  parse_error(R"("\x")");              // invalid escape
  parse_error(R"("abc\)");             // dangling backslash
}

TEST(json_bad_numbers) {
  for (const char* s : {"-", "01", "1.", ".5", "+1", "1e", "1e+", "--1", "0x10", "NaN", "Infinity", "1e999"}) {
    CHECK(!json::parse(s).has_value());
  }
  CHECK(json::parse("-0")->as_number() == 0.0);
  CHECK(json::parse("0.5E-1")->as_number() == 0.05);
}

TEST(json_structure_errors) {
  for (const char* s : {"", "   ", "[", "{", "[1,]", "{\"a\":1,}", "{\"a\"}", "{a:1}", "[1 2]", "{\"a\":1 \"b\":2}",
                        "tru", "nul", "'a'", "[}", "{\"a\":}"}) {
    CHECK(!json::parse(s).has_value());
  }
}

TEST(json_trailing_garbage) {
  CHECK(!json::parse("{} x").has_value());
  CHECK(!json::parse("1 2").has_value());
  CHECK(!json::parse("[]]").has_value());
  CHECK(json::parse("  [] \n\t ").has_value());
}

TEST(json_error_position) {
  std::string err = parse_error("{\n  \"a\": ?\n}");
  CHECK(err.find("line 2, column 8") == 0);
}

TEST(json_bom_and_duplicate_keys) {
  CHECK(json::parse("\xEF\xBB\xBF[1]").has_value());
  auto v = json::parse(R"({"a":1,"a":2})");
  REQUIRE(v.has_value());
  CHECK(v->find("a")->as_number() == 2.0);
}

TEST(json_depth_limit) {
  auto nest = [](int n) { return std::string(static_cast<size_t>(n), '[') + std::string(static_cast<size_t>(n), ']'); };
  CHECK(json::parse(nest(32)).has_value());
  CHECK(json::parse(nest(json::kMaxDepth)).has_value());
  std::string err = parse_error(nest(json::kMaxDepth + 2));
  CHECK(err.find("nesting") != std::string::npos);
  // Must not blow the stack.
  CHECK(!json::parse(nest(200000)).has_value());
}

TEST(kb_from_json_basic) {
  std::string err;
  auto kb = KnowledgeBase::from_json(kMini, &err);
  REQUIRE(kb.has_value());
  CHECK(kb->dlls().size() == 8);
  CHECK(kb->packages().size() == 2);
  const auto* p = kb->find_package("vc");
  REQUIRE(p != nullptr);
  CHECK(p->kind == "redist");  // default
  CHECK(kb->find_package("ucrt")->kind == "windows-feature");
  CHECK(kb->find_package("nope") == nullptr);
  // Keys are normalised to lower case; lookup is case-insensitive.
  const auto* d = kb->find_dll("MsVcP140.DLL");
  REQUIRE(d != nullptr);
  CHECK(d->name == "msvcp140.dll");
  CHECK(d->package == "vc");
  CHECK(d->arch.empty());
  const auto* d2 = kb->find_dll("vcruntime140_1.dll");
  REQUIRE(d2 != nullptr);
  CHECK(d2->arch.size() == 1 && d2->arch[0] == "x64");
}

TEST(kb_flags) {
  auto kb = KnowledgeBase::from_json(kMini);
  REQUIRE(kb.has_value());
  CHECK(kb->find_dll("ucrtbased.dll")->debug_only);
  CHECK(kb->find_dll("ucrtbased.dll")->package.empty());
  CHECK(kb->find_dll("steam_api.dll")->program_file);
  CHECK(kb->find_dll("vulkan-1.dll")->gpu_driver);
  CHECK(!kb->find_dll("msvcp140.dll")->debug_only);
}

TEST(kb_exact_beats_wildcard_and_longest_wildcard_wins) {
  auto kb = KnowledgeBase::from_json(kMini);
  REQUIRE(kb.has_value());
  // Exact entry wins over the wildcard that would also match.
  CHECK(kb->find_dll("API-MS-WIN-CRT-RUNTIME-L1-1-0.DLL")->package == "vc");
  // Longest wildcard prefix wins over shorter one.
  const auto* crt = kb->find_dll("api-ms-win-crt-stdio-l1-1-0.dll");
  REQUIRE(crt != nullptr);
  CHECK(crt->name == "api-ms-win-crt-*");
  const auto* core = kb->find_dll("api-ms-win-core-file-l1-1-0.dll");
  REQUIRE(core != nullptr);
  CHECK(core->name == "api-ms-win-*");
  CHECK(kb->find_dll("kernel32.dll") == nullptr);
  CHECK(kb->find_dll("") == nullptr);
}

TEST(kb_winget_and_url_fallback) {
  auto kb = KnowledgeBase::from_json(kMini);
  REQUIRE(kb.has_value());
  const auto* p = kb->find_package("vc");
  REQUIRE(p != nullptr);
  CHECK(p->winget_for("x86") == "A.x86");
  CHECK(p->winget_for("x64") == "A.any");
  CHECK(p->winget_for("arm64") == "A.any");
  CHECK(p->url_for("x64") == "https://example.com/x64.exe");
  CHECK(p->url_for("x86").empty());
  CHECK(kb->find_package("ucrt")->winget_for("x86").empty());
}

TEST(kb_validation_errors) {
  auto bad = [](const char* text, const char* needle) {
    std::string err;
    auto kb = KnowledgeBase::from_json(text, &err);
    CHECK(!kb.has_value());
    CHECK(err.find(needle) != std::string::npos);
    if (err.find(needle) == std::string::npos) std::fprintf(stderr, "  error was: %s\n", err.c_str());
  };
  bad("{", "JSON");
  bad("[]", "top level");
  bad(R"({"dlls": {}})", "top level");
  bad(R"({"dlls": [], "packages": {}})", "top level");
  bad(R"({"dlls": {"a.dll": {"package": "x"}}, "packages": {}})", "unknown package");
  bad(R"({"dlls": {}, "packages": {"p": {"url": {"x86": "http://e.com/a.exe"}}}})", "https://");
  bad(R"({"dlls": {}, "packages": {"p": {"url": {"x86": "ftp://e.com/a.exe"}}}})", "https://");
  bad(R"({"dlls": {}, "packages": {"p": {"infoUrl": "http://e.com"}}})", "https://");
  bad(R"({"dlls": {}, "packages": {"p": 3}})", "must be an object");
  bad(R"({"dlls": {}, "packages": {"p": {"name": 3}}})", "string");
  bad(R"({"dlls": {"a.dll": 3}, "packages": {}})", "object");
  bad(R"({"dlls": {"a.dll": {}}, "packages": {}})", "needs a");
  bad(R"({"dlls": {"a.dll": {"debugOnly": "yes"}}, "packages": {}})", "true or false");
  bad(R"({"dlls": {"a.dll": {"debugOnly": true, "arch": "x64"}}, "packages": {}})", "array");
  bad(R"({"dlls": {"*": {"debugOnly": true}}, "packages": {}})", "'*'");
  bad(R"({"dlls": {"a*b": {"debugOnly": true}}, "packages": {}})", "'*'");
  bad(R"({"dlls": {"A.dll": {"debugOnly": true}, "a.DLL": {"debugOnly": true}}, "packages": {}})", "twice");
}

TEST(kb_lenient_shapes) {
  std::string err;
  // Unknown top-level keys and unknown fields are ignored; error pointer is optional.
  auto kb = KnowledgeBase::from_json(
      R"({"$comment": "x", "future": 1, "dlls": {"a.dll": {"debugOnly": true, "newField": 1}}, "packages": {}})");
  CHECK(kb.has_value());
  CHECK(KnowledgeBase::from_json("nope").has_value() == false);
}

TEST(kb_embedded_is_consistent) {
  const KnowledgeBase& kb = KnowledgeBase::embedded();
  REQUIRE(!kb.dlls().empty());
  REQUIRE(!kb.packages().empty());
  for (const auto& [key, e] : kb.dlls()) {
    CHECK(key == e.name);
    if (!e.package.empty() && kb.find_package(e.package) == nullptr) {
      std::fprintf(stderr, "  dll %s -> unknown package %s\n", key.c_str(), e.package.c_str());
      CHECK(false);
    }
    for (char c : key) CHECK(!(c >= 'A' && c <= 'Z'));
  }
  for (const auto& [id, p] : kb.packages()) {
    CHECK(!p.name.empty());
    CHECK(p.id == id);
    for (const auto& [arch, u] : p.url) {
      CHECK(u.rfind("https://", 0) == 0);
      CHECK(arch == "x86" || arch == "x64" || arch == "arm64" || arch == "any");
    }
    for (const auto& [arch, w] : p.winget) {
      CHECK(!w.empty());
      CHECK(arch == "x86" || arch == "x64" || arch == "arm64" || arch == "any");
    }
    if (!p.info_url.empty()) CHECK(p.info_url.rfind("https://", 0) == 0);
    if (p.kind == "redist" || p.kind == "windows-feature") CHECK(p.signer == "Microsoft Corporation" || p.id == "physx");
    CHECK(p.kind == "redist" || p.kind == "windows-feature" || p.kind == "driver" || p.kind == "program-file");
    // A redistributable must be obtainable somehow.
    if (p.kind == "redist") CHECK(!p.winget.empty() || !p.url.empty() || !p.info_url.empty());
  }
}

TEST(kb_embedded_lookups) {
  const KnowledgeBase& kb = KnowledgeBase::embedded();

  const auto* ucrt = kb.find_dll("API-MS-WIN-CRT-RUNTIME-L1-1-0.DLL");
  REQUIRE(ucrt != nullptr);
  CHECK(ucrt->package == "ucrt");
  CHECK(kb.find_dll("ucrtbase.dll")->package == "ucrt");

  const auto* msvcp = kb.find_dll("msvcp140.dll");
  REQUIRE(msvcp != nullptr);
  CHECK(msvcp->package == "vcredist14");

  const auto* vc1 = kb.find_dll("VCRUNTIME140_1.dll");
  REQUIRE(vc1 != nullptr);
  CHECK(!vc1->arch.empty());
  bool has_x86 = false;
  for (const auto& a : vc1->arch) has_x86 = has_x86 || a == "x86";
  CHECK(!has_x86);

  const auto* ucrtd = kb.find_dll("ucrtbased.dll");
  REQUIRE(ucrtd != nullptr);
  CHECK(ucrtd->debug_only);
  CHECK(kb.find_dll("VCRUNTIME140D.dll")->debug_only);
  CHECK(kb.find_dll("msvcr100d.dll")->debug_only);

  CHECK(kb.find_dll("msvcr100.dll")->package == "vcredist2010");
  CHECK(kb.find_dll("mfc140u.dll")->package == "vcredist14");
  CHECK(kb.find_dll("mfc140ud.dll")->debug_only);
  CHECK(kb.find_dll("d3dx9_43.dll")->package == "directx-jun2010");
  CHECK(kb.find_dll("X3DAudio1_7.dll")->package == "directx-jun2010");
  CHECK(kb.find_dll("mscoree.dll")->package == "netfx");
  CHECK(kb.find_dll("steam_api64.dll")->program_file);
  CHECK(kb.find_dll("Qt5Core.dll")->program_file);
  CHECK(kb.find_dll("vulkan-1.dll")->gpu_driver);
  CHECK(kb.find_dll("kernel32.dll") == nullptr);

  const auto* vc14 = kb.find_package("vcredist14");
  REQUIRE(vc14 != nullptr);
  CHECK(vc14->winget_for("x64") == "Microsoft.VCRedist.2015+.x64");
  CHECK(vc14->url_for("x86").rfind("https://", 0) == 0);
  CHECK(vc14->signer == "Microsoft Corporation");

  const auto* dx = kb.find_package("directx-jun2010");
  REQUIRE(dx != nullptr);
  CHECK(dx->winget_for("x86") == "Microsoft.DirectX");  // falls back to "any"

  const auto* net35 = kb.find_package("netfx35");
  REQUIRE(net35 != nullptr);
  CHECK(net35->kind == "windows-feature");
  CHECK(kb.find_package("gpu-driver")->kind == "driver");
  CHECK(kb.find_package("program-file")->kind == "program-file");
}
