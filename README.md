# Why Won't It Open? (Neden Açılmıyor?)

[![build](https://github.com/nowackk-cp/why-wont-it-open/actions/workflows/build.yml/badge.svg)](https://github.com/nowackk-cp/why-wont-it-open/actions/workflows/build.yml)

A Windows program doctor. Drag an `.exe` that refuses to start onto the window and it tells you
which component is missing or wrong, and points you to the **official** fix.

> **Status:** early development (milestone M0: project skeleton). Not usable yet.

## Principles

- **Never runs the target program.** Analysis is done by reading the file only; DLLs are never
  loaded with `LoadLibrary`, so even a malicious file cannot execute code.
- **Sends nothing anywhere.** No telemetry, no uploads.
- **Portable.** A single x86 `.exe`, statically linked against the C runtime, so it starts even on a
  machine missing the very runtimes it diagnoses.
- **Honest.** When the tool isn't sure, it says so. A wrong diagnosis is worse than none.

## What it will detect (first release)

1. Missing DLLs, mapped to the official redistributable (VC++ 2005–2022, DirectX June 2010, …)
2. Wrong architecture (`0xc000007b`), including stray DLLs found on `PATH`
3. "Entry point not found" caused by an outdated DLL shadowing the system copy
4. Debug runtimes (`vcruntime140d.dll`, `ucrtbased.dll`) shipped by mistake
5. Platform mismatch (e.g. a 64-bit exe on 32-bit Windows)
6. Corrupt or truncated files
7. Programs that need .NET Framework 3.5

## Roadmap

- [x] **M0** skeleton: CMake, `/MT`, CI, MIT license
- [ ] **M1** bounds-checked PE parser + fuzzing → `neden info x.exe`
- [ ] **M2** DLL resolver (search order, KnownDLLs, API sets, WOW64) → `neden check x.exe --json`
- [ ] **M3** diagnosis rules 1–7, English and Turkish texts
- [ ] **M4** Win32 GUI: drag & drop, result cards, "Copy report" ← first release
- [ ] **M5** one-click fix via winget or signature-verified official installer
- [ ] **M6** release: attestation, SHA256, winget manifest

## Building

Requires Visual Studio 2022 (Desktop development with C++) and CMake ≥ 3.21.

```bash
cmake --preset x86
cmake --build --preset x86-release
ctest --preset x86-release
```

The CLI ends up at `build/x86/cli/Release/neden.exe`.

## Contributing

The easiest way to help is adding a DLL → package mapping to
[`data/runtimes.json`](data/runtimes.json). See [CONTRIBUTING.md](CONTRIBUTING.md).

## Türkçe

**Neden Açılmıyor?**, açılmayan Windows programlarını teşhis eden bir araçtır. Açılmayan `.exe`'yi
pencereye sürüklersiniz; araç eksik ya da yanlış bileşeni bulur ve resmi çözümü gösterir.

- Hedef programı **asla çalıştırmaz**, sadece dosyayı okur.
- Dışarıya **hiçbir veri göndermez**.
- Kurulum gerektirmeyen **tek bir exe**'dir.

Proje erken geliştirme aşamasındadır. Katkı vermek için en kolay yol `data/runtimes.json`
dosyasına yeni bir DLL eşlemesi eklemektir.

## License

[MIT](LICENSE)
