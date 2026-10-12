# Contributing

Thanks for helping! Issues and pull requests are welcome in English or Turkish.

## Adding a DLL mapping (good first issue)

Open [`data/runtimes.json`](data/runtimes.json) and add an entry under `dlls`:

```json
"msvcr120.dll": { "package": "vcredist2013" }
```

- `package` must refer to a key under `packages`. Add the package too if it does not exist yet.
- Use `"arch": ["x64"]` when the DLL only exists for some architectures.
- Use `"debugOnly": true` for debug runtimes that have no redistributable.
- Download links must point to an **official** vendor page (e.g. Microsoft's
  "Latest supported Visual C++ Redistributable downloads"). Never link to DLL download sites.
- Do not add mappings for a game's or program's own files (e.g. `steam_api64.dll`); the tool
  tells users to verify/reinstall the program instead. Nothing that touches DRM will be accepted.

## Code

- C++20, MSVC, statically linked CRT (`/MT`), 32-bit (x86) build.
- The target file is **never executed or loaded**. All parsing must bounds-check every offset.
- Build and run tests before sending a PR:

```bash
cmake --preset x86
cmake --build --preset x86-release
ctest --preset x86-release
```
