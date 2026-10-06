# JADX Studio

A desktop **decompiler GUI** and **batch CLI** for Android artifacts (APK, DEX, AAR, AAB, ZIP, JAR, class)
plus analysis frameworks for native `.so` libraries and Android binary XML.

Deep decompilation is provided by the [jadx](https://github.com/skylot/jadx) engine (used as a library,
version 1.5.0). This project adds the tooling around it: browsing, navigation, editing, splitting Java vs
smali, deobfuscation workflow, native/XML analysis and batch export.

> ⚠️ **Decompilation is best effort.** Java is *reconstructed* from Dalvik bytecode and may be wrong,
> incomplete, or not compile. Verify important findings against the **Smali** view (Split mode) and the
> reported errors. This warning is also shown in the GUI banner and written into exported output.

---

## Features

### GUI
| Area | What you get |
|------|--------------|
| Open | APK / DEX / AAR / AAB / ZIP / JAR / CLASS, via `File ▸ Open` or a file argument |
| Browser | Package → class tree, resources tree, native (`lib/*/*.so`) tree |
| Editors | Syntax-highlighted, editable, line numbers, dirty markers (`*`) |
| View modes | `Java` · `Smali` · `Split (Java | Smali)` — switchable per class, at any time |
| Navigation | Outline/members, **Go to declaration** (Ctrl+G), **Find usages** (Ctrl+U), Back/Forward (Alt+←/→) |
| Search | Full-text search across sources, manifest and text resources (regex + case options) |
| Resources | Decoded `AndroidManifest.xml`, `res/**` values, layouts, assets |
| Editing | Edit code in place, `Save` stores it in the project, `Export all edits…` writes files |
| Deobfuscation | Mapping editor (classes/methods/fields/packages) + re-decompile, `.jobf` save/load |
| Native | `.so` analysis: ELF structure, symbols, strings, findings, **function list + assembly**, and **C pseudocode** (see below) |
| XML | Binary AXML decoder + manifest permission/exported/debuggable analysis |

### CLI
Batch decompilation with sensible defaults, one output folder per input:

```bash
jadx-studio -o out/ app.apk              # sources + resources
jadx-studio -o out/ --no-res app.apk     # sources only
jadx-studio -o out/ --map renames.jobf app.apk
jadx-studio --gui app.apk                # open the GUI with the file
jadx-studio --help
```

Output layout:

```
out/
  sources/            decompiled .java (mirrors package structure)
  resources/          decoded AndroidManifest.xml, res/**, assets, native libs
  <input>.jobf        deobfuscation mapping (reused on the next run)
  DISCLAIMER.txt      best-effort notice
```

---

## Build & run

Requires **JDK 17+** and network access to Maven Central on first build.

```bash
cd jadx-studio
./gradlew installDist          # or: gradle installDist
```

Then:

```bash
./run.sh                      # GUI
./run.sh --gui app.apk        # GUI with a file
./run.sh -o out app.apk       # CLI
```

Or run the generated launcher directly:

```bash
build/install/jadx-studio/bin/jadx-studio          # GUI
build/install/jadx-studio/bin/jadx-studio -o out app.apk
build/install/jadx-studio/bin/jadx-studio.bat      # Windows
```

`./gradlew run` also works (GUI). Tests are disabled — use the CLI/GUI to verify.

---

## Keyboard shortcuts

| Shortcut | Action |
|----------|--------|
| Ctrl+O | Open file |
| Ctrl+S | Save current edit |
| Ctrl+G | Go to declaration |
| Ctrl+U | Find usages |
| Ctrl+F | Search all text |
| Ctrl+W | Close current tab |
| Alt+← / Alt+→ | Back / Forward |

---

## Deobfuscation workflow

1. Load the APK — jadx renames short/obfuscated names and writes `<input>.jobf` next to the APK.
2. `Tools ▸ Deobfuscation / mappings…` shows every rename in editable tables.
   Format per line: `c com.example.Foo = ReadableName`, `m com.example.Foo.bar()V = doBar`,
   `f com.example.Foo.x:I = count`, `p com.example = com.example.sub`.
3. Edit names (clear a "new name" cell to drop that rename), then **Apply** — the project is
   re-decompiled with your mapping, and your in-editor edits are re-applied on top.
4. **Save…** writes the `.jobf` file so renames are reproducible in later runs (also used by `--map`).

---

## Project layout

```
src/main/java/com/jadxstudio/
  Main.java              entry point: args -> CLI, no args -> GUI
  core/                  Project (engine), CodeHolder, JavaIndex, export options
  editor/                CodeEditor (JTextPane + gutter), CodeDocument (incremental highlighting),
                         JavaTokenizer, CodeTabs
  gui/                   MainWindow, dialogs (GoTo/Search/Deobfuscation/So/Xml/About)
  analysis/so/           ElfScanner, ElfInfo, SymbolInfo — ELF parsing + heuristics
  analysis/xml/          XmlAnalyzer, AxmlDoc — binary AXML decoder + findings
  cli/Cli.java           batch interface
```

---

## Notes & limits

- Decompiled Java is generated output; treat it as a lead, not as ground truth.
- Very large APKs (tens of thousands of classes) take time and memory to decompile on load.
- The `.so` parser reads ELF32/ELF64 (LE/BE). Packed libraries with wiped section headers will show
  few sections/symbols — strings and dynamic behaviour hints still work.
- Binary XML decoding handles namespaces, typed values and resources; text round-trip is for
  reading, not for rebuilding an APK.
- Decompiled output is written to `sources/`; the original DEX is never modified.

## License / attribution

This project bundles [jadx](https://github.com/skylot/jadx) (Apache-2.0) as a dependency and
credits it as the decompilation engine. Verify any finding yourself before acting on it.
---

## Native library analysis (`.so` → assembly + C pseudocode)

Open a native library with `Tools ▸ Analyze .so (native)…` (or double-click a `lib/*/*.so` entry in the tree).
Tabs: **Overview**, **Functions / Assembly / Pseudocode**, **Strings**, **Findings**, **Structure**.

The middle tab is the analysis workspace:
- **Function list** — click a row to load that function. Filter box filters by name.
- **Assembly** (left) — real disassembly for the selected function.
- **C pseudocode** (right) — the same function as C, so you can walk a call in the asm and read its
  C form side by side.
- **References to this address** — who calls/references the selected function.

### Backends (real tools, detected at runtime)

| Output | Backend | Notes |
|--------|---------|-------|
| Functions + assembly | **radare2** or **rizin** | also used for its own analysis, so stripped libs still yield functions |
| C pseudocode | **Ghidra headless** (`analyzeHeadless`) | click *Generate C pseudocode (Ghidra)*; result cached per library |
| C pseudocode (alt) | radare2/rizin `pdg`/`pdc` plugin | used automatically when installed |
| ELF structure, strings, heuristics | built-in parser | no external tool needed |

Status of each backend is shown in the window (and in `Overview`). Nothing is fabricated: if no
backend is installed, the corresponding view says what is missing instead of guessing. Ghidra analysis
is cached under `~/.cache/jadx-studio/native/` keyed by file hash, so it runs once per library.

Addresses are unified across backends (ELF-relative), so a function address is the same number in the
asm view, the pseudocode view and the ELF section list.
