package com.jadxstudio.analysis.nativecode;

import com.jadxstudio.analysis.so.ElfInfo;
import com.jadxstudio.analysis.so.ElfScanner;

import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Consumer;

/**
 * Native library analysis facade: ELF structure + function list + assembly + C pseudocode.
 *
 * <p>
 * Sources of truth, in order of preference: radare2/rizin for functions and assembly, Ghidra headless
 * for C pseudocode, and the built-in ELF parser for structure/strings/heuristics. If a backend is not
 * installed, the corresponding view explains what is missing instead of showing invented output.
 */
public class NativeAnalysis {

	private final Path so;
	private final ElfInfo elf;
	private final NativeModel.Backends backends;
	private final DisasmBackend disasm;
	private final GhidraBackend ghidra;
	private List<NativeModel.Func> functions;
	private String ghidraInfo = "";

	public NativeAnalysis(Path so) {
		this.so = so;
		try {
			this.elf = ElfScanner.analyze(so);
		} catch (java.io.IOException e) {
			throw new IllegalStateException("cannot read " + so + ": " + e.getMessage(), e);
		}
		this.backends = BackendLocator.detect();
		Path r2 = BackendLocator.radare2();
		Path rz = BackendLocator.rizin();
		if (r2 != null) {
			this.disasm = new DisasmBackend(r2, BackendLocator.cacheDir(), false);
		} else if (rz != null) {
			this.disasm = new DisasmBackend(rz, BackendLocator.cacheDir(), true);
		} else {
			this.disasm = null;
		}
		Path gh = BackendLocator.ghidraHeadless();
		this.ghidra = gh == null ? null : new GhidraBackend(gh, scriptDir(), BackendLocator.cacheDir());
	}

	private static Path scriptDir() {
		try {
			return GhidraBackend.extractScript();
		} catch (Exception e) {
			throw new IllegalStateException(e);
		}
	}

	public Path file() {
		return so;
	}

	public ElfInfo elf() {
		return elf;
	}

	public NativeModel.Backends backends() {
		return backends;
	}

	public DisasmBackend disasm() {
		return disasm;
	}

	public GhidraBackend ghidra() {
		return ghidra;
	}

	public boolean hasGhidraResults() {
		return ghidra != null && ghidra.isCached(so);
	}

	/** Runs Ghidra analysis in the background (GUI). */
	public void analyzePseudocodeAsync(Consumer<String> progress, Runnable onDone, Consumer<String> onError) {
		if (ghidra == null) {
			onError.accept("Ghidra (analyzeHeadless) not found. Install Ghidra or add it to PATH.");
			return;
		}
		ghidra.analyzeAsync(so, progress, () -> {
			ghidraInfo = ghidra.programInfo(so);
			onDone.run();
		}, onError);
	}

	/**
	 * Functions from all available sources. Ghidra results are preferred when present (they are the
	 * result of a full CFG-based analysis), otherwise radare2, otherwise ELF symbols.
	 */
	public List<NativeModel.Func> functions(Consumer<String> log) {
		if (functions != null) {
			return functions;
		}
		Map<String, NativeModel.Func> merged = new LinkedHashMap<>();
		if (disasm != null) {
			try {
				log.accept("Disassembling function list with " + disasm.toolName() + "...");
				for (NativeModel.Func f : disasm.functions(so)) {
					merged.put(NativeModel.hex(f.addr()), f);
				}
			} catch (Exception e) {
				log.accept("disasm backend: " + e);
			}
		}
		if (ghidra != null && ghidra.isCached(so)) {
			ghidraInfo = ghidra.programInfo(so);
			List<NativeModel.Func> gf = ghidra.functions(so);
			if (!gf.isEmpty()) {
				log.accept("Ghidra: " + gf.size() + " functions");
				merged.clear();
				for (NativeModel.Func f : gf) {
					merged.put(NativeModel.hex(f.addr()), f);
				}
			}
		}
		if (merged.isEmpty()) {
			// last resort: ELF symbols as pseudo-functions
			for (var s : elf.symbols) {
				if (s.value != 0) {
					merged.put(NativeModel.hex(s.value),
							new NativeModel.Func(s.value, (int) s.size, s.name, List.of(), "elf-symbol"));
				}
			}
		}
		functions = new ArrayList<>(merged.values());
		functions.sort(java.util.Comparator.comparingLong(NativeModel.Func::addr));
		return functions;
	}

	/** Assembly of one function. */
	public List<NativeModel.Insn> assembly(long addr, int max, Consumer<String> log) {
		if (disasm == null) {
			log.accept("No disassembler available (install radare2 or rizin).");
			return List.of();
		}
		return disasm.disasm(so, addr, max);
	}

	/** C pseudocode of one function (requires Ghidra analysis first). */
	public String pseudocode(long addr) {
		if (ghidra == null) {
			return "";
		}
		return ghidra.pseudocode(so, addr);
	}

	public List<String> xrefsTo(long addr, Consumer<String> log) {
		if (disasm == null) {
			return List.of();
		}
		return disasm.xrefsTo(so, addr);
	}

	public String ghidraProgramInfo() {
		return ghidraInfo;
	}

	/** Human-readable status for the UI status bar / overview tab. */
	public String statusText() {
		StringBuilder sb = new StringBuilder();
		sb.append("disassembler: ").append(backends.hasDisassembler() ? backends.disassembler() : "not available")
				.append('\n');
		sb.append("decompiler: ").append(backends.hasDecompiler() ? backends.decompiler() : "not available")
				.append('\n');
		if (disasm != null) {
			sb.append("version: ").append(disasm.toolName()).append(' ').append(disasm.version()).append('\n');
		}
		sb.append("pseudocode results: ").append(hasGhidraResults() ? "cached" : "none (run analysis)").append('\n');
		for (String n : backends.notes()) {
			sb.append("note: ").append(n).append('\n');
		}
		if (disasm != null) {
			for (String w : disasm.warnings()) {
				sb.append("note: ").append(w).append('\n');
			}
		}
		return sb.toString();
	}
}