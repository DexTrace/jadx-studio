package com.jadxstudio.analysis.nativecode;

import java.io.File;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.TimeUnit;

/**
 * Detects the external tools used for native analysis.
 *
 * <p>
 * Disassembly: radare2 or rizin (any arch, function list + xrefs). Decompiler to C pseudocode:
 * Ghidra headless (best quality), or a radare2/rizin decompiler plugin when installed. Nothing here
 * fabricates output: when a backend is missing the UI says so instead of guessing.
 */
public final class BackendLocator {

	private BackendLocator() {
	}

	/** Cache root for backend results (survives restarts). */
	public static Path cacheDir() {
		String home = System.getProperty("user.home", ".");
		Path d = Paths.get(home, ".cache", "jadx-studio", "native");
		try {
			Files.createDirectories(d);
		} catch (Exception ignored) {
		}
		return d;
	}

	public static Path which(String... names) {
		String pathEnv = System.getenv("PATH");
		if (pathEnv == null) {
			return null;
		}
		for (String n : names) {
			for (String dir : pathEnv.split(File.pathSeparator)) {
				if (dir.isBlank()) {
					continue;
				}
				Path p = Paths.get(dir, n);
				if (Files.isExecutable(p) && !Files.isDirectory(p)) {
					return p;
				}
			}
		}
		return null;
	}

	public static Path radare2() {
		return which("r2", "radare2");
	}

	public static Path rizin() {
		return which("rz-bin", "rizin", "rizin.exe");
	}

	/** Locate Ghidra's headless analyzer. */
	public static Path ghidraHeadless() {
		List<Path> candidates = new ArrayList<>();
		String env = System.getenv("GHIDRA_INSTALL_DIR");
		if (env != null && !env.isBlank()) {
			candidates.add(Paths.get(env, "support", "analyzeHeadless"));
			candidates.add(Paths.get(env, "ghidraRun"));
		}
		String[] roots = { "/usr/share/ghidra", "/opt/ghidra", "/usr/local/ghidra", "/opt/Ghidra",
				"/Applications/Ghidra.app/Contents/Resources/ghidra", "/Applications/Ghidra.app/Contents/MacOS" };
		for (String r : roots) {
			candidates.add(Paths.get(r, "support", "analyzeHeadless"));
		}
		Path onPath = which("analyzeHeadless", "analyzeHeadless.bat");
		if (onPath != null) {
			candidates.add(onPath);
		}
		for (Path p : candidates) {
			if (Files.isRegularFile(p)) {
				return p;
			}
		}
		return null;
	}

	/** radare2/rizin decompiler plugin available? (pdg / pdc) */
	public static boolean r2HasDecompiler(Path r2) {
		if (r2 == null) {
			return false;
		}
		try {
			Proc p = run(r2, 20, "-2", "-q", "-c", "e cmd.pdg", "--", "/dev/null");
			String out = new String(p.output(), java.nio.charset.StandardCharsets.UTF_8);
			return !out.contains("Cannot find");
		} catch (Exception e) {
			return false;
		}
	}

	public static NativeModel.Backends detect() {
		Path r2 = radare2();
		Path rz = rizin();
		Path gh = ghidraHeadless();
		List<String> notes = new ArrayList<>();

		String disasm = null;
		if (r2 != null) {
			disasm = "radare2 (" + NativeModel.toolName(r2) + ")";
		} else if (rz != null) {
			disasm = "rizin (" + NativeModel.toolName(rz) + ")";
		} else {
			notes.add("No radare2/rizin found: assembly view unavailable. Install radare2 or rizin.");
		}

		String decomp = null;
		if (gh != null) {
			decomp = "Ghidra headless";
			notes.add("Pseudocode C is produced by Ghidra (headless, one-time analysis per library).");
		} else if (r2HasDecompiler(r2)) {
			decomp = "radare2 decompiler plugin";
		} else {
			notes.add("No Ghidra found: C pseudocode unavailable. "
					+ "Install Ghidra (analyzeHeadless) or a radare2 decompiler plugin.");
		}
		if (r2 != null && !r2HasDecompiler(r2)) {
			notes.add("radare2 decompiler plugin (pdc/pdg) not detected - radare2 provides assembly only.");
		}
		return new NativeModel.Backends(disasm, decomp, notes);
	}

	static Proc run(Path exe, int timeoutSec, String... args) throws Exception {
		ProcessBuilder pb = new ProcessBuilder(args);
		pb.redirectErrorStream(false);
		Process proc = pb.start();
		proc.getOutputStream().close();
		byte[] out = proc.getInputStream().readAllBytes();
		proc.getErrorStream().readAllBytes();
		if (!proc.waitFor(timeoutSec, TimeUnit.SECONDS)) {
			proc.destroyForcibly();
		}
		return new Proc(out);
	}

	record Proc(byte[] output) {
	}
}