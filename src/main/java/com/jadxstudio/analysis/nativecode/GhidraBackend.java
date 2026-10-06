package com.jadxstudio.analysis.nativecode;

import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.List;
import java.util.concurrent.TimeUnit;
import java.util.function.Consumer;

/**
 * Native -> C pseudocode via Ghidra headless analysis.
 *
 * <p>
 * Ghidra is invoked once per library (its own analysis is the expensive part); results are cached
 * under {@code ~/.cache/jadx-studio/native/<hash>/} as a function index plus one .c file per function.
 * A worker thread reports progress so the GUI stays responsive.
 */
public class GhidraBackend {

	private final Path analyzeHeadless;
	private final Path scriptDir;
	private final Path cacheRoot;
	private final List<String> notes = new ArrayList<>();

	public GhidraBackend(Path analyzeHeadless, Path scriptDir, Path cacheRoot) {
		this.analyzeHeadless = analyzeHeadless;
		this.scriptDir = scriptDir;
		this.cacheRoot = cacheRoot;
	}

	public String toolName() {
		return NativeModel.toolName(analyzeHeadless);
	}

	private static String hash(Path so) throws Exception {
		MessageDigest md = MessageDigest.getInstance("SHA-256");
		return HexFormat.of().formatHex(md.digest(Files.readAllBytes(so)), 0, 12);
	}

	private Path resultDir(Path so) throws Exception {
		return cacheRoot.resolve(hash(so) + "-ghidra");
	}

	public boolean isCached(Path so) {
		try {
			return Files.isRegularFile(resultDir(so).resolve("functions.tsv"));
		} catch (Exception e) {
			return false;
		}
	}

	/**
	 * Run Ghidra headless decompilation for a library (blocking). Use
	 * {@link #analyzeAsync} for the GUI.
	 */
	public void analyze(Path so, Consumer<String> progress) throws Exception {
		Path outDir = resultDir(so);
		if (Files.isRegularFile(outDir.resolve("functions.tsv"))) {
			progress.accept("Using cached Ghidra analysis: " + outDir);
			return;
		}
		Files.createDirectories(outDir);
		// Ghidra rejects path elements starting with '.' (e.g. ~/.cache), so the project
		// lives in a temp dir while only the RESULTS are cached
		Path projDir = Files.createTempDirectory("jadxstudio-ghidra-proj-");
		projDir.toFile().deleteOnExit();
		progress.accept("Ghidra: scriptPath=" + scriptDir + " (exists="
				+ Files.isDirectory(scriptDir) + ", script=" + Files.isRegularFile(scriptDir.resolve("DecompileAll.java"))
				+ ")");
		progress.accept("Ghidra: importing " + so.getFileName() + " (this can take a while)...");

		List<String> cmd = new ArrayList<>(List.of(analyzeHeadless.toString(), projDir.toString(),
				"jadxstudio", "-import", so.toString(), "-scriptPath", scriptDir.toString(),
				"-postScript", "DecompileAll.java", outDir.toString(), "-deleteProject"));
		ProcessBuilder pb = new ProcessBuilder(cmd);
		pb.redirectErrorStream(true);
		pb.environment().put("GHIDRA_JAVA_OPTS", "-Xmx2g");
		Process p = pb.start();
		p.getOutputStream().close();

		Thread reader = new Thread(() -> {
			try (InputStream in = p.getInputStream()) {
				byte[] buf = new byte[8192];
				int n;
				StringBuilder tail = new StringBuilder();
				while ((n = in.read(buf)) > 0) {
					String s = new String(buf, 0, n, StandardCharsets.UTF_8);
					for (String line : s.split("\n")) {
						if (line.contains("JADX Studio") || line.contains("decompres")
								|| line.contains("INFO  REPORT") || line.contains("ERROR")) {
							tail.append(line.strip()).append('\n');
							progress.accept(line.strip());
						}
					}
					if (tail.length() > 4000) {
						tail.delete(0, tail.length() - 2000);
					}
				}
			} catch (Exception ignored) {
			}
		});
		reader.setDaemon(true);
		reader.start();

		boolean done = p.waitFor(30, TimeUnit.MINUTES);
		if (!done) {
			p.destroyForcibly();
			throw new IllegalStateException("Ghidra analysis timed out (30 min limit)");
		}
		reader.join(2000);
		int rc = p.exitValue();
		if (!Files.isRegularFile(outDir.resolve("functions.tsv"))) {
			throw new IllegalStateException("Ghidra produced no results (exit code " + rc + ")");
		}
		progress.accept("Ghidra analysis complete -> " + outDir);
	}

	/** Background wrapper for the GUI. */
	public Thread analyzeAsync(Path so, Consumer<String> progress, Runnable onDone, Consumer<String> onError) {
		Thread t = new Thread(() -> {
			try {
				analyze(so, progress);
				onDone.run();
			} catch (Exception e) {
				onError.accept(String.valueOf(e.getMessage()));
			}
		}, "ghidra-analysis");
		t.setDaemon(true);
		t.start();
		return t;
	}

	/** Function index from a completed analysis. */
	public List<NativeModel.Func> functions(Path so) {
		List<NativeModel.Func> out = new ArrayList<>();
		try {
			Path tsv = resultDir(so).resolve("functions.tsv");
			if (!Files.isRegularFile(tsv)) {
				return out;
			}
			List<String> lines = Files.readAllLines(tsv, StandardCharsets.UTF_8);
			for (String line : lines) {
				String[] parts = line.split("\t", -1);
				if (parts.length < 3 || parts[0].equals("address")) {
					continue;
				}
				long addr = parts.length >= 3 && !parts[1].isBlank() ? Long.parseLong(parts[1].trim())
						: Long.parseLong(parts[0].trim());
				int size = parts.length >= 6 ? (parts[2].isBlank() ? 0 : Integer.parseInt(parts[2].trim()))
						: (parts[1].isBlank() ? 0 : Integer.parseInt(parts[1].trim()));
				String name = parts.length >= 6 ? parts[3].trim() : parts[2].trim();
				String calleesCol = parts.length >= 6 ? parts[4] : (parts.length > 3 ? parts[3] : "");
				List<String> callees = new ArrayList<>();
				if (!calleesCol.isBlank()) {
					for (String c : calleesCol.split(";")) {
						if (!c.isBlank()) {
							callees.add(c);
						}
					}
				}
				out.add(new NativeModel.Func(addr, size, name, callees, "ghidra"));
			}
		} catch (Exception e) {
			notes.add("parse functions.tsv failed: " + e);
		}
		out.sort(java.util.Comparator.comparingLong(NativeModel.Func::addr));
		return out;
	}

	/** C pseudocode for a function given its ELF address ("" when not available). */
	public String pseudocode(Path so, long elfAddr) {
		try {
			Path dir = resultDir(so);
			if (!Files.isDirectory(dir)) {
				return "";
			}
			// files are named with the GHIDRA address = ELF address + image base
			long ghidraAddr = elfAddr + imageBase(dir);
			Path direct = dir.resolve("pseudocode")
					.resolve(ghidraAddr + "_" + safeName(dir, elfAddr) + ".c");
			if (Files.isRegularFile(direct)) {
				return Files.readString(direct, StandardCharsets.UTF_8);
			}
			String prefix = ghidraAddr + "_";
			try (var stream = Files.list(dir.resolve("pseudocode"))) {
				for (Path p : stream.toList()) {
					if (p.getFileName().toString().startsWith(prefix)) {
						return Files.readString(p, StandardCharsets.UTF_8);
					}
				}
			}
		} catch (Exception e) {
			notes.add("read pseudocode failed: " + e);
		}
		return "";
	}

	private long imageBase(Path dir) {
		try {
			for (String line : Files.readAllLines(dir.resolve("program.txt"), StandardCharsets.UTF_8)) {
				if (line.startsWith("imageBase=")) {
					return Long.parseLong(line.substring("imageBase=".length()).trim(), 16);
				}
			}
		} catch (Exception ignored) {
		}
		return 0;
	}

	/** Ghidra stores <ghidraAddr>_<name>.c; map an ELF address to that file name. */
	private String safeName(Path dir, long elfAddr) throws Exception {
		for (String line : Files.readAllLines(dir.resolve("functions.tsv"), StandardCharsets.UTF_8)) {
			String[] p = line.split("\t", -1);
			if (p.length < 3 || p[0].equals("address")) {
				continue;
			}
			boolean modern = p.length >= 6 && p[1].matches("-?\\d+");
			long rowElf = modern ? Long.parseLong(p[1].trim()) : Long.parseLong(p[0].trim());
			String name = modern ? p[3].trim() : p[2].trim();
			if (rowElf == elfAddr) {
				return name.replaceAll("[^A-Za-z0-9_.]", "_");
			}
		}
		return "unknown";
	}

	public String programInfo(Path so) {
		try {
			Path f = resultDir(so).resolve("program.txt");
			return Files.isRegularFile(f) ? Files.readString(f, StandardCharsets.UTF_8) : "";
		} catch (Exception e) {
			return "";
		}
	}

	public List<String> warnings() {
		return notes;
	}

	/** Extract the bundled Ghidra post-script to a temp dir so headless can use it. */
	public static Path extractScript() throws Exception {
		Path dir = Files.createTempDirectory("jadxstudio-ghidra-script");
		try (InputStream in = GhidraBackend.class.getResourceAsStream("/ghidra/DecompileAll.java")) {
			if (in == null) {
				throw new IllegalStateException("bundled DecompileAll.java not found");
			}
			Path out = dir.resolve("DecompileAll.java");
			try (OutputStream os = Files.newOutputStream(out)) {
				in.transferTo(os);
			}
			dir.toFile().deleteOnExit();
			out.toFile().deleteOnExit();
			return dir;
		}
	}
}