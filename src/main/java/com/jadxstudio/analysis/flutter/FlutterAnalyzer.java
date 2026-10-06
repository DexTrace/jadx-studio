package com.jadxstudio.analysis.flutter;

import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

/**
 * Flutter / Dart AOT analysis.
 *
 * <p>
 * Finds the Flutter engine and app libraries, locates the Dart AOT snapshot inside
 * {@code libapp.so}, reports Flutter/Dart versions and extracts the Dart symbol table
 * (libraries, classes, function names) so the hidden app logic can be read.
 *
 * <p>
 * NOTE: this does not reimplement Blutter's full AOT-to-Dart decompiler. It reports the
 * real snapshot structure and symbol names; for instruction-level reconstruction use
 * Blutter itself.
 */
public class FlutterAnalyzer {

	/** Dart AOT snapshot magic (little endian dcdcf5f5) and section keys. */
	private static final int[] SNAPSHOT_MAGIC = { 0xf5, 0xf5, 0xdc, 0xdc };
	private static final Set<String> SNAPSHOT_KEYS = Set.of(
			"kDartVmSnapshotData", "kDartIsolateSnapshotData", "kDartCoreIsolateSnapshotData",
			"vm_snapshot_data", "isolate_snapshot_data", "kernel_blob.bin");

	private final List<String> findings = new ArrayList<>();
	private final Map<String, String> info = new LinkedHashMap<>();
	private final List<String> dartLibraries = new ArrayList<>();
	private final Set<String> dartClasses = new LinkedHashSet<>();
	private final Set<String> dartFunctions = new LinkedHashSet<>();
	private long snapshotOffset = -1;
	private long snapshotLength;

	public static FlutterAnalyzer analyze(Path soFile) throws java.io.IOException {
		FlutterAnalyzer a = new FlutterAnalyzer();
		a.scan(soFile);
		return a;
	}

	private void scan(Path file) throws java.io.IOException {
		byte[] data = java.nio.file.Files.readAllBytes(file);
		info.put("library", file.getFileName().toString());
		info.put("size", data.length + " bytes");
		info.put("md5", md5(data));

		long off = findSnapshot(data);
		if (off >= 0) {
			snapshotOffset = off;
			snapshotLength = data.length - off;
			info.put("dart snapshot", "found at 0x" + Long.toHexString(off) + " ("
					+ snapshotLength + " bytes)");
		} else {
			info.put("dart snapshot", "not found in this library");
		}
		info.put("flutter version", flutterVersion(data));
		info.put("dart vm version", dartVersion(data));

		collectDartSymbols(data);
		info.put("dart libraries", String.valueOf(dartLibraries.size()));
		info.put("dart class names", String.valueOf(dartClasses.size()));
		info.put("dart function names", String.valueOf(dartFunctions.size()));
	}

	/** Locate the AOT snapshot by magic + section keys. */
	private static long findSnapshot(byte[] d) {
		for (int i = 0; i + 4 < d.length; i++) {
			if (d[i] == SNAPSHOT_MAGIC[0] && d[i + 1] == SNAPSHOT_MAGIC[1]
					&& d[i + 2] == SNAPSHOT_MAGIC[2] && d[i + 3] == SNAPSHOT_MAGIC[3]) {
				return i;
			}
			// older layout: section key followed by length then data
			if (d[i] == 0x00) {
				String key = asciiAround(d, i, 40);
				for (String k : SNAPSHOT_KEYS) {
					if (key.contains(k)) {
						return i;
					}
				}
			}
		}
		return -1;
	}

	private static String asciiAround(byte[] d, int off, int n) {
		int end = Math.min(d.length, off + n);
		StringBuilder sb = new StringBuilder();
		for (int i = off; i < end; i++) {
			int c = d[i] & 0xff;
			sb.append(c >= 0x20 && c < 0x7f ? (char) c : '.');
		}
		return sb.toString();
	}

	/** Pull Dart library / class / function names out of the embedded strings. */
	private void collectDartSymbols(byte[] d) {
		StringBuilder cur = new StringBuilder();
		for (byte b : d) {
			int c = b & 0xff;
			if (c >= 0x20 && c < 0x7f) {
				cur.append((char) c);
			} else {
				consumeString(cur.toString());
				cur.setLength(0);
			}
		}
		consumeString(cur.toString());

		if (snapshotOffset < 0 && dartLibraries.isEmpty()) {
			findings.add("No Dart snapshot markers found - this may not be a Flutter AOT library.");
		}
	}

	private void consumeString(String s) {
		if (s.length() < 4) {
			return;
		}
		String low = s.toLowerCase(Locale.ROOT);
		if (s.contains("package:") && s.contains(".dart")) {
			if (dartLibraries.size() < 4000 && !dartLibraries.contains(s)) {
				dartLibraries.add(s);
			}
			return;
		}
		if (s.startsWith("file:///") && s.contains(".dart")) {
			if (dartLibraries.size() < 4000 && !dartLibraries.contains(s)) {
				dartLibraries.add(s);
			}
			return;
		}
		if (SNAPSHOT_KEYS.contains(s) || s.equals("kDartVmSnapshotData")) {
			return;
		}
		if (isDartIdentifier(s)) {
			if (Character.isUpperCase(s.charAt(0))) {
				if (dartClasses.size() < 6000) {
					dartClasses.add(s);
				}
			} else if (dartFunctions.size() < 8000) {
				dartFunctions.add(s);
			}
		}
	}

	private static boolean isDartIdentifier(String s) {
		if (s.length() < 3 || s.length() > 90) {
			return false;
		}
		if (s.contains(" ") || s.contains("/") || s.contains("\\") || s.contains("://")) {
			return false;
		}
		if (!Character.isLetter(s.charAt(0))) {
			return false;
		}
		for (int i = 0; i < s.length(); i++) {
			char c = s.charAt(i);
			if (!Character.isLetterOrDigit(c) && c != '_' && c != '$' && c != '.') {
				return false;
			}
		}
		// skip obvious C++ / ELF noise
		if (s.contains("..") || s.endsWith(".") || s.startsWith("_Z") || s.startsWith("GLIBC")) {
			return false;
		}
		return true;
	}

	private static String flutterVersion(byte[] d) {
		String v = findMatching(d, "Flutter ", 24);
		if (v == null) {
			v = findMatching(d, "flutter/engine", 40);
		}
		return v == null ? "(not found)" : v;
	}

	private static String dartVersion(byte[] d) {
		String v = findMatching(d, "Dart VM version:", 40);
		if (v == null) {
			v = findMatching(d, "Dart SDK version:", 40);
		}
		return v == null ? "(not found)" : v;
	}

	private static String findMatching(byte[] d, String marker, int maxLen) {
		byte[] m = marker.getBytes(StandardCharsets.US_ASCII);
		outer: for (int i = 0; i + m.length < d.length; i++) {
			for (int j = 0; j < m.length; j++) {
				if (d[i + j] != m[j]) {
					continue outer;
				}
			}
			int end = i;
			while (end < d.length && end - i < maxLen && d[end] >= 0x20 && d[end] < 0x7f) {
				end++;
			}
			return new String(d, i, end - i, StandardCharsets.US_ASCII);
		}
		return null;
	}

	private static String md5(byte[] data) {
		try {
			byte[] h = java.security.MessageDigest.getInstance("MD5").digest(data);
			StringBuilder sb = new StringBuilder();
			for (byte b : h) {
				sb.append(String.format("%02x", b));
			}
			return sb.toString();
		} catch (Exception e) {
			return "?";
		}
	}

	// ----------------------------------------------------------- accessors

	public Map<String, String> getInfo() {
		return info;
	}

	public List<String> getDartLibraries() {
		return dartLibraries;
	}

	public Set<String> getDartClasses() {
		return dartClasses;
	}

	public Set<String> getDartFunctions() {
		return dartFunctions;
	}

	public List<String> getFindings() {
		return findings;
	}

	public boolean hasSnapshot() {
		return snapshotOffset >= 0;
	}

	/** Notes for the disassembly window. */
	public static String describe(byte[] soBytes) {
		String name = "libapp.so";
		FlutterAnalyzer a = analyzeQuiet(soBytes, name);
		StringBuilder sb = new StringBuilder("Flutter/Dart library: ").append(name).append('\n');
		for (var e : a.getInfo().entrySet()) {
			sb.append("  ").append(e.getKey()).append(": ").append(e.getValue()).append('\n');
		}
		return sb.toString();
	}

	private static FlutterAnalyzer analyzeQuiet(byte[] data, String name) {
		FlutterAnalyzer a = new FlutterAnalyzer();
		try {
			java.nio.file.Path tmp = java.nio.file.Files.createTempFile("flutter", ".so");
			java.nio.file.Files.write(tmp, data);
			FlutterAnalyzer r = analyze(tmp);
			tmp.toFile().deleteOnExit();
			return r;
		} catch (Exception e) {
			a.info.put("error", String.valueOf(e.getMessage()));
			return a;
		}
	}
}