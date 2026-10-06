package com.jadxstudio.analysis.nativecode;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.List;
import java.util.concurrent.TimeUnit;

/**
 * Disassembly + function discovery through radare2 (or rizin).
 *
 * <p>
 * radare2 performs its own analysis ({@code aa}) so stripped native libraries still yield a function
 * list; assembly text is taken verbatim from the tool (never re-implemented heuristically).
 */
public class DisasmBackend {

	private final Path exe;
	private final String tool;
	private final boolean rizin;
	private final Path cacheRoot;
	private final List<String> cacheJson = new ArrayList<>();

	public DisasmBackend(Path exe, Path cacheRoot, boolean rizin) {
		this.exe = exe;
		this.tool = exe.getFileName().toString();
		this.rizin = rizin;
		this.cacheRoot = cacheRoot;
	}

	public String toolName() {
		return tool;
	}

	public String version() {
		if (cachedVersion != null) {
			return cachedVersion;
		}
		try {
			ProcessBuilder pb = new ProcessBuilder(exe.toString(), "-v");
			pb.redirectErrorStream(true);
			Process p = pb.start();
			String out = new String(p.getInputStream().readAllBytes(), StandardCharsets.UTF_8).trim();
			p.waitFor(15, TimeUnit.SECONDS);
			int nl = out.indexOf('\n');
			cachedVersion = nl > 0 ? out.substring(0, nl) : out;
		} catch (Exception e) {
			cachedVersion = "unknown";
		}
		return cachedVersion;
	}

	private String cachedVersion;

	/**
	 * Extracts the first complete JSON value (object or array) from tool output, which may contain
	 * banners or trailing text around it.
	 */
	static String extractJson(String raw, char open) {
		if (raw == null) {
			return "";
		}
		char close = open == '{' ? '}' : ']';
		int start = raw.indexOf(open);
		if (start < 0) {
			return "";
		}
		int depth = 0;
		boolean inStr = false;
		boolean esc = false;
		for (int i = start; i < raw.length(); i++) {
			char c = raw.charAt(i);
			if (inStr) {
				if (esc) {
					esc = false;
				} else if (c == '\\') {
					esc = true;
				} else if (c == '"') {
					inStr = false;
				}
				continue;
			}
			if (c == '"') {
				inStr = true;
			} else if (c == open) {
				depth++;
			} else if (c == close) {
				depth--;
				if (depth == 0) {
					return raw.substring(start, i + 1);
				}
			}
		}
		return raw.substring(start);
	}

	private static JsonElement parseJson(String json) {
		com.google.gson.stream.JsonReader reader = new com.google.gson.stream.JsonReader(
				new java.io.StringReader(json));
		reader.setLenient(true);
		return JsonParser.parseReader(reader);
	}

	/** r2 >=5 reports "addr"; older versions used "offset". */
	private static long addrOf(JsonObject o) {
		if (o.has("addr")) {
			return o.get("addr").getAsLong();
		}
		if (o.has("offset")) {
			return o.get("offset").getAsLong();
		}
		if (o.has("from")) {
			return o.get("from").getAsLong();
		}
		return 0;
	}

	private static String hash(Path so) throws Exception {
		MessageDigest md = MessageDigest.getInstance("SHA-256");
		byte[] d = md.digest(Files.readAllBytes(so));
		return HexFormat.of().formatHex(d, 0, 12);
	}

	/** Function list (analysis is done once and cached on disk). */
	public List<NativeModel.Func> functions(Path so) {
		try {
			Path cache = cacheRoot.resolve(hash(so) + "-funcs.json");
			if (Files.isRegularFile(cache)) {
				return parseFuncs(Files.readString(cache, StandardCharsets.UTF_8));
			}
			String json = rizin ? rzRun(so, "aaa; aflj") : r2Run(so, "aa; aflj");
			Files.writeString(cache, json, StandardCharsets.UTF_8);
			return parseFuncs(json);
		} catch (Exception e) {
			cacheJson.add("function list failed: " + e);
			return List.of();
		}
	}

	private List<NativeModel.Func> parseFuncs(String json) {
		List<NativeModel.Func> out = new ArrayList<>();
		try {
			String j = extractJson(json, '[');
			if (j.isEmpty()) {
				return out;
			}
			JsonArray arr = parseJson(j).getAsJsonArray();
			for (JsonElement el : arr) {
				JsonObject o = el.getAsJsonObject();
				long off = addrOf(o);
				int size = o.has("size") ? o.get("size").getAsInt() : 0;
				String name = o.has("name") ? o.get("name").getAsString() : NativeModel.hex(off);
				List<String> callees = new ArrayList<>();
				if (o.has("callrefs") && o.get("callrefs").isJsonArray()) {
					for (JsonElement c : o.getAsJsonArray("callrefs")) {
						JsonObject co = c.getAsJsonObject();
						if (co.has("fcn_name")) {
							callees.add(co.get("fcn_name").getAsString());
						} else if (co.has("name")) {
							callees.add(co.get("name").getAsString());
						}
					}
				}
				out.add(new NativeModel.Func(off, size, name, callees, tool));
			}
		} catch (Exception e) {
			cacheJson.add("parse funcs failed: " + e);
		}
		out.sort(java.util.Comparator.comparingLong(NativeModel.Func::addr));
		return out;
	}

	/** Disassembly of the function containing {@code addr} (falls back to a raw instruction window). */
	public List<NativeModel.Insn> disasm(Path so, long addr, int maxInstructions) {
		String cmd = rizin
				? "aaa; pdfj @ " + NativeModel.hex(addr) + "; pdj " + maxInstructions + " @ " + NativeModel.hex(addr)
				: "aa; pdfj @ " + NativeModel.hex(addr);
		String json = rizin ? rzRun(so, cmd) : r2Run(so, cmd);
		List<NativeModel.Insn> insns = parseDisasm(json, maxInstructions);
		if (insns.isEmpty()) {
			json = rizin
					? rzRun(so, "aaa; pdj " + maxInstructions + " @ " + NativeModel.hex(addr))
					: r2Run(so, "aa; pdj " + maxInstructions + " @ " + NativeModel.hex(addr));
			insns = parseDisasm(json, maxInstructions);
		}
		return insns;
	}

	private List<NativeModel.Insn> parseDisasm(String json, int max) {
		List<NativeModel.Insn> out = new ArrayList<>();
		try {
			String j = extractJson(json, '{');
			if (j.isEmpty()) {
				return out;
			}
			JsonObject root = parseJson(j).getAsJsonObject();
			JsonArray ops = root.has("ops") ? root.getAsJsonArray("ops") : null;
			if (ops == null) {
				return out;
			}
			for (JsonElement el : ops) {
				if (out.size() >= max) {
					break;
				}
				JsonObject o = el.getAsJsonObject();
				long off = addrOf(o);
				String bytes = o.has("bytes") ? o.get("bytes").getAsString() : "";
				String text;
				if (o.has("disasm") && !o.get("disasm").getAsString().isBlank()) {
					text = o.get("disasm").getAsString();
				} else if (o.has("opcode") && o.has("type") && !o.get("type").getAsString().equals("invalid")) {
					text = o.get("opcode").getAsString();
				} else {
					text = "(invalid)";
				}
				String comment = null;
				if (o.has("comment")) {
					comment = o.get("comment").getAsString();
				} else if (o.has("flag") && !o.get("flag").getAsString().isEmpty()) {
					comment = o.get("flag").getAsString();
				}
				out.add(new NativeModel.Insn(off, bytes, text, comment));
			}
		} catch (Exception e) {
			cacheJson.add("parse disasm failed: " + e);
		}
		return out;
	}

	/** Cross references to an address (who calls / refers to it). */
	public List<String> xrefsTo(Path so, long addr) {
		String json = rizin
				? rzRun(so, "aaa; axtj @ " + NativeModel.hex(addr))
				: r2Run(so, "aa; axtj @ " + NativeModel.hex(addr));
		List<String> out = new ArrayList<>();
		try {
			String j = extractJson(json, '[');
			if (j.isEmpty()) {
				return out;
			}
			for (JsonElement el : parseJson(j).getAsJsonArray()) {
				JsonObject o = el.getAsJsonObject();
				long from = addrOf(o);
				String type = o.has("type") ? o.get("type").getAsString() : "";
				String fname = o.has("fcn_name") ? o.get("fcn_name").getAsString() : "";
				out.add(NativeModel.hex(from) + " " + type + (fname.isEmpty() ? "" : " in " + fname));
			}
		} catch (Exception e) {
			cacheJson.add("parse xrefs failed: " + e);
		}
		return out;
	}

	/**
	 * References to a string value (radare2 search + cross references).
	 * Returns human readable lines.
	 */
	public java.util.List<String> stringXrefs(java.nio.file.Path so, String value) {
		java.util.List<String> out = new java.util.ArrayList<>();
		if (value == null || value.isBlank()) {
			return out;
		}
		String needle = value.trim();
		if (needle.length() > 60) {
			needle = needle.substring(0, 60);
		}
		String cmd = rizin
				? "aaa; / " + needle + "; axt @@= `?v:izz~" + escape(needle) + "`"
				: "aa; / " + escape(needle) + "; axt @@= `?v:izz~" + escape(needle) + "`";
		String raw = rizin ? rzRun(so, cmd) : r2Run(so, cmd);
		int i = raw.indexOf('{');
		if (i >= 0) {
			String j = extractJson(raw, '{');
			if (!j.isEmpty()) {
				try {
					JsonObject root = parseJson(j).getAsJsonObject();
					if (root.has("refs") && root.get("refs").isJsonArray()) {
						for (JsonElement el : root.getAsJsonArray("refs")) {
							JsonObject o = el.getAsJsonObject();
							long at = addrOf(o);
							String fcn = o.has("fcn_name") ? o.get("fcn_name").getAsString() : "";
							out.add(NativeModel.hex(at) + (fcn.isEmpty() ? "" : "  in " + fcn));
						}
					}
				} catch (Exception ignored) {
				}
			}
		}
		if (out.isEmpty()) {
			// fall back: list the instruction addresses holding the bytes
			String searchCmd = (rizin ? "aaa; " : "aa; ") + "/ " + escape(needle);
			String res = rizin ? rzRun(so, searchCmd) : r2Run(so, searchCmd);
			for (String line : res.split("\n")) {
				String t = line.trim();
				if (t.startsWith("0x") && !t.isEmpty()) {
					out.add(t);
				}
			}
		}
		return out;
	}

	private static String escape(String s) {
		return "\"" + s.replace("\"", "\\").replace("\"", "\\\"") + "\"";
	}

	public List<String> warnings() {
		return cacheJson;
	}

	// ---------------------------------------------------------------- process

	private String r2Run(Path so, String cmd) {
		return exec(exe, List.of("-2", "-e", "scr.color=0", "-e", "bin.cache=true", "-q", "-c", cmd), so);
	}

	private String rzRun(Path so, String cmd) {
		return exec(exe, List.of("-2", "-q", "-c", cmd), so);
	}

	private String exec(Path exe, List<String> args, Path so) {
		List<String> full = new ArrayList<>();
		full.add(exe.toString());
		full.addAll(args);
		// absolute path: the process working directory is the file's parent
		full.add(so.toAbsolutePath().toString());
		try {
			ProcessBuilder pb = new ProcessBuilder(full);
			pb.redirectErrorStream(true);
			pb.directory(so.toAbsolutePath().getParent().toFile());
			Process p = pb.start();
			p.getOutputStream().close();
			byte[] out = p.getInputStream().readAllBytes();
			if (!p.waitFor(300, TimeUnit.SECONDS)) {
				p.destroyForcibly();
				cacheJson.add(tool + " timed out");
				return "";
			}
			return new String(out, StandardCharsets.UTF_8);
		} catch (Exception e) {
			cacheJson.add(tool + " failed: " + e.getMessage());
			return "";
		}
	}
}