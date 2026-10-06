package com.jadxstudio.core;

import jadx.api.ICodeInfo;
import jadx.api.JadxArgs;
import jadx.api.JadxDecompiler;
import jadx.api.JavaClass;
import jadx.api.ResourceFile;
import jadx.api.ResourceType;
import jadx.api.args.GeneratedRenamesMappingFileMode;
import jadx.core.dex.attributes.AFlag;
import jadx.core.dex.nodes.ClassNode;
import jadx.core.xmlgen.ResContainer;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.TreeMap;

/**
 * Loads an APK/DEX/AAR/AAB/ZIP through the jadx engine, indexes decompiled
 * sources, decodes resources and keeps user edits + deobfuscation mappings.
 *
 * <p>
 * Decompilation is best effort: output may be wrong or incomplete.
 */
public class Project {

	private Path input;
	private Path output;
	private Path mappingFile;

	private JadxDecompiler dec;
	/** fullName -> class (lazy: text is decompiled on demand, so load stays fast) */
	private final Map<String, JavaClass> classIndex = new LinkedHashMap<>();
	private final List<String> classPaths = new ArrayList<>();
	/** small LRU cache of decompiled text (bounded to keep memory sane on huge APKs) */
	private final Map<String, CodeHolder> sourceMap = new LinkedHashMap<>();
	private static final int TEXT_CACHE_MAX = 160;
	private static final int TEXT_CACHE_CHARS = 8_000_000;
	private int textCacheChars;
	private volatile java.util.function.Consumer<Progress> progressListener = msg -> {
	};
	private final List<String> resourcePaths = new ArrayList<>();
	private final List<String> nativePaths = new ArrayList<>();
	private final List<ResourceFile> resFiles = new ArrayList<>();
	private final Map<String, ResContainer> resTableFiles = new LinkedHashMap<>();
	private String manifestXml = "";
	private int issues;
	private boolean loaded;

	/** Deobfuscation mapping in jadx .jobf format: "c raw.name" -&gt; "NewName". */
	private final Map<String, String> mapping = new LinkedHashMap<>();
/** User edits: path key (a/b/C.java or a/b/C.smali) -&gt; edited text. */
	private final Map<String, String> edits = new TreeMap<>();
	private boolean mappingsChanged;

	/** Names shorter than this (or longer than max) get renamed by deobfuscation. */
	private int deobfMinLength = 3;
	private int deobfMaxLength = Integer.MAX_VALUE;

	// ------------------------------------------------------------- loading

	public synchronized void load(Path file) throws Exception {
		this.input = file.toAbsolutePath();
		if (mappingFile == null) {
			String base = file.getFileName().toString();
			int dot = base.lastIndexOf('.');
			if (dot > 0) {
				base = base.substring(0, dot);
			}
			this.mappingFile = input.resolveSibling(base + ".jobf");
		}
		mapping.clear();
		if (Files.isRegularFile(mappingFile)) {
			mapping.putAll(readJobf(mappingFile));
		}
		doLoad();
	}

	private void doLoad() throws Exception {
		if (dec != null) {
			try {
				dec.close();
			} catch (Exception ignored) {
			}
			dec = null;
		}
		sourceMap.clear();
		classIndex.clear();
		classPaths.clear();
		textCacheChars = 0;
		resourcePaths.clear();
		nativePaths.clear();
		resFiles.clear();
		resTableFiles.clear();
		manifestXml = "";

		JadxArgs args = new JadxArgs();
		args.setInputFiles(List.of(input.toFile()));
		Path out = output != null ? output : Files.createTempDirectory("jadxstudio");
		args.setRootDir(out.toFile());
		args.setDeobfuscationOn(true);
		args.setDeobfuscationMinLength(deobfMinLength);
		args.setDeobfuscationMaxLength(deobfMaxLength);
		if (mappingFile != null) {
			args.setGeneratedRenamesMappingFile(mappingFile.toFile());
			args.setGeneratedRenamesMappingFileMode(GeneratedRenamesMappingFileMode.READ_OR_SAVE);
		}
		args.setThreadsCount(Math.max(2, Runtime.getRuntime().availableProcessors()));
		dec = new JadxDecompiler(args);
		dec.load();
		try {
			buildIndex();
		} catch (Exception e) {
			throw new IllegalStateException("Failed to index decompiled output: " + e.getMessage(), e);
		}
		issues = dec.getErrorsCount() + dec.getWarnsCount();
		refreshMappingFromFile();
		loaded = true;
	}

	/**
	 * Re-read the mapping file: jadx writes generated renames into it during
	 * load (first run), so the deobfuscation editor sees them immediately.
	 */
	private void refreshMappingFromFile() {
		if (mappingFile == null || !Files.isRegularFile(mappingFile)) {
			return;
		}
		try {
			Map<String, String> onDisk = readJobf(mappingFile);
			if (!onDisk.isEmpty()) {
				mapping.clear();
				mapping.putAll(onDisk);
			}
		} catch (IOException ignored) {
		}
	}

	/** Re-run decompilation applying the current mapping (used by deobfuscation). */
	public synchronized void reloadWithMappings() throws Exception {
		if (input == null) {
			throw new IllegalStateException("No file loaded");
		}
		if (mappingsChanged && mappingFile != null) {
			writeJobf(mappingFile, mapping);
			mappingsChanged = false;
		}
		Map<String, String> savedEdits = new TreeMap<>(edits);
		doLoad();
		// user edits survive re-decompilation (they are applied on top)
		edits.clear();
		edits.putAll(savedEdits);
		for (Map.Entry<String, String> e : edits.entrySet()) {
			applyEditInternal(e.getKey(), e.getValue());
		}
	}

	private void buildIndex() {
		// NOTE: decompilation is deliberately lazy - a 20-dex APK has tens of thousands of
		// classes and decompiling all of them up front is what made the GUI hang
		List<JavaClass> classes = dec.getClasses();
		int i = 0;
		for (JavaClass jc : classes) {
			ClassNode cn = jc.getClassNode();
			if (cn.contains(AFlag.DONT_GENERATE)) {
				continue;
			}
			classIndex.put(jc.getFullName(), jc);
			classPaths.add(jc.getFullName().replace('.', '/') + ".java");
			if (++i % 250 == 0) {
				progress(Progress.of((int) (100L * i / Math.max(1, classes.size())),
						"Indexing " + i + "/" + classes.size() + " classes"));
			}
		}
		classPaths.sort(String::compareTo);

		for (ResourceFile rf : dec.getResources()) {
			ResourceType type = rf.getType();
			String name = rf.getOriginalName();
			if (name == null || name.isEmpty()) {
				continue;
			}
			if (type == ResourceType.CODE) {
				continue;
			}
			if (type == ResourceType.LIB) {
				nativePaths.add(name);
				continue;
			}
			resourcePaths.add(name);
			if (type == ResourceType.ARSC) {
				try {
					ResContainer rc = rf.loadContent();
					if (rc != null && rc.getDataType() == ResContainer.DataType.RES_TABLE) {
						for (ResContainer sub : rc.getSubFiles()) {
							String subName = sub.getName();
							resTableFiles.put(subName, sub);
							if (!resourcePaths.contains(subName)) {
								resourcePaths.add(subName);
							}
						}
					}
				} catch (Exception e) {
					issues++;
				}
			}
			if (type == ResourceType.MANIFEST) {
				try {
					ResContainer rc = rf.loadContent();
					if (rc != null && rc.getText() != null) {
						manifestXml = rc.getText().getCodeStr();
					}
				} catch (Exception e) {
					issues++;
				}
			}
		}
		if (manifestXml == null || manifestXml.isBlank()) {
			manifestXml = com.jadxstudio.analysis.xml.XmlAnalyzer.decodeManifestFallback(input);
		}
	}

	private String safeSmali(ClassNode cn) {
		try {
			return cn.getDisassembledCode();
		} catch (Exception e) {
			return "// smali unavailable: " + e.getMessage();
		}
	}

	// ------------------------------------------------------------- getters

	public synchronized Path getRoot() {
		return input;
	}

	public synchronized Path getOutput() {
		return output;
	}

	public synchronized void setOutput(Path output) {
		this.output = output;
	}

	public synchronized void setMappingPath(Path p) {
		this.mappingFile = p;
	}

	public synchronized Path getMappingPath() {
		return mappingFile;
	}

	public synchronized Map<String, CodeHolder> getSourceMap() {
		return sourceMap;
	}

	/**
	 * All strings found in native libraries (cheap, used by the protector scanner).
	 * Cached after the first call so repeated scans stay instant.
	 */
	private List<String> nativeStringsCache;

	public synchronized List<String> collectStrings() {
		if (nativeStringsCache != null) {
			return nativeStringsCache;
		}
		List<String> out = new ArrayList<>();
		for (String lib : nativePaths) {
			try {
				byte[] data = readResource(lib);
				if (data == null) {
					continue;
				}
				StringBuilder cur = new StringBuilder();
				for (byte b : data) {
					int c = b & 0xff;
					if (c >= 0x20 && c < 0x7f) {
						cur.append((char) c);
					} else {
						if (cur.length() >= 5) {
							out.add(cur.toString());
						}
						cur.setLength(0);
					}
				}
				if (cur.length() >= 5) {
					out.add(cur.toString());
				}
			} catch (Exception ignored) {
			}
			if (out.size() > 60_000) {
				break;
			}
		}
		nativeStringsCache = out;
		return out;
	}

	/**
	 * Blank static fields (class, field, type) - PairIP keeps protected strings here.
	 * Reads dex metadata only, no decompilation, so it stays fast.
	 */
	public synchronized List<String[]> blankStaticFields() {
		List<String[]> out = new ArrayList<>();
		if (dec == null) {
			return out;
		}
		for (JavaClass jc : dec.getClasses()) {
			ClassNode cn = jc.getClassNode();
			for (var f : cn.getFields()) {
				if (!f.getAccessFlags().isStatic()) {
					continue;
				}
				var fi = f.getFieldInfo();
				String type = String.valueOf(fi.getType());
				out.add(new String[] { jc.getFullName(), fi.getName(), type });
				if (out.size() > 40000) {
					return out;
				}
			}
		}
		return out;
	}

	/** Application class declared in the manifest (if any). */
	public String getApplicationClass() {
		String m = getManifestXml();
		java.util.regex.Matcher mt = java.util.regex.Pattern
				.compile("<application[^>]*android:name\s*=\s*\"([^\"]+)\"").matcher(m);
		if (mt.find()) {
			return mt.group(1);
		}
		return null;
	}

	/** Class file paths (e.g. com/foo/Bar.java) - cheap, no decompilation needed. */
	public synchronized List<String> getClassPaths() {
		return classPaths;
	}

	public synchronized int getClassCount() {
		return classIndex.size();
	}

	public void setProgressListener(java.util.function.Consumer<Progress> listener) {
		this.progressListener = listener == null ? msg -> {
		} : listener;
	}

	private void progress(String msg) {
		progress(new Progress(-1, msg));
	}

	/** Emit a phase update without a percentage (percentage unknown). */
	private void progress(Progress p) {
		try {
			progressListener.accept(p);
		} catch (Exception ignored) {
		}
	}

	/** Total number of classes (for percentage maths). */
	public synchronized int totalClasses() {
		return classIndex.size();
	}

	/** Iterate every class, decompiling one at a time (used by export/search). */
	public synchronized List<String> classNames() {
		return new ArrayList<>(classIndex.keySet());
	}

	public synchronized String decompileText(String fullName) {
		CodeHolder h = getCode(fullName, DecompileTarget.JAVA);
		return h == null ? null : h.text;
	}

	public synchronized List<String> getResourcePaths() {
		return resourcePaths;
	}

	public synchronized List<String> getNativePaths() {
		return nativePaths;
	}

	public synchronized String getManifestXml() {
		return manifestXml == null ? "" : manifestXml;
	}

	public synchronized int getIssueCount() {
		return issues;
	}

	public synchronized boolean isLoaded() {
		return loaded;
	}

	/** Set deobfuscation name-length thresholds (default min 3, no max). */
	public synchronized void setDeobfuscationLengths(int min, int max) {
		this.deobfMinLength = min;
		this.deobfMaxLength = max;
	}

	public synchronized Map<String, String> getMapping() {
		return mapping;
	}

	public synchronized void setMappingsChanged() {
		this.mappingsChanged = true;
	}

	// --------------------------------------------------------------- code

	/** Returns decompiled java or disassembled smali for a class (with edits applied). */
	public synchronized CodeHolder getCode(String className, DecompileTarget target) {
		String cls = normalizeClassName(className);
		String ext = target == DecompileTarget.SMALI ? ".smali" : ".java";
		String key = cls.replace('.', '/') + ext;
		String edited = edits.get(key);
		if (edited != null) {
			return new CodeHolder(edited, null);
		}
		CodeHolder cached = sourceMap.get(key);
		if (cached != null) {
			// refresh LRU position
			sourceMap.remove(key);
			sourceMap.put(key, cached);
			return cached;
		}
		JavaClass jc = classIndex.get(cls);
		if (jc == null) {
			jc = findJavaClass(cls);
		}
		if (jc == null) {
			return null;
		}
		CodeHolder result;
		if (target == DecompileTarget.SMALI) {
			StringBuilder sb = new StringBuilder();
			appendSmali(sb, jc.getClassNode());
			result = new CodeHolder(sb.toString(), null);
		} else {
			String text;
			List<String> errs = new ArrayList<>();
			try {
				text = jc.isNoCode() ? null : jc.getCode();
			} catch (Exception e) {
				text = null;
				errs.add("decompiler failed: " + e.getMessage());
			}
			if (text == null || text.isBlank()) {
				String smali = safeSmali(jc.getClassNode());
				text = "// Best-effort decompilation unavailable for this class.\n"
						+ "// Showing smali bytecode instead (verify manually).\n\n" + smali;
				errs.add("java decompilation failed; smali fallback shown");
			} else if (text.contains("JADX ERROR")) {
				errs.add("contains JADX ERROR comments");
			} else if (text.contains("JADX WARN")) {
				errs.add("contains JADX WARNING comments");
			}
			result = new CodeHolder(text, errs.isEmpty() ? null : errs);
		}
		putCached(key, result);
		return result;
	}

	/** LRU insert with size caps so huge APKs cannot exhaust memory. */
	private void putCached(String key, CodeHolder h) {
		sourceMap.put(key, h);
		textCacheChars += h.text.length();
		while (sourceMap.size() > TEXT_CACHE_MAX || textCacheChars > TEXT_CACHE_CHARS) {
			var it = sourceMap.entrySet().iterator();
			if (!it.hasNext()) {
				break;
			}
			Map.Entry<String, CodeHolder> first = it.next();
			if (first.getKey().equals(key)) {
				break;
			}
			textCacheChars -= first.getValue().text.length();
			it.remove();
		}
	}

	private void appendSmali(StringBuilder sb, ClassNode cn) {
		try {
			sb.append(cn.getDisassembledCode());
		} catch (Exception e) {
			sb.append("# smali unavailable: ").append(e.getMessage());
		}
		for (ClassNode inner : cn.getInnerClasses()) {
			sb.append('\n');
			appendSmali(sb, inner);
		}
	}

	private static String normalizeClassName(String className) {
		String cls = className.replace('/', '.');
		if (cls.endsWith(".java")) {
			cls = cls.substring(0, cls.length() - 5);
		}
		if (cls.endsWith(".smali")) {
			cls = cls.substring(0, cls.length() - 6);
		}
		return cls;
	}

	private synchronized JavaClass findJavaClass(String fullName) {
		if (dec == null) {
			return null;
		}
		for (JavaClass jc : dec.getClasses()) {
			if (jc.getFullName().equals(fullName)) {
				return jc;
			}
		}
		return null;
	}

	private synchronized ClassNode findClassNode(String fullName) {
		JavaClass jc = findJavaClass(fullName);
		return jc == null ? null : jc.getClassNode();
	}

	// ----------------------------------------------------------- resources

	public synchronized boolean isResourcePath(String path) {
		return resourcePaths.contains(path) || nativePaths.contains(path) || resTableFiles.containsKey(path);
	}

	public synchronized byte[] readResource(String path) throws IOException {
		ResContainer sub = resTableFiles.get(path);
		if (sub != null) {
			byte[] b = containerBytes(sub);
			if (b != null) {
				return b;
			}
		}
		for (ResourceFile rf : resFiles()) {
			if (!path.equals(rf.getOriginalName()) && !path.equals(rf.getDeobfName())) {
				continue;
			}
			try {
				ResContainer rc = rf.loadContent();
				if (rc == null) {
					return rawZipEntry(path);
				}
				if (rc.getDataType() == ResContainer.DataType.RES_LINK) {
					// link target is the resource file itself: read raw bytes from the archive
					byte[] raw = rawZipEntry(rf.getOriginalName());
					return raw != null ? raw : rawZipEntry(path);
				}
				if (rc.getDataType() == ResContainer.DataType.RES_TABLE) {
					for (ResContainer s : rc.getSubFiles()) {
						if (path.equals(s.getName())) {
							byte[] b = containerBytes(s);
							if (b != null) {
								return b;
							}
						}
					}
				}
				byte[] b = containerBytes(rc);
				if (b != null) {
					return b;
				}
				return rawZipEntry(rf.getOriginalName());
			} catch (Exception e) {
				return rawZipEntry(path);
			}
		}
		return rawZipEntry(path);
	}

	/** Read raw entry bytes straight from the loaded archive. */
	private byte[] rawZipEntry(String path) {
		if (input == null) {
			return null;
		}
		try (java.util.zip.ZipFile zip = new java.util.zip.ZipFile(input.toFile())) {
			java.util.zip.ZipEntry e = zip.getEntry(path);
			if (e == null) {
				return null;
			}
			try (java.io.InputStream is = zip.getInputStream(e)) {
				return is.readAllBytes();
			}
		} catch (Exception ex) {
			return null;
		}
	}

	private List<ResourceFile> resFiles() {
		if (resFiles.isEmpty() && dec != null) {
			resFiles.addAll(dec.getResources());
		}
		return resFiles;
	}

	private static byte[] containerBytes(ResContainer rc) {
		try {
			return switch (rc.getDataType()) {
				case TEXT, RES_TABLE -> {
					ICodeInfo t = rc.getText();
					yield t == null || t == ICodeInfo.EMPTY ? null : t.getCodeStr().getBytes(StandardCharsets.UTF_8);
				}
				case DECODED_DATA -> rc.getDecodedData();
				case RES_LINK -> null; // resolved via raw zip read
			};
		} catch (Exception e) {
			return null;
		}
	}

	// --------------------------------------------------------------- edits

	/** Apply a user edit for a source/smali file (path key, e.g. a/b/C.java). */
	public synchronized void applyEdit(String key, String text) {
		edits.put(key, text);
		applyEditInternal(key, text);
	}

	private void applyEditInternal(String key, String text) {
		CodeHolder h = new CodeHolder(text, null);
		sourceMap.remove(key);
		putCached(key, h);
	}

	public synchronized int exportEdits(Path dir) throws IOException {
		int n = 0;
		for (Map.Entry<String, String> e : edits.entrySet()) {
			Path f = dir.resolve(e.getKey());
			Files.createDirectories(f.getParent());
			Files.writeString(f, e.getValue(), StandardCharsets.UTF_8);
			n++;
		}
		return n;
	}

	// -------------------------------------------------------------- export

	/** Export sources and/or resources into the output folder. Returns file count. */
	public synchronized int export(ExportOptions o) throws IOException {
		if (output == null) {
			throw new IOException("Output folder not set");
		}
		int n = 0;
		if (o.export && o.sources) {
			Path src = output.resolve("sources");
			Files.createDirectories(src);
			List<String> names = classNames();
			for (int i = 0; i < names.size(); i++) {
				String full = names.get(i);
				if (i % 5 == 0 || names.size() < 20) {
					progress(Progress.of((int) (100L * (i + 1) / Math.max(1, names.size())),
							"Exporting " + (i + 1) + "/" + names.size() + " classes"));
				}
				String edit = edits.get(full.replace('.', '/') + ".java");
				CodeHolder h = edit != null ? new CodeHolder(edit, null)
						: getCode(full, DecompileTarget.JAVA);
				if (h == null) {
					continue;
				}
				Path f = src.resolve(full.replace('.', '/') + ".java");
				Files.createDirectories(f.getParent());
				Files.writeString(f, h.text, StandardCharsets.UTF_8);
				n++;
			}
		}
		if (o.export && o.resources) {
			Path res = output.resolve("resources");
			Files.createDirectories(res);
			if (manifestXml != null && !manifestXml.isBlank()) {
				Files.writeString(res.resolve("AndroidManifest.xml"), manifestXml, StandardCharsets.UTF_8);
				n++;
			}
			for (String p : resourcePaths) {
				try {
					byte[] data = readResource(p);
					if (data == null) {
						continue;
					}
					Path f = res.resolve(p);
					Files.createDirectories(f.getParent());
					Files.write(f, data);
					n++;
				} catch (Exception ignored) {
				}
			}
			for (String p : nativePaths) {
				try {
					byte[] data = readResource(p);
					if (data == null) {
						continue;
					}
					Path f = res.resolve(p);
					Files.createDirectories(f.getParent());
					Files.write(f, data);
					n++;
				} catch (Exception ignored) {
				}
			}
			Files.writeString(output.resolve("DISCLAIMER.txt"), """
					Best-effort output generated by JADX Studio.

					Decompiled Java source is reconstructed automatically from Dalvik
					bytecode and may be wrong, incomplete or fail to compile. When in
					doubt, compare against the smali/bytecode and verify manually.
					""", StandardCharsets.UTF_8);
			n++;
		}
		if (o.export && mappingFile != null && Files.isRegularFile(mappingFile)) {
			Files.copy(mappingFile, output.resolve(mappingFile.getFileName()),
					java.nio.file.StandardCopyOption.REPLACE_EXISTING);
			n++;
		}
		return n;
	}

	// -------------------------------------------------------------- search

	public record SearchHit(String path, int line, String preview) {
	}

	/**
	 * Full-text search across all classes (decompiled one at a time so memory stays flat)
	 * plus manifest and text resources.
	 */
	public enum SearchMode {
		/** plain text lines containing the query */
		TEXT,
		/** class / method / field declarations matching the query */
		SYMBOL,
		/** string literals that contain the query (e.g. urls, api keys) */
		STRING_LITERAL,
		/** numeric literals that contain the query */
		NUMBER
	}

	public synchronized List<SearchHit> search(String query, boolean caseSensitive, int maxHits,
			int[] progressState) {
		return search(query, caseSensitive, maxHits, progressState, SearchMode.TEXT);
	}

	public synchronized List<SearchHit> search(String query, boolean caseSensitive, int maxHits,
			int[] progressState, SearchMode mode) {
		List<SearchHit> out = new ArrayList<>();
		if (query == null || query.isBlank()) {
			return out;
		}
		String needle = caseSensitive ? query : query.toLowerCase(Locale.ROOT);
		List<String> names = classNames();
		java.util.regex.Pattern lit = literalPattern(query, mode, caseSensitive);
		for (int i = 0; i < names.size(); i++) {
			int pct = (int) (100L * (i + 1) / Math.max(1, names.size()));
			if (progressState != null) {
				progressState[0] = pct;
			}
			if (i % 3 == 0 || names.size() < 20) {
				progress(Progress.of(pct, "Searching " + (i + 1) + "/" + names.size() + " classes ("
						+ mode.name().toLowerCase(Locale.ROOT).replace('_', ' ') + ")"));
			}
			String full = names.get(i);
			CodeHolder h = getCode(full, DecompileTarget.JAVA);
			if (h == null) {
				continue;
			}
			out.addAll(hit(h.text, full.replace('.', '/') + ".java", needle, caseSensitive, out.size(), maxHits,
					mode, lit));
			if (out.size() >= maxHits) {
				break;
			}
		}
		String manifest = getManifestXml();
		if (!manifest.isBlank()) {
			out.addAll(hit(manifest, "AndroidManifest.xml", needle, caseSensitive, out.size(), maxHits, mode, lit));
		}
		return out;
	}

	/** Regex for the literal-oriented search modes. */
	private static java.util.regex.Pattern literalPattern(String query, SearchMode mode, boolean cs) {
		if (mode != SearchMode.STRING_LITERAL && mode != SearchMode.NUMBER && mode != SearchMode.SYMBOL) {
			return null;
		}
		String q = java.util.regex.Pattern.quote(query);
		String body = switch (mode) {
			case STRING_LITERAL -> "\"[^\\\"\\\\\\n]*" + q + "[^\\\"\\\\\\n]*\"";
			case NUMBER -> "\\b(?:0[xX][0-9a-fA-F]+|[0-9][0-9_]*(?:\\.[0-9_]+)?(?:[lLfFdD])?)\\b";
			case SYMBOL -> "\\b(?:class|interface|enum|void|public|private|protected|static|final|abstract|native)\\b[^\\n]*"
					+ q + "[^\\n]*";
			default -> null;
		};
		return java.util.regex.Pattern.compile(body, cs ? 0 : java.util.regex.Pattern.CASE_INSENSITIVE);
	}

	/** Matches the requested mode and records hits. */
	private static List<SearchHit> hit(String text, String path, String needle, boolean caseSensitive,
			int already, int maxHits, SearchMode mode, java.util.regex.Pattern lit) {
		List<SearchHit> out = new ArrayList<>();
		if (mode == SearchMode.TEXT) {
			return scan(text, path, needle, caseSensitive, already, maxHits);
		}
		if (lit == null) {
			return out;
		}
		java.util.regex.Matcher m = lit.matcher(text);
		int line = 1;
		int lastLine = 1;
		while (m.find() && already + out.size() < maxHits) {
			line = 1 + (int) text.substring(0, m.start()).chars().filter(c -> c == '\n').count();
			if (line == lastLine) {
				continue;
			}
			lastLine = line;
			String value = m.group().trim();
			if (mode == SearchMode.NUMBER && !value.toLowerCase(Locale.ROOT).contains(needle)) {
				continue;
			}
			if (mode == SearchMode.STRING_LITERAL && !value.toLowerCase(Locale.ROOT).contains(needle)) {
				continue;
			}
			int lineStart = text.lastIndexOf('\n', m.start()) + 1;
			int lineEnd = text.indexOf('\n', m.start());
			if (lineEnd < 0) {
				lineEnd = text.length();
			}
			out.add(new SearchHit(path, line, shortenValue(value)));
		}
		return out;
	}

	private static String shortenValue(String v) {
		return v.length() > 160 ? v.substring(0, 160) + "..." : v;
	}

	private static List<SearchHit> scan(String text, String path, String needle, boolean caseSensitive,
			int already, int maxHits) {
		List<SearchHit> out = new ArrayList<>();
		String hay = caseSensitive ? text : text.toLowerCase(Locale.ROOT);
		int from = 0;
		int line = 1;
		while (true) {
			int at = hay.indexOf(needle, from);
			if (at < 0 || already + out.size() >= maxHits) {
				break;
			}
			line = 1 + (int) hay.substring(0, at).chars().filter(c -> c == '\n').count();
			int lineStart = hay.lastIndexOf('\n', at) + 1;
			int lineEnd = hay.indexOf('\n', at);
			if (lineEnd < 0) {
				lineEnd = text.length();
			}
			out.add(new SearchHit(path, line, text.substring(lineStart, lineEnd).trim()));
			from = at + Math.max(1, needle.length());
		}
		return out;
	}

	// ------------------------------------------------------------- mapping

	/** Reads a .jobf mapping file: lines like "c raw.Name = NewName". */
	public static Map<String, String> readJobf(Path file) throws IOException {
		Map<String, String> out = new LinkedHashMap<>();
		for (String line : Files.readAllLines(file, StandardCharsets.UTF_8)) {
			String l = line.trim();
			if (l.isEmpty() || l.startsWith("#") || l.length() < 4) {
				continue;
			}
			char kind = l.charAt(0);
			if (kind != 'c' && kind != 'm' && kind != 'f' && kind != 'p') {
				continue;
			}
			if (l.charAt(1) != ' ') {
				continue;
			}
			String rest = l.substring(2);
			int eq = rest.lastIndexOf('=');
			if (eq <= 0) {
				continue;
			}
			String orig = rest.substring(0, eq).trim();
			String alias = rest.substring(eq + 1).trim();
			if (!orig.isEmpty() && !alias.isEmpty()) {
				out.put(kind + " " + orig, alias);
			}
		}
		return out;
	}

	public static void writeJobf(Path file, Map<String, String> mapping) throws IOException {
		List<String> lines = new ArrayList<>();
		for (Map.Entry<String, String> e : mapping.entrySet()) {
			if (e.getValue() == null || e.getValue().isBlank()) {
				continue;
			}
			String k = e.getKey();
			if (k.length() < 3 || k.charAt(1) != ' ') {
				continue;
			}
			lines.add(k + " = " + e.getValue().trim());
		}
		lines.sort(String::compareTo);
		if (file.getParent() != null) {
			Files.createDirectories(file.getParent());
		}
		Files.write(file, lines, StandardCharsets.UTF_8);
	}
}

