package com.jadxstudio.core;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Locale;

/**
 * Lightweight in-memory index over decompiled sources for
 * go-to-declaration, find-usages and text search.
 */
public class JavaIndex {

	public record Entry(String display, String kind, String target, String text, int line) {
	}

	private final List<Entry> entries = new ArrayList<>();
	private final List<String[]> textDocs = new ArrayList<>(); // [path, text]

	public synchronized void clear() {
		entries.clear();
		textDocs.clear();
	}

	public synchronized void addSource(String path, String text) {
		textDocs.add(new String[] { path, text });
		String[] lines = text.split("\n", -1);
		for (int i = 0; i < lines.length; i++) {
			String line = lines[i].trim();
			String cls = match(line, "class ", 5);
			if (cls == null) {
				cls = match(line, "interface ", 10);
			}
			if (cls == null) {
				cls = match(line, "enum ", 5);
			}
			if (cls != null) {
				entries.add(new Entry(cls, "class", path, line, i + 1));
				continue;
			}
			if (line.startsWith("package ") && line.endsWith(";")) {
				String pkg = line.substring(8, line.length() - 1);
				entries.add(new Entry(pkg, "package", path, line, i + 1));
			}
		}
	}

	public synchronized void addText(String path, String text) {
		textDocs.add(new String[] { path, text });
	}

	public static String match(String line, String kw, int prefixLen) {
		int idx = line.indexOf(kw);
		if (idx < 0 || idx > prefixLen + 6) {
			return null;
		}
		// ensure keyword starts a declaration, not e.g. "classX"
		if (idx + kw.length() < line.length()) {
			char c = line.charAt(idx + kw.length());
			if (Character.isLetterOrDigit(c) || c == '_' || c == '$') {
				return null;
			}
		}
		String rest = line.substring(idx + kw.length()).trim();
		int end = 0;
		while (end < rest.length()) {
			char c = rest.charAt(end);
			if (Character.isLetterOrDigit(c) || c == '_' || c == '$' || c == '.') {
				end++;
			} else {
				break;
			}
		}
		if (end == 0) {
			return null;
		}
		String name = rest.substring(0, end);
		if (name.equals("extends") || name.equals("implements") || name.equals("new")) {
			return null;
		}
		return name;
	}

	public synchronized List<String> search(String query, int limit) {
		List<String> out = new ArrayList<>();
		if (query == null || query.isEmpty()) {
			for (Entry e : entries) {
				if (out.size() >= limit) {
					break;
				}
				out.add(e.display() + "   [" + e.kind() + "]");
			}
			return out;
		}
		String q = query.toLowerCase(Locale.ROOT);
		List<Entry> scored = new ArrayList<>();
		for (Entry e : entries) {
			if (e.display().toLowerCase(Locale.ROOT).contains(q)) {
				scored.add(e);
			}
		}
		scored.sort(Comparator.comparingInt((Entry e) -> {
			String d = e.display().toLowerCase(Locale.ROOT);
			return d.startsWith(q) ? 0 : d.contains("." + q) ? 1 : 2;
		}).thenComparing(Entry::display));
		for (Entry e : scored) {
			if (out.size() >= limit) {
				break;
			}
			out.add(e.display() + "   [" + e.kind() + "]");
		}
		return out;
	}

	public synchronized Entry resolve(String display) {
		String bare = display;
		int i = bare.indexOf("   [");
		if (i > 0) {
			bare = bare.substring(0, i);
		}
		for (Entry e : entries) {
			if (e.display().equals(bare)) {
				return e;
			}
		}
		for (Entry e : entries) {
			if (e.display().endsWith("." + bare) || e.display().equals(bare)) {
				return e;
			}
		}
		return null;
	}

	/** Find all lines containing the needle across indexed text. */
	public synchronized List<int[]> findUsages(String needle, boolean caseSensitive) {
		List<int[]> hits = new ArrayList<>(); // [docIdx, line]
		if (needle == null || needle.isEmpty()) {
			return hits;
		}
		for (int d = 0; d < textDocs.size(); d++) {
			String text = textDocs.get(d)[1];
			String hay = caseSensitive ? text : text.toLowerCase(Locale.ROOT);
			String nd = caseSensitive ? needle : needle.toLowerCase(Locale.ROOT);
			int from = 0;
			while (true) {
				int at = hay.indexOf(nd, from);
				if (at < 0) {
					break;
				}
				int line = countNewlines(text, at);
				hits.add(new int[] { d, line });
				if (hits.size() > 20000) {
					return hits;
				}
				from = at + Math.max(1, nd.length());
			}
		}
		return hits;
	}

	public synchronized String docPath(int docIdx) {
		return textDocs.get(docIdx)[0];
	}

	public synchronized String docText(int docIdx) {
		return textDocs.get(docIdx)[1];
	}

	public synchronized int docCount() {
		return textDocs.size();
	}

	public synchronized List<String> allPaths() {
		List<String> out = new ArrayList<>();
		for (String[] t : textDocs) {
			out.add(t[0]);
		}
		return out;
	}

	private static int countNewlines(String text, int idx) {
		int line = 1;
		for (int i = 0; i < idx && i < text.length(); i++) {
			if (text.charAt(i) == '\n') {
				line++;
			}
		}
		return line;
	}
}
