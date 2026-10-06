package com.jadxstudio.analysis.so;

import java.util.ArrayList;
import java.util.List;

/** Parsed ELF structure + extracted strings + heuristic findings. */
public class ElfInfo {

	public static class Header {
		public boolean is64;
		public String classHeader;
		public String data;
		public String type;
		public String machine;
		public long entry;
		public int phoff;
		public int shoff;
		public int phentsize;
		public int phnum;
		public int shentsize;
		public int shnum;
		public int shstrndx;
	}

	public static class Section {
		public String name;
		public String typeName;
		public long type;
		public long flags;
		public long addr;
		public long offset;
		public long size;
	}

	public static class Segment {
		public String typeName;
		public long type;
		public long offset;
		public long vaddr;
		public long filesz;
		public long memsz;
		public long flags;
	}

	public final Header header = new Header();
	public final List<Section> sections = new ArrayList<>();
	public final List<Segment> segments = new ArrayList<>();
	public final List<SymbolInfo> symbols = new ArrayList<>();
	public final List<String> strings = new ArrayList<>();
	public final List<String> findings = new ArrayList<>();

	public String headerText() {
		StringBuilder sb = new StringBuilder();
		sb.append("ELF ").append(header.is64 ? "64-bit" : "32-bit").append('\n');
		sb.append("Type:    ").append(header.type).append('\n');
		sb.append("Machine: ").append(header.machine).append('\n');
		sb.append("Data:    ").append(header.data).append('\n');
		sb.append("Entry:   0x").append(Long.toHexString(header.entry)).append('\n');
		sb.append("Sections: ").append(sections.size()).append("  Segments: ").append(segments.size())
				.append('\n');
		return sb.toString();
	}

	public String stringsText() {
		StringBuilder sb = new StringBuilder();
		int n = 0;
		for (String s : strings) {
			sb.append(s).append('\n');
			if (++n >= 4000) {
				sb.append("... (").append(strings.size() - n).append(" more)\n");
				break;
			}
		}
		return sb.toString();
	}

	public String findingsText() {
		if (findings.isEmpty()) {
			return "No notable findings (heuristic scan).";
		}
		StringBuilder sb = new StringBuilder();
		for (String f : findings) {
			sb.append(" - ").append(f).append('\n');
		}
		return sb.toString();
	}
}
