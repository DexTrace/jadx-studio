package com.jadxstudio.analysis.so;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Locale;
import java.util.Set;

/**
 * Minimal ELF parser for Android native libraries (.so): headers, sections,
 * segments, dynamic symbols, printable strings and heuristic security findings.
 */
public final class ElfScanner {

	private static final Set<String> SUSPICIOUS_IMPORTS = Set.of(
			"system", "popen", "execve", "execl", "fork", "vfork", "ptrace", "chmod", "chown",
			"kill", "setuid", "setgid", "getuid", "dlopen", "dlsym", "dlclose", "mprotect",
			"__system_property_get", "property_get", "socket", "connect", "send", "recv",
			"fopen", "open", "remove", "rename", "unlink", "symlink", "mount", "umount");

	private ElfScanner() {
	}

	public static ElfInfo analyze(Path file) throws IOException {
		byte[] data = Files.readAllBytes(file);
		return analyze(data);
	}

	public static ElfInfo analyze(byte[] data) {
		ElfInfo info = new ElfInfo();
		if (data.length < 52 || data[0] != 0x7f || data[1] != 'E' || data[2] != 'L' || data[3] != 'F') {
			info.findings.add("Not an ELF file (bad magic)");
			extractStrings(data, info);
			return info;
		}
		int cls = data[4]; // 1=32bit 2=64bit
		int enc = data[5]; // 1=LE 2=BE
		ByteOrder order = enc == 2 ? ByteOrder.BIG_ENDIAN : ByteOrder.LITTLE_ENDIAN;
		boolean is64 = cls == 2;
		ByteBuffer buf = ByteBuffer.wrap(data).order(order);

		ElfInfo.Header h = info.header;
		h.is64 = is64;
		h.classHeader = is64 ? "ELF64" : "ELF32";
		h.data = enc == 2 ? "big endian" : "little endian";
		try {
			int type = buf.getShort(16) & 0xffff;
			int machine = buf.getShort(18) & 0xffff;
			h.type = typeName(type);
			h.machine = machineName(machine);
			if (is64) {
				h.entry = buf.getLong(24);
				h.phoff = (int) buf.getLong(32);
				h.shoff = (int) buf.getLong(40);
				h.phentsize = buf.getShort(54) & 0xffff;
				h.phnum = buf.getShort(56) & 0xffff;
				h.shentsize = buf.getShort(58) & 0xffff;
				h.shnum = buf.getShort(60) & 0xffff;
				h.shstrndx = buf.getShort(62) & 0xffff;
			} else {
				h.entry = buf.getInt(24) & 0xFFFFFFFFL;
				h.phoff = buf.getInt(28);
				h.shoff = buf.getInt(32);
				h.phentsize = buf.getShort(42) & 0xffff;
				h.phnum = buf.getShort(44) & 0xffff;
				h.shentsize = buf.getShort(46) & 0xffff;
				h.shnum = buf.getShort(48) & 0xffff;
				h.shstrndx = buf.getShort(50) & 0xffff;
			}
		} catch (Exception e) {
			info.findings.add("Truncated ELF header: " + e.getMessage());
			extractStrings(data, info);
			return info;
		}

		// program headers
		for (int i = 0; i < h.phnum; i++) {
			try {
				int off = h.phoff + i * h.phentsize;
				ElfInfo.Segment s = new ElfInfo.Segment();
				if (is64) {
					s.type = buf.getInt(off) & 0xFFFFFFFFL;
					s.flags = buf.getInt(off + 4) & 0xFFFFFFFFL;
					s.offset = buf.getLong(off + 8);
					s.vaddr = buf.getLong(off + 16);
					s.filesz = buf.getLong(off + 32);
					s.memsz = buf.getLong(off + 40);
				} else {
					s.type = buf.getInt(off) & 0xFFFFFFFFL;
					s.offset = buf.getInt(off + 4) & 0xFFFFFFFFL;
					s.vaddr = buf.getInt(off + 8) & 0xFFFFFFFFL;
					s.filesz = buf.getInt(off + 16) & 0xFFFFFFFFL;
					s.memsz = buf.getInt(off + 20) & 0xFFFFFFFFL;
					s.flags = buf.getInt(off + 24) & 0xFFFFFFFFL;
				}
				s.typeName = segTypeName(s.type);
				info.segments.add(s);
				boolean r = (s.flags & 4) != 0;
				boolean w = (s.flags & 2) != 0;
				boolean x = (s.flags & 1) != 0;
				if (w && x) {
					info.findings.add("RWX segment at vaddr 0x" + Long.toHexString(s.vaddr)
							+ " (writable + executable)");
				}
			} catch (Exception e) {
				break;
			}
		}

		// section headers
		String[] shstr = new String[0];
		try {
			if (h.shnum > 0 && h.shoff > 0) {
				long[][] secRaw = new long[h.shnum][];
				String[] tmpNames = new String[h.shnum];
				int shstrOff = -1;
				long shstrSize = 0;
				for (int i = 0; i < h.shnum; i++) {
					int off = h.shoff + i * h.shentsize;
					long[] v = new long[10];
					if (is64) {
						v[0] = buf.getInt(off) & 0xFFFFFFFFL; // name
						v[1] = buf.getInt(off + 4) & 0xFFFFFFFFL; // type
						v[2] = buf.getLong(off + 8); // flags
						v[3] = buf.getLong(off + 16); // addr
						v[4] = buf.getLong(off + 24); // offset
						v[5] = buf.getLong(off + 32); // size
					} else {
						v[0] = buf.getInt(off) & 0xFFFFFFFFL;
						v[1] = buf.getInt(off + 4) & 0xFFFFFFFFL;
						v[2] = buf.getInt(off + 8) & 0xFFFFFFFFL;
						v[3] = buf.getInt(off + 12) & 0xFFFFFFFFL;
						v[4] = buf.getInt(off + 16) & 0xFFFFFFFFL;
						v[5] = buf.getInt(off + 20) & 0xFFFFFFFFL;
					}
					secRaw[i] = v;
					if (i == h.shstrndx) {
						shstrOff = (int) v[4];
						shstrSize = v[5];
					}
				}
				if (shstrOff >= 0 && shstrOff + shstrSize <= data.length) {
					byte[] shData = new byte[(int) shstrSize];
					System.arraycopy(data, shstrOff, shData, 0, (int) shstrSize);
					shstr = readStrTab(shData);
				}
				for (int i = 0; i < h.shnum; i++) {
					long[] v = secRaw[i];
					ElfInfo.Section s = new ElfInfo.Section();
					int nameIdx = (int) v[0];
					s.name = nameIdx < shstr.length ? shstr[nameIdx] : "";
					s.type = v[1];
					s.typeName = secTypeName(s.type);
					s.flags = v[2];
					s.addr = v[3];
					s.offset = v[4];
					s.size = v[5];
					info.sections.add(s);
				}
				// read symbols from .dynsym / .symtab
				for (int i = 0; i < h.shnum; i++) {
					long[] v = secRaw[i];
					long type = v[1];
					if (type != 2 && type != 11) { // SYMTAB, DYNSYM
						continue;
					}
					int linkIdx = is64 ? (int) buf.getInt(h.shoff + i * h.shentsize + 40)
							: (int) buf.getInt(h.shoff + i * h.shentsize + 24);
					long strOff = linkIdx >= 0 && linkIdx < secRaw.length ? secRaw[linkIdx][4] : -1;
					long strSize = linkIdx >= 0 && linkIdx < secRaw.length ? secRaw[linkIdx][5] : 0;
					if (strOff < 0 || strOff + strSize > data.length) {
						continue;
					}
					byte[] strData = new byte[(int) strSize];
					System.arraycopy(data, (int) strOff, strData, 0, (int) strSize);
					String[] names = readStrTab(strData);
					int entsize = is64 ? 24 : 16;
					long symOff = v[4];
					long symSize = v[5];
					int count = (int) (symSize / entsize);
					boolean dynsym = type == 11;
					for (int si = 0; si < count && si < 60000; si++) {
						int off = (int) (symOff + (long) si * entsize);
						if (off + entsize > data.length) {
							break;
						}
						int nameI = buf.getInt(off);
						long value;
						long size;
						int bind;
						int styp;
						if (is64) {
							int stInfo = buf.get(off + 4) & 0xff;
							value = buf.getLong(off + 8);
							size = buf.getLong(off + 16);
							bind = stInfo >> 4;
							styp = stInfo & 0xf;
						} else {
							value = buf.getInt(off + 4) & 0xFFFFFFFFL;
							size = buf.getInt(off + 8) & 0xFFFFFFFFL;
							int stInfo = buf.get(off + 12) & 0xff;
							bind = stInfo >> 4;
							styp = stInfo & 0xf;
						}
						if (nameI < 0 || nameI >= names.length) {
							continue;
						}
						String nm = names[nameI];
						if (nm == null || nm.isEmpty()) {
							continue;
						}
						boolean undefined = value == 0 && styp != 0 && dynsym;
						info.symbols.add(new SymbolInfo(nm, value, size, bind, styp, undefined));
					}
				}
			}
		} catch (Exception e) {
			info.findings.add("Section parsing issue: " + e.getMessage());
		}

		extractStrings(data, info);
		analyzeSymbols(info);
		analyzeStrings(info);
		return info;
	}

	private static void analyzeSymbols(ElfInfo info) {
		int exports = 0;
		for (SymbolInfo s : info.symbols) {
			if (s.imported && SUSPICIOUS_IMPORTS.contains(s.name)) {
				info.findings.add("Imports suspicious native API: " + s.name + "()");
			}
			if (!s.imported && (s.name.startsWith("Java_") || s.name.equals("JNI_OnLoad"))) {
				exports++;
			}
		}
		if (exports > 0) {
			info.findings.add(exports + " JNI export(s) found (Java_* / JNI_OnLoad)");
		}
	}

	private static void analyzeStrings(ElfInfo info) {
		int http = 0;
		int b64 = 0;
		for (String s : info.strings) {
			String low = s.toLowerCase(Locale.ROOT);
			if (low.startsWith("http://") || low.startsWith("https://")) {
				if (http++ < 8) {
					info.findings.add("Embedded URL: " + s);
				}
			}
			if (low.contains("/proc/") || low.contains("/dev/")) {
				info.findings.add("Device/proc access string: " + s);
			}
			if (low.contains("magisk") || low.contains("supersu") || low.contains("/system/xbin/su")
					|| low.contains("busybox")) {
				info.findings.add("Root/hotspot related string: " + s);
			}
			if (s.length() >= 40 && s.length() % 4 == 0 && isBase64ish(s) && b64++ < 5) {
				info.findings.add("Possible embedded base64 blob (" + s.length() + " chars): "
						+ s.substring(0, 32) + "...");
			}
			if (low.contains("libnative") || low.contains("loadlibrary") || low.contains("dlopen")) {
				info.findings.add("Dynamic loading related string: " + s);
			}
		}
	}

	private static boolean isBase64ish(String s) {
		for (int i = 0; i < s.length(); i++) {
			char c = s.charAt(i);
			boolean ok = (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '+'
					|| c == '/' || c == '=' || c == '-';
			if (!ok) {
				return false;
			}
		}
		return true;
	}

	private static void extractStrings(byte[] data, ElfInfo info) {
		int min = 5;
		StringBuilder cur = new StringBuilder();
		for (byte b : data) {
			int c = b & 0xff;
			if (c >= 0x20 && c < 0x7f) {
				cur.append((char) c);
			} else {
				if (cur.length() >= min) {
					info.strings.add(cur.toString());
				}
				cur.setLength(0);
			}
		}
		if (cur.length() >= min) {
			info.strings.add(cur.toString());
		}
	}

	private static String[] readStrTab(byte[] data) {
		int count = 0;
		for (byte b : data) {
			if (b == 0) {
				count++;
			}
		}
		String[] out = new String[count + 1];
		int idx = 0;
		int start = 0;
		for (int i = 0; i < data.length; i++) {
			if (data[i] == 0) {
				out[idx++] = new String(data, start, i - start, StandardCharsets.US_ASCII);
				start = i + 1;
			}
		}
		return out;
	}

	private static String typeName(int t) {
		return switch (t) {
			case 0 -> "NONE";
			case 1 -> "REL (relocatable)";
			case 2 -> "EXEC (executable)";
			case 3 -> "DYN (shared object)";
			case 4 -> "CORE";
			default -> "0x" + Integer.toHexString(t);
		};
	}

	private static String machineName(int m) {
		return switch (m) {
			case 3 -> "x86";
			case 8 -> "MIPS";
			case 40 -> "ARM";
			case 62 -> "x86-64";
			case 183 -> "AArch64";
			case 243 -> "RISC-V";
			default -> "machine " + m;
		};
	}

	private static String segTypeName(long t) {
		return switch ((int) t) {
			case 0 -> "NULL";
			case 1 -> "LOAD";
			case 2 -> "DYNAMIC";
			case 3 -> "INTERP";
			case 4 -> "NOTE";
			case 6 -> "PHDR";
			case 1685382480 -> "GNU_EH_FRAME";
			case 1685382481 -> "GNU_STACK";
			case 1685382482 -> "GNU_RELRO";
			default -> "0x" + Long.toHexString(t);
		};
	}

	private static String secTypeName(long t) {
		return switch ((int) t) {
			case 0 -> "NULL";
			case 1 -> "PROGBITS";
			case 2 -> "SYMTAB";
			case 3 -> "STRTAB";
			case 4 -> "RELA";
			case 8 -> "NOBITS";
			case 9 -> "REL";
			case 11 -> "DYNSYM";
			case 14 -> "INIT_ARRAY";
			case 15 -> "FINI_ARRAY";
			case 16 -> "PREINIT_ARRAY";
			case 17 -> "GROUP";
			case 18 -> "SYMTAB_SHNDX";
			default -> "0x" + Long.toHexString(t);
		};
	}
}
