package com.jadxstudio.analysis.nativecode;

import java.nio.file.Path;
import java.util.List;

/** Shared model for native (ELF) analysis results. */
public final class NativeModel {

	private NativeModel() {
	}

	/** One function discovered by a backend (or by ELF symbols). */
	public record Func(long addr, int size, String name, List<String> callees, String source) {
	}

	/** One disassembled instruction. */
	public record Insn(long addr, String bytes, String text, String comment) {
	}

	/** What each external backend can and cannot do. */
	public record Backends(String disassembler, String decompiler, List<String> notes) {
		public boolean hasDisassembler() {
			return disassembler != null && !disassembler.isBlank();
		}

		public boolean hasDecompiler() {
			return decompiler != null && !decompiler.isBlank();
		}
	}

	public static String hex(long v) {
		return "0x" + Long.toHexString(v);
	}

	public static String toolName(Path p) {
		return p == null ? "?" : p.getFileName().toString();
	}
}