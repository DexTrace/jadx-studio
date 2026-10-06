package com.jadxstudio.editor;

/**
 * Small multi-language tokenizer used for syntax highlighting:
 * Java, C pseudocode, native assembly / smali, and XML.
 */
public final class JavaTokenizer {

	public static final int PLAIN = 0;
	public static final int KW = 1;
	public static final int STR = 2;
	public static final int CHAR = 3;
	public static final int CMT = 4;
	public static final int NUM = 5;
	public static final int ANN = 6;
	public static final int TYPE = 7;
	public static final int TPL = 8;
	public static final int PRE = 9; // C preprocessor / asm directives / xml tags
	public static final int ATTR = 10; // xml attributes
	public static final int DESC = 11; // Lcom/x/Y; type descriptors
	public static final int REG = 12; // registers (v0, r0, x1, sp)
	public static final int LABEL = 13; // asm labels / branch targets

	public enum Lang {
		JAVA, C, ASM, SMALI, XML, TEXT
	}

	private static final java.util.Set<String> KEYWORDS = java.util.Set.of("package", "import", "class", "interface", "enum", "extends", "implements", "new", "return", "if", "else", "for", "while", "do", "switch", "case", "break", "continue", "try", "catch", "finally", "throw", "throws", "static", "final", "public", "private", "protected", "abstract", "synchronized", "volatile", "transient", "native", "this", "super", "null", "true", "false", "void", "instanceof", "default", "var", "record", "sealed", "permits", "yield", "assert", "const", "goto", "strictfp");

	private static final java.util.Set<String> C_KEYWORDS = java.util.Set.of("auto", "break", "case", "char", "const", "continue", "default", "do", "double", "else", "enum", "extern", "float", "for", "goto", "if", "inline", "int", "long", "register", "restrict", "return", "short", "signed", "sizeof", "static", "struct", "switch", "typedef", "union", "unsigned", "void", "volatile", "while", "bool", "true", "false", "NULL", "size_t", "uint8_t", "uint16_t", "uint32_t", "uint64_t", "int8_t", "int16_t", "int32_t", "int64_t", "undefined", "code", "param", "local", "stack", "basicblock", "function", "address", "switchop");

	private static final java.util.Set<String> C_TYPES = java.util.Set.of(
			"byte", "char", "double", "float", "int", "long", "short", "void", "uint", "ulong", "ushort",
			"u_int", "undefined", "code", "pointer", "string", "wchar_t");

	private static final java.util.Set<String> ASM_MNEMONICS = java.util.Set.of("mov", "movs", "movz", "movk", "mvn", "add", "adds", "sub", "subs", "mul", "muls", "div", "udiv", "sdiv", "and", "ands", "orr", "eor", "lsl", "lsr", "asr", "ror", "cmp", "cmn", "tst", "cmpz", "cbnz", "cbz", "b", "bl", "blx", "bx", "br", "bxj", "pop", "push", "ldr", "ldrb", "ldrh", "ldrsb", "ldrsh", "ldrsw", "str", "strb", "strh", "stp", "ldp", "stur", "ldur", "swp", "ldxr", "stxr", "mrs", "msr", "svc", "svc0", "nop", "wfi", "wfe", "sev", "isb", "dsb", "dmb", "ret", "eret", "call", "tail", "int", "jmp", "je", "jne", "jae", "jb", "ja", "jl", "jg", "jle", "jge", "test", "inc", "dec", "neg", "not", "adr", "adrp", "bne", "blt", "bgt", "ble", "bge", "tbz", "tbnz", "hlt", "udf");

	private static final java.util.Set<String> SMALI_MNEMONICS = java.util.Set.of("move", "move-result", "move-result-wide", "move-result-object", "move-exception", "return", "return-void", "return-wide", "return-object", "const", "const-string", "const-class", "const/4", "const/16", "const-wide", "const/high16", "invoke-virtual", "invoke-super", "invoke-direct", "invoke-static", "invoke-interface", "invoke-virtual/range", "new-instance", "new-array", "check-cast", "instance-of", "array-length", "throw", "goto", "goto/16", "if-eq", "if-ne", "if-lt", "if-ge", "if-gt", "if-le", "if-eqz", "if-nez", "aget", "aput", "iget", "iput", "sget", "sput", "sget-wide", "sput-wide", "monitor-enter", "monitor-exit", "packed-switch", "sparse-switch", "fill-array-data", "add-int", "sub-int", "mul-int", "div-int", "rem-int", "and-int", "or-int", "xor-int", "shl-int", "shr-int", "ushr-int", "add-long", "cmp-long", "int-to-long", "long-to-int", "int-to-float", "float-to-int", "double-to-int", "neg-int", "not-int", "double", "float", "long");

	private JavaTokenizer() {
	}

	/** Tokens as {kind, absoluteStart, absoluteEnd}. Only non-PLAIN tokens are returned. */
	public static java.util.List<int[]> tokenize(String text, int base, Lang lang) {
		java.util.List<int[]> out = new java.util.ArrayList<>();
		if (lang == null || lang == Lang.TEXT) {
			return out;
		}
		if (lang == Lang.XML) {
			tokenizeXml(text, base, out);
			return out;
		}
		if (lang == Lang.ASM || lang == Lang.SMALI) {
			tokenizeAsm(text, base, out, lang == Lang.SMALI);
			return out;
		}
		tokenizeCLike(text, base, out, lang == Lang.C);
		return out;
	}

	// ------------------------------------------------------------ C / Java

	private static void tokenizeCLike(String text, int base, java.util.List<int[]> out, boolean cMode) {
		int n = text.length();
		int i = 0;
		while (i < n) {
			char c = text.charAt(i);
			if (c == '/' && i + 1 < n && text.charAt(i + 1) == '/') {
				int e = lineEnd(text, i);
				out.add(new int[] { CMT, base + i, base + e });
				i = e;
			} else if (c == '/' && i + 1 < n && text.charAt(i + 1) == '*') {
				int e = text.indexOf("*/", i + 2);
				e = e < 0 ? n : e + 2;
				out.add(new int[] { CMT, base + i, base + e });
				i = e;
			} else if (c == '#' && cMode) {
				int e = lineEnd(text, i);
				out.add(new int[] { PRE, base + i, base + e });
				i = e;
			} else if (c == '"' && i + 2 < n && text.charAt(i + 1) == '"' && text.charAt(i + 2) == '"') {
				int e = text.indexOf("\"\"\"", i + 3);
				e = e < 0 ? n : e + 3;
				out.add(new int[] { STR, base + i, base + e });
				i = e;
			} else if (c == '"') {
				int e = scanString(text, i);
				out.add(new int[] { STR, base + i, base + e });
				i = e;
			} else if (c == '\'') {
				int e = i + 1;
				if (e < n && text.charAt(e) == '\\') {
					e += 2;
				} else {
					e += 1;
				}
				if (e < n && text.charAt(e) == '\'') {
					e++;
				}
				out.add(new int[] { CHAR, base + i, base + e });
				i = e;
			} else if (c == '@') {
				int e = i + 1;
				while (e < n && (Character.isJavaIdentifierPart(text.charAt(e)) || text.charAt(e) == '.')) {
					e++;
				}
				if (e > i + 1) {
					out.add(new int[] { ANN, base + i, base + e });
					i = e;
				} else {
					i++;
				}
			} else if (Character.isDigit(c) || (c == '.' && i + 1 < n && Character.isDigit(text.charAt(i + 1)))) {
				int e = i;
				while (e < n && (Character.isLetterOrDigit(text.charAt(e)) || text.charAt(e) == '.'
						|| text.charAt(e) == '_' || text.charAt(e) == 'x' || text.charAt(e) == 'X')) {
					e++;
				}
				out.add(new int[] { NUM, base + i, base + e });
				i = e;
			} else if (Character.isJavaIdentifierStart(c)) {
				int e = i;
				while (e < n && (Character.isJavaIdentifierPart(text.charAt(e)) || text.charAt(e) == '$')) {
					e++;
				}
				String word = text.substring(i, e);
				int kind = PLAIN;
				if (KEYWORDS.contains(word)) {
					kind = KW;
				} else if (cMode && C_KEYWORDS.contains(word)) {
					kind = KW;
				} else if (cMode && C_TYPES.contains(word)) {
					kind = TYPE;
				} else if (!word.isEmpty() && Character.isUpperCase(word.charAt(0))) {
					kind = TYPE;
				}
				if (kind != PLAIN) {
					out.add(new int[] { kind, base + i, base + e });
				}
				i = e;
			} else {
				i++;
			}
		}
	}

	// ------------------------------------------------------------ asm/smali

	private static void tokenizeAsm(String text, int base, java.util.List<int[]> out, boolean smali) {
		int n = text.length();
		int i = 0;
		while (i < n) {
			char c = text.charAt(i);
			if (c == '#' || (c == '/' && i + 1 < n && text.charAt(i + 1) == '/')) {
				int e = lineEnd(text, i);
				out.add(new int[] { CMT, base + i, base + e });
				i = e;
			} else if (c == '"') {
				int e = scanString(text, i);
				out.add(new int[] { STR, base + i, base + e });
				i = e;
			} else if (c == '\'') {
				int e = scanString(text, i, '\'');
				out.add(new int[] { STR, base + i, base + e });
				i = e;
			} else if (c == 'L' && i + 1 < n && (text.charAt(i + 1) == '/' || text.charAt(i + 1) == '[')) {
				// type descriptor like Lcom/x/Y; or [I
				int e = i + 1;
				while (e < n && (text.charAt(e) != ';' && text.charAt(e) != '\n')) {
					e++;
				}
				if (e < n && text.charAt(e) == ';') {
					e++;
				}
				out.add(new int[] { DESC, base + i, base + e });
				i = e;
			} else if (c == '.') {
				// directive (.class .method .field ...) or label
				int e = i;
				while (e < n && (Character.isJavaIdentifierPart(text.charAt(e)) || text.charAt(e) == '.'
						|| text.charAt(e) == '-')) {
					e++;
				}
				out.add(new int[] { PRE, base + i, base + e });
				i = e;
			} else if (c == ':') {
				out.add(new int[] { LABEL, base + i, base + i + 1 });
				i++;
			} else if (Character.isDigit(c) || (c == '-' && i + 1 < n && Character.isDigit(text.charAt(i + 1)))) {
				int e = i;
				if (text.charAt(e) == '-') {
					e++;
				}
				while (e < n && (Character.isLetterOrDigit(text.charAt(e)) || text.charAt(e) == 'x')) {
					e++;
				}
				out.add(new int[] { NUM, base + i, base + e });
				i = e;
			} else if (Character.isJavaIdentifierStart(c)) {
				int e = i;
				while (e < n && (Character.isJavaIdentifierPart(text.charAt(e)) || text.charAt(e) == '_'
						|| text.charAt(e) == '-' || text.charAt(e) == '$')) {
					e++;
				}
				String word = text.substring(i, e);
				boolean atLineStart = isWordStart(text, i);
				int kind = PLAIN;
				if (atLineStart && (ASM_MNEMONICS.contains(word) || SMALI_MNEMONICS.contains(word))) {
					kind = KW;
				} else if (atLineStart) {
					kind = LABEL;
				} else if (word.matches("v\\d+|p\\d+") || word.matches("[rxs]\\d+")
						|| word.matches("w\\d+") || word.equals("sp") || word.equals("lr")
						|| word.equals("pc") || word.equals("fp")) {
					kind = REG;
				} else if (!word.isEmpty() && Character.isUpperCase(word.charAt(0))) {
					kind = TYPE;
				}
				if (kind != PLAIN) {
					out.add(new int[] { kind, base + i, base + e });
				}
				i = e;
			} else {
				i++;
			}
		}
	}

	private static boolean isWordStart(String text, int i) {
		for (int j = i - 1; j >= 0; j--) {
			char c = text.charAt(j);
			if (c == ' ' || c == '\t') {
				continue;
			}
			return c == '\n' || j == 0 || text.charAt(j - 1) == '\n';
		}
		return true;
	}

	// ------------------------------------------------------------------ XML

	private static void tokenizeXml(String text, int base, java.util.List<int[]> out) {
		int n = text.length();
		int i = 0;
		while (i < n) {
			char c = text.charAt(i);
			if (text.startsWith("<!--", i)) {
				int e = text.indexOf("-->", i);
				e = e < 0 ? n : e + 3;
				out.add(new int[] { CMT, base + i, base + e });
				i = e;
			} else if (text.startsWith("<?", i)) {
				int e = text.indexOf("?>", i);
				e = e < 0 ? n : e + 2;
				out.add(new int[] { PRE, base + i, base + e });
				i = e;
			} else if (c == '<') {
				int e = i + 1;
				while (e < n && text.charAt(e) != '>' && text.charAt(e) != '\n') {
					e++;
				}
				out.add(new int[] { PRE, base + i, base + Math.min(e + 1, n) });
				i = Math.min(e + 1, n);
			} else if (c == '"') {
				int e = scanString(text, i);
				out.add(new int[] { STR, base + i, base + e });
				i = e;
			} else if (Character.isJavaIdentifierStart(c) || c == '_') {
				int e = i;
				while (e < n && (Character.isJavaIdentifierPart(text.charAt(e)) || text.charAt(e) == ':'
						|| text.charAt(e) == '.' || text.charAt(e) == '-')) {
					e++;
				}
				out.add(new int[] { ATTR, base + i, base + e });
				i = e;
			} else {
				i++;
			}
		}
	}

	// ---------------------------------------------------------------- utils

	private static int lineEnd(String text, int from) {
		int e = text.indexOf('\n', from);
		return e < 0 ? text.length() : e;
	}

	private static int scanString(String text, int quoteAt) {
		return scanString(text, quoteAt, '"');
	}

	private static int scanString(String text, int quoteAt, char quote) {
		int n = text.length();
		int i = quoteAt + 1;
		while (i < n) {
			char c = text.charAt(i);
			if (c == '\\') {
				i += 2;
				continue;
			}
			if (c == quote) {
				return i + 1;
			}
			if (c == '\n' && quote == '"') {
				return i;
			}
			i++;
		}
		return n;
	}
}