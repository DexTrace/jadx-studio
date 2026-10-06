package com.jadxstudio.analysis.so;

/** One ELF symbol entry. */
public class SymbolInfo {
	public final String name;
	public final long value;
	public final long size;
	public final int bind;
	public final int type;
	public final boolean imported;

	public SymbolInfo(String name, long value, long size, int bind, int type, boolean imported) {
		this.name = name;
		this.value = value;
		this.size = size;
		this.bind = bind;
		this.type = type;
		this.imported = imported;
	}

	@Override
	public String toString() {
		return name + (imported ? "  [import]" : "  [export]");
	}
}
