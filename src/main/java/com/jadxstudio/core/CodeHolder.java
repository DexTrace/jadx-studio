package com.jadxstudio.core;

import java.util.List;

/** Holds decompiled (or disassembled) text plus any reported issues. */
public class CodeHolder {
	public final String text;
	public final List<String> errors;

	public CodeHolder(String text, List<String> errors) {
		this.text = text == null ? "" : text;
		this.errors = errors;
	}

	public boolean hasErrors() {
		return errors != null && !errors.isEmpty();
	}
}
