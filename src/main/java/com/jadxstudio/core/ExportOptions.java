package com.jadxstudio.core;

/** Options for exporting decompiled output to a folder. */
public class ExportOptions {
	/** Write decompiled sources. */
	public boolean sources = true;
	/** Write decoded resources (manifest, res/, native libs, etc.). */
	public boolean resources = true;
	/** Actually write files to disk (false = dry run counting entries). */
	public boolean export = true;
}
