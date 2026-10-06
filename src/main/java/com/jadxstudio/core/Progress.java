package com.jadxstudio.core;

/** Progress report for long-running work (percentage + phase text). */
public record Progress(int percent, String message) {

	public static Progress of(int pct, String msg) {
		return new Progress(Math.max(0, Math.min(100, pct)), msg);
	}
}