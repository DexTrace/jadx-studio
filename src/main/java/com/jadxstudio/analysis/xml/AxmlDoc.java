package com.jadxstudio.analysis.xml;

import java.util.ArrayList;
import java.util.List;

/** Result of XML analysis: decoded document + findings + attribute inventory. */
public class AxmlDoc {
	public String xml = "";
	public final List<String> findings = new ArrayList<>();
	public final List<String> attributes = new ArrayList<>();

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

	public String attributesText() {
		if (attributes.isEmpty()) {
			return "(no attributes recorded)";
		}
		StringBuilder sb = new StringBuilder();
		for (String a : attributes) {
			sb.append(a).append('\n');
		}
		return sb.toString();
	}
}
