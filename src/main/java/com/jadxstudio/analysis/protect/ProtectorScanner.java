package com.jadxstudio.analysis.protect;

import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;

/**
 * Detects commercial packers / protectors and "hidden code" setups such as
 * dex2c (code moved into native), jiagu, Legu, Bangcle, Ijiami, AppGuard, DexProtector.
 *
 * <p>
 * Everything here is cheap: it reads the DEX class index, resource/native names and the
 * already-extracted strings - it never decompiles, so it stays fast on huge APKs.
 */
public class ProtectorScanner {

	/** name fragment -> vendor */
	private static final String[][] LIB_SIGNATURES = {
			{ "libjiagu", "360 Jiagu (Qihoo)" },
			{ "libDexHelper", "DexHelper / Tencent" },
			{ "libshell", "Bangcle (SecNeo)" },
			{ "libsecexe", "Bangcle (SecNeo)" },
			{ "libsecmain", "Bangcle (SecNeo)" },
			{ "libDex2C", "dex2c (code moved to native)" },
			{ "libdex2c", "dex2c (code moved to native)" },
			{ "libdexjni", "dex2c / DexBridge style" },
			{ "libpagestore", "Tencent Legu" },
			{ "libx3g", "Tencent Legu" },
			{ "libsuperblock", "Tencent Legu" },
			{ "libshield", "DexProtector" },
			{ "libchaosvmp", "DexProtector / ChaosVMP" },
			{ "libnativehelper", "generic native helper (packing)" },
			{ "libexecmain", "Bangcle (SecNeo)" },
			{ "libnesec", "Bangcle (SecNeo)" },
			{ "libepic", "Ijiami" },
			{ "libwtecrsa", "Ijiami" },
			{ "libwtecdvmp", "Ijiami" },
			{ "libDexLoader", "generic dex loader" },
			{ "libnativeDex", "native dex loader" },
			{ "libtinker", "Tinker (hot patch, not packing)" },
	};

	private static final String[][] CLASS_SIGNATURES = {
			{ "com.stub.StubApp", "stub Application (360 Jiagu / generic packer)" },
			{ "com.stub.StubApplication", "stub Application (Bangcle / generic)" },
			{ "com.qihoo.util.StubApplication", "360 Jiagu stub Application" },
			{ "com.SecShell.SecApp", "Bangcle SecShell Application" },
			{ "com.secshell.", "Bangcle SecShell" },
			{ "com.tencent.StubShell", "Tencent Legu stub shell" },
			{ "com.tencent.bugly.", "Tencent Bugly / Legu" },
			{ "com.lody.", "generic packer runtime" },
			{ "com.ijiami.", "Ijiami" },
			{ "com.shell.", "generic packer runtime" },
			{ "com.nagain.", "Nagain / generic packer" },
			{ "com.chaosvmp", "DexProtector (ChaosVMP)" },
			{ "org.jindev", "appguard-ish stub" },
			{ "com.mars.", "Mars Xposed/packing hook" },
			{ "DexHelper", "DexHelper loader" },
			{ "NativeHelper", "native helper (packing)" },
			{ "ProxyApplication", "proxy Application (packer)" },
			{ "StubApplication", "stub Application (packer)" },
			{ "attachBaseContext", "packer entry point" },
	};

	/** strings that betray anti-analysis / packing */
	private static final String[][] STRING_SIGNATURES = {
			{ "/proc/self/maps", "anti-analysis: reads /proc/self/maps" },
			{ "/proc/self/status", "anti-analysis: reads /proc/self/status" },
			{ "/proc/self/cmdline", "anti-analysis: process inspection" },
			{ "TracerPid", "anti-debugger check" },
			{ "frida", "anti-instrumentation (Frida)" },
			{ "gum-js-loop", "anti-instrumentation (Frida)" },
			{ "xposed", "anti-hook (Xposed)" },
			{ "substrate", "anti-hook (CydiaSubstrate)" },
			{ "magisk", "root detection (Magisk)" },
			{ "supersu", "root detection (SuperSU)" },
			{ "ro.debuggable", "debug build check" },
			{ "classes.dex", "dex file manipulation" },
			{ "dalvik.system.DexClassLoader", "dynamic dex loading" },
			{ "InMemoryDexClassLoader", "in-memory dex loading (hide code)" },
			{ "DexFile.loadDex", "secondary dex loading" },
			{ "/data/data/", "app data access" },
			{ "JNI_OnLoad", "native init hook" },
	};

	public record Finding(String severity, String title, String detail) {
	}

	private final List<Finding> findings = new ArrayList<>();
	private final Map<String, Integer> scores = new TreeMap<>();
	private int confidence;

	public static ProtectorScanner scan(List<String> nativeLibs, List<String> classNames, String applicationClass,
			List<String> strings) {
		ProtectorScanner s = new ProtectorScanner();
		s.run(nativeLibs, classNames, applicationClass, strings);
		return s;
	}

	private void run(List<String> nativeLibs, List<String> classNames, String appClass, List<String> strings) {
		Set<String> matchedVendors = new LinkedHashSet<>();

		for (String lib : nativeLibs) {
			String low = lib.toLowerCase(Locale.ROOT);
			for (String[] sig : LIB_SIGNATURES) {
				if (low.contains(sig[0])) {
					matchedVendors.add(sig[1]);
					add(sig[0].startsWith("libdex2c") || sig[0].startsWith("libdexjni") ? "high" : "high",
							"Native packer library: " + lib, sig[1] + " - matched '" + sig[0] + "'");
					score(sig[1], 35);
				}
			}
		}

		if (appClass != null) {
			for (String[] sig : CLASS_SIGNATURES) {
				if (appClass.startsWith(sig[0]) || appClass.contains(sig[0])) {
					matchedVendors.add(sig[1]);
					add("high", "Application class is a packer stub: " + appClass, sig[1]);
					score(sig[1], 35);
				}
			}
		}

		for (String cls : classNames) {
			for (String[] sig : CLASS_SIGNATURES) {
				if (cls.contains(sig[0])) {
					matchedVendors.add(sig[1]);
					add("info", "Packer runtime class: " + cls, sig[1]);
					score(sig[1], 10);
					break;
				}
			}
		}

		if (strings != null) {
			Set<String> seen = new LinkedHashSet<>();
			for (String s : strings) {
				String low = s.toLowerCase(Locale.ROOT);
				for (String[] sig : STRING_SIGNATURES) {
					if (low.contains(sig[0].toLowerCase(Locale.ROOT))) {
						String key = sig[1];
						if (seen.add(key)) {
							boolean anti = low.contains("anti-") || sig[1].contains("root") || sig[1].contains("Frida")
									|| sig[1].contains("Xposed") || sig[1].contains("debug");
							add(anti ? "medium" : "info", key, "found string \"" + shorten(s) + "\"");
							score("environment", anti ? 5 : 2);
						}
					}
				}
			}
		}

		if (!matchedVendors.isEmpty()) {
			confidence = Math.min(99, confidence + 20);
			add("high", "Likely protected/packed app",
					"Detected: " + String.join(", ", matchedVendors)
							+ ". Some Java code is generated at runtime or lives inside native libraries.");
		} else if (!findings.isEmpty()) {
			add("info", "No known packer signature matched",
					"Only generic anti-analysis strings were found.");
		} else {
			add("info", "No packing/anti-analysis indicators found", "The app looks unprotected.");
		}
	}

	private void add(String severity, String title, String detail) {
		findings.add(new Finding(severity, title, detail));
	}

	private void score(String key, int points) {
		scores.merge(key, points, Integer::sum);
		confidence = Math.min(99, confidence + points / 2);
	}

	private static String shorten(String s) {
		return s.length() > 60 ? s.substring(0, 60) + "..." : s;
	}

	public List<Finding> getFindings() {
		return findings;
	}

	public Map<String, Integer> getScores() {
		return scores;
	}

	public int getConfidence() {
		return confidence;
	}

	public boolean isProtected() {
		return confidence >= 35;
	}
}