package com.jadxstudio.analysis.pairip;

import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;

/**
 * Google PLAY Integrity Protect ("PairIP" / pairipcore) detection and support mapping.
 *
 * <p>
 * PairIP keeps protected strings as blank static fields in the APK and fills them at runtime,
 * after an integrity/signature check through {@code com.pairip.SignatureCheck} and
 * {@code LicenseClient.checkLicense}. Heavy variants add a bytecode VM ({@code VMRunner}).
 *
 * <p>
 * This finds the PairIP classes/natives, the string fields that need runtime recovery, and
 * generates the Frida script + smali patch notes used to restore them.
 */
public class PairipAnalyzer {

	/** Classes that indicate PairIP. */
	private static final String[] CLASS_MARKERS = {
			"com.pairip.application", "com.pairip.SignatureCheck", "com.pairip.LicenseClient",
			"com.pairip.VMRunner", "com.pairip.util", "com.pairip.protect",
	};

	/** Native libraries used by PairIP. */
	private static final String[] LIB_MARKERS = {
			"libpairipcore.so", "libpairip.so", "libplayintegrity.so",
	};

	/** Methods that decide whether the app runs. */
	private static final String[] GATE_METHODS = {
			"com.pairip.LicenseClient.checkLicense", "com.pairip.SignatureCheck.verifyIntegrity",
			"com.pairip.SignatureCheck.verifySignatureMatches", "com.pairip.VMRunner.executeVM",
			"com.pairip.LicenseClient.getVersionCode",
	};

	public record ProtectedField(String cls, String field, String type, String note) {
	}

	private final List<String> notes = new ArrayList<>();
	private final List<ProtectedField> fields = new ArrayList<>();
	private final Set<String> pairipClasses = new LinkedHashSet<>();
	private final Set<String> nativeLibs = new LinkedHashSet<>();
	private final List<String> gateMethods = new ArrayList<>();
	private boolean detected;
	private boolean vmLayer;

	/**
	 * @param classNames   all class paths in the APK
	 * @param nativeLibs   native library paths
	 * @param classFields  blank static fields (class -> field -> type)
	 */
	public static PairipAnalyzer analyze(List<String> classNames, List<String> nativeLibs,
			List<String[]> classFields) {
		PairipAnalyzer a = new PairipAnalyzer();
		a.run(classNames, nativeLibs, classFields);
		return a;
	}

	private void run(List<String> classNames, List<String> libs, List<String[]> classFields) {
		for (String c : classNames) {
			for (String m : CLASS_MARKERS) {
				if (c.startsWith(m.replace('.', '/'))) {
					pairipClasses.add(c.replace('/', '.'));
					detected = true;
					if (m.endsWith("VMRunner")) {
						vmLayer = true;
					}
				}
			}
			for (String g : GATE_METHODS) {
				String owner = g.substring(0, g.lastIndexOf('.'));
				if (c.replace('/', '.').equals(owner)) {
					gateMethods.add(g);
				}
			}
		}
		for (String l : libs) {
			String low = l.toLowerCase(Locale.ROOT);
			for (String m : LIB_MARKERS) {
				if (low.endsWith(m)) {
					nativeLibs.add(l);
					detected = true;
				}
			}
		}
		// empty static fields inside (or near) protected classes are the PairIP strings
		if (classFields != null) {
			for (String[] row : classFields) {
				String cls = row[0];
				String field = row[1];
				String type = row[2];
				if (!type.toLowerCase(Locale.ROOT).contains("string")) {
					continue;
				}
				boolean protectedCls = cls.startsWith("com.pairip");
				if (protectedCls || looksRandomName(field)) {
					fields.add(new ProtectedField(cls, field, type,
							protectedCls ? "PairIP-owned" : "candidate (blank static String)"));
				}
			}
		}
		if (!detected) {
			notes.add("No PairIP classes or natives found.");
		}
		if (vmLayer) {
			notes.add("VMRunner detected: this app uses PairIP's bytecode VM. Removing the license check "
					+ "alone is not enough - the VM layer executes protected code.");
		}
		if (!fields.isEmpty()) {
			notes.add(fields.size() + " blank static String field(s) found: these are the values PairIP "
					+ "fills in at runtime (recover them with the generated Frida script).");
		}
	}

	/** PairIP names are typically long uppercase/random identifiers with no lowercase words. */
	private static boolean looksRandomName(String name) {
		if (name.length() < 6) {
			return false;
		}
		boolean upper = false;
		boolean lower = false;
		for (int i = 0; i < name.length(); i++) {
			char c = name.charAt(i);
			if (Character.isUpperCase(c)) {
				upper = true;
			} else if (Character.isLowerCase(c)) {
				lower = true;
			}
		}
		return upper && !lower;
	}

	public boolean isDetected() {
		return detected;
	}

	public boolean hasVmLayer() {
		return vmLayer;
	}

	public List<String> getNotes() {
		return notes;
	}

	public Set<String> getPairipClasses() {
		return pairipClasses;
	}

	public Set<String> getNativeLibs() {
		return nativeLibs;
	}

	public List<String> getGateMethods() {
		return gateMethods;
	}

	public List<ProtectedField> getFields() {
		return fields;
	}

	/** Frida script that dumps PairIP runtime strings (device-side step). */
	public String fridaScript() {
		return """
				// PairIP runtime string dumper
				// Usage (rooted device/emulator, matching frida-server version):
				//   frida -U -f <package> -l pairip-dump.js --no-pause
				// Writes: /data/local/tmp/pairip-dump.txt
				'use strict';
				const File = Java.use('java.io.File');
				const FileOutputStream = Java.use('java.io.FileOutputStream');
				const outPath = '/data/local/tmp/pairip-dump.txt';
				function emit(s) { send(s); }
				emit('[*] PairIP dumper attached');

				function dumpClass(clsName) {
				  try {
				    var cls = Java.use(clsName);
				    var out = [];
				    cls.class.getDeclaredFields().forEach(function (f) {
				      var mods = f.getModifiers();
				      var isStatic = (mods.valueOf() & 8) !== 0;
				      if (!isStatic) { return; }
				      try {
				        var v = cls[f.getName()].value;
				        if (v !== null && v !== undefined && String(v).length > 0) {
				          out.push(clsName + '->' + f.getName() + ' = ' + String(v));
				        }
				      } catch (e) {}
				    });
				    if (out.length) { out.forEach(emit); }
				  } catch (e) {}
				}

				Java.enumerateLoadedClasses({
				  onMatch: function (name) {
				    if (name.indexOf('com.pairip') === 0 || name.indexOf('pairip') !== -1) {
				      dumpClass(name);
				    }
				  },
				  onComplete: function () { emit('[*] done'); }
				});
				""";
	}

	/** Static patch notes for the license gate. */
	public String patchNotes() {
		StringBuilder sb = new StringBuilder();
		sb.append("PairIP removal (static, research use on apps you own)\n");
		sb.append("=================================================\n\n");
		if (gateMethods.isEmpty()) {
			sb.append("No gate method found in the class list.\n");
		}
		for (String g : gateMethods) {
			sb.append("Patch target: ").append(g).append("()\n");
		}
		sb.append("  1. Make LicenseClient.checkLicense(Context) return-void immediately.\n");
		sb.append("  2. Neutralise SignatureCheck.verifyIntegrity(Context) (signature/integrity).\n");
		sb.append("  3. Remove calls to com.pairip/* except the license stub.\n");
		if (vmLayer) {
			sb.append("  4. NOTE: VMRunner present - protected code is virtualised, so 1-3 will not ");
			sb.append("recover the protected logic.\n");
		}
		sb.append("\nPairIP string recovery (values for the blank fields listed above):\n");
		sb.append("  Run the generated Frida script on a device, then patch each field with the dumped ");
		sb.append("value\n  or map them into your own smali replacement class.\n");
		return sb.toString();
	}
}