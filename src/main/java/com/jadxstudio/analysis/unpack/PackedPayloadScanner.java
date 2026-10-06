package com.jadxstudio.analysis.unpack;

import java.io.IOException;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;

/**
 * Offline half of a packer/jiagu dumper: finds the encrypted/packed payloads inside an
 * archive so they can be inspected or extracted, and reports entropy as a hint.
 *
 * <p>
 * Note: the actual decryption of jiagu/Bangcle payloads happens in app memory at runtime.
 * That part needs a rooted device plus Frida - see {@link FridaScripts} for the scripts
 * this tool generates for that step.
 */
public class PackedPayloadScanner {

	public record Payload(String entry, long size, double entropy, String kind, String note) {
	}

	private static final byte[] DEX_MAGIC = { 'd', 'e', 'x', '\n', '0' };
	private static final byte[] ZIP_MAGIC = { 'P', 'K', 3, 4 };
	private static final byte[] ELF_MAGIC = { 0x7f, 'E', 'L', 'F' };

	/** well-known compressed / already-encoded formats: high entropy is normal for these */
	private static final java.util.Set<String> BENIGN_EXT = java.util.Set.of(
			"ttf", "otf", "png", "jpg", "jpeg", "webp", "gif", "ico", "mp3", "mp4", "m4a", "ogg", "wav",
			"flac", "avi", "mov", "pdf", "so", "dex", "jar", "zip", "gz", "bz2", "xz", "7z", "rar", "br",
			"webm", "woff", "woff2", "jpg_", "arsc");

	private static final String[] SUSPICIOUS_NAMES = {
			"classes0.jar", "classes.jar", "ijiami.dat", "libjiagu", "libDexHelper", "libexecmain",
			"libshell", "libsecexe", "libnativehelper", "libdexjni", "libdex2c", "protect.dat",
			"jiagu.dat", "shell.dat", "sec.dat", "packer.dat", "app_protect", "stub.dat",
	};

	private final List<Payload> payloads = new ArrayList<>();
	private final List<String> notes = new ArrayList<>();

	public static PackedPayloadScanner scan(Path apk) throws IOException {
		PackedPayloadScanner s = new PackedPayloadScanner();
		s.run(apk);
		return s;
	}

	private void run(Path apk) throws IOException {
		try (ZipFile zip = new ZipFile(apk.toFile())) {
			var entries = zip.entries();
			while (entries.hasMoreElements()) {
				ZipEntry e = entries.nextElement();
				if (e.isDirectory() || e.getSize() < 2048) {
					continue;
				}
				String name = e.getName();
				String low = name.toLowerCase(Locale.ROOT);
				boolean suspicious = false;
				for (String s : SUSPICIOUS_NAMES) {
					if (low.contains(s)) {
						suspicious = true;
						break;
					}
				}
				byte[] head = read(zip, e, 64);
				if (head == null) {
					continue;
				}
				boolean isDex = startsWith(head, DEX_MAGIC);
				boolean isZip = startsWith(head, ZIP_MAGIC);
				boolean isElf = startsWith(head, ELF_MAGIC);
				boolean inAssets = name.startsWith("assets/");

				// entropy from a bounded sample (keeps this fast on big payloads)
				byte[] sample = read(zip, e, 262144);
				double ent = entropy(sample);

				if (isDex) {
					payloads.add(new Payload(name, e.getSize(), ent, "DEX",
							"plain dex file" + (inAssets ? " hidden in assets" : "")));
				} else if (isZip) {
					payloads.add(new Payload(name, e.getSize(), ent, "ZIP/JAR",
							"nested archive (possible second-stage payload)"));
				} else if (suspicious) {
					String kind = isElf ? "ELF (packer lib)" : "blob";
					payloads.add(new Payload(name, e.getSize(), ent, kind,
							ent > 7.5 ? "known packer name and high entropy (likely encrypted)"
									: "known packer name"));
				} else if (inAssets && ent > 7.7 && e.getSize() > 32768 && !isBenign(low)) {
					payloads.add(new Payload(name, e.getSize(), ent, "encrypted blob",
							"asset with very high entropy - probable encrypted payload"));
				}
			}
		}
		if (payloads.isEmpty()) {
			notes.add("No obvious packed/encrypted payload found in this archive.");
		} else {
			notes.add(payloads.size() + " candidate payload(s). Entropy > 7.5 usually means encrypted.");
		}
	}

	private static boolean isBenign(String lowerName) {
		int dot = lowerName.lastIndexOf('.');
		if (dot < 0) {
			return false;
		}
		return BENIGN_EXT.contains(lowerName.substring(dot + 1));
	}

	private static byte[] read(ZipFile zip, ZipEntry e, int max) throws IOException {
		int n = (int) Math.min(e.getSize(), max);
		byte[] buf = new byte[n];
		try (var in = zip.getInputStream(e)) {
			int read = 0;
			while (read < n) {
				int r = in.read(buf, read, n - read);
				if (r < 0) {
					break;
				}
				read += r;
			}
			return buf;
		}
	}

	private static boolean startsWith(byte[] data, byte[] magic) {
		if (data.length < magic.length) {
			return false;
		}
		for (int i = 0; i < magic.length; i++) {
			if (data[i] != magic[i]) {
				return false;
			}
		}
		return true;
	}

	/** Shannon entropy in bits/byte (8.0 = fully random). */
	static double entropy(byte[] data) {
		if (data == null || data.length == 0) {
			return 0;
		}
		long[] counts = new long[256];
		for (byte b : data) {
			counts[b & 0xff]++;
		}
		double h = 0;
		double n = data.length;
		for (long c : counts) {
			if (c == 0) {
				continue;
			}
			double p = c / n;
			h -= p * (Math.log(p) / Math.log(2));
		}
		return h;
	}

	/** Extract a payload from the archive to disk. */
	public static void extract(Path apk, String entryName, Path out) throws IOException {
		try (ZipFile zip = new ZipFile(apk.toFile())) {
			ZipEntry e = zip.getEntry(entryName);
			if (e == null) {
				throw new IOException("entry not found: " + entryName);
			}
			if (out.getParent() != null) {
				java.nio.file.Files.createDirectories(out.getParent());
			}
			try (var in = zip.getInputStream(e)) {
				java.nio.file.Files.copy(in, out, java.nio.file.StandardCopyOption.REPLACE_EXISTING);
			}
		}
	}

	public List<Payload> getPayloads() {
		return payloads;
	}

	public List<String> getNotes() {
		return notes;
	}

	/** Device-side DEX dumper (Frida) for jiagu / DexHelper style packers. */
	public static String fridaDexDumpScript() {
		return """
				// Generic in-memory DEX dumper (jiagu / DexHelper / custom packers)
				// Usage: frida -U -f <package> -l dex-dump.js --no-pause
				// Output: /data/local/tmp/dump-<pid>/*.dex
				'use strict';
				const FS = Java.use('java.io.File');
				const FOS = Java.use('java.io.FileOutputStream');
				const Buf = Java.use('java.nio.ByteBuffer');

				const outDir = '/data/local/tmp/dump-' + Process.id;
				function ensureDir(p) { try { var f = FS.$new(p); if (!f.exists()) f.mkdirs(); } catch (e) {} }
				function saveDex(name, addr, size) {
				  try {
				    var buf = Buf.allocateDirect(java.lang.Integer.valueOf(size));
				    buf.put(0, addr, java.lang.Integer.valueOf(0), java.lang.Integer.valueOf(size));
				    arr = Java.array('byte', size);
				    for (var i = 0; i < size; i++) {
				      arr[i] = buf.get(java.lang.Integer.valueOf(i));
				    }
				    var f = FS.$new(outDir + '/' + name);
				    var os = FOS.$new(f);
				    os.write(arr);
				    os.flush(); os.close();
				    send('[*] dumped ' + name + ' (' + size + ' bytes) from ' + addr);
				  } catch (e) { send('[!] dump failed: ' + e); }
				}

				function isDex(addr) {
				  try {
				    var b = Memory.readByteArray(addr, 4);
				    return b[0] === 0x64 && b[1] === 0x65 && b[2] === 0x78 && b[3] === 0x0a;
				  } catch (e) { return false; }
				}

				// hook mmap so we see the unpacked dex as it is mapped
				var mmap = Module.findExportByName(null, 'mmap');
				if (mmap) {
				  Interceptor.attach(mmap, {
				    onLeave: function (ret) {
				      if (isDex(ret)) {
				        send('[*] mapped dex at ' + ret);
				        setTimeout(function () { saveDex('mapped-' + ret + '.dex', ret, 4 * 1024 * 1024); }, 1500);
				      }
				    }
				  });
				}

				// enumerate already loaded dex files after startup
				setTimeout(function () {
				  Java.perform(function () {
				    var DexFile = Java.use('dalvik.system.DexFile');
				    DexFile.loadDex.$ownMembers = DexFile.loadDex.$ownMembers;
				    try {
				      DexFile.loadDex.overload('java.lang.String', 'java.lang.String', 'int', 'java.lang.ClassLoader')
				        .implementation = function (src, out, opt, loader) {
				          var r = this.loadDex(src, out, opt, loader);
				          setTimeout(function () {
				            try {
				              var File = Java.use('java.io.File');
				              var f = File.$new(out);
				              if (f.exists()) { send('[+] dex: ' + out + ' size=' + f.length()); }
				            } catch (e) {}
				          }, 800);
				          return r;
				        };
				    } catch (e) { send('[!] loadDex hook: ' + e); }
				  });
				}, 1500);

				ensureDir(outDir);
				send('[*] dumper ready, waiting for unpacked dex...');
				""";
	}
}