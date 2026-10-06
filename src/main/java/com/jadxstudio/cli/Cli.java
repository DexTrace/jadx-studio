package com.jadxstudio.cli;

import com.jadxstudio.core.ExportOptions;
import com.jadxstudio.core.Project;

import java.io.PrintStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.List;

/**
 * Batch command line decompiler.
 *
 * <pre>
 * Usage: jadx-studio [options] &lt;file ...&gt;
 *   -o, --output DIR    output folder (default: &lt;input&gt;_decompiled)
 *   -e, --export        export sources/resources after load
 *   --no-src            do not export sources
 *   --no-res            do not export resources
 *   --map FILE          apply deobfuscation mapping file
 *   -q, --quiet         less output
 *   --gui FILE          open the GUI instead
 *   -h, --help          this help
 * </pre>
 */
public final class Cli {

	private Cli() {
	}

	public static int run(String[] args) {
		Path output = null;
		boolean export = true;
		boolean sources = true;
		boolean resources = true;
		boolean quiet = false;
		Path mapping = null;
		List<Path> inputs = new ArrayList<>();

		for (int i = 0; i < args.length; i++) {
			String a = args[i];
			switch (a) {
				case "-h", "--help" -> {
					usage(System.out);
					return 0;
				}
				case "-o", "--output" -> {
					if (++i >= args.length) {
						System.err.println("missing value for " + a);
						return 2;
					}
					output = Paths.get(args[i]);
				}
				case "-e", "--export" -> export = true;
				case "--no-src" -> sources = false;
				case "--no-res" -> resources = false;
				case "-q", "--quiet" -> quiet = true;
				case "--map" -> {
					if (++i >= args.length) {
						System.err.println("missing value for --map");
						return 2;
					}
					mapping = Paths.get(args[i]);
				}
				case "--gui" -> {
					if (++i >= args.length) {
						System.err.println("missing value for --gui");
						return 2;
					}
					return com.jadxstudio.gui.Launcher.launch(new String[] { args[i] });
				}
				default -> {
					if (a.startsWith("-")) {
						System.err.println("unknown option: " + a);
						usage(System.err);
						return 2;
					}
					inputs.add(Paths.get(a));
				}
			}
		}

		if (inputs.isEmpty()) {
			usage(System.err);
			return 2;
		}

		int failed = 0;
		for (Path in : inputs) {
			if (!Files.isRegularFile(in)) {
				System.err.println("not a file: " + in);
				failed++;
				continue;
			}
			Path out = output != null ? output
					: in.toAbsolutePath().getParent().resolve(in.getFileName().toString() + "_decompiled");
			try {
				long t0 = System.currentTimeMillis();
				Project p = new Project();
				if (mapping != null) {
					p.setMappingPath(mapping);
				}
				p.load(in);
				p.setOutput(out);
				if (!quiet) {
					System.out.println("[*] loaded " + in.getFileName() + ": " + p.getSourceMap().size()
							+ " source files, " + p.getResourcePaths().size() + " resources, "
							+ p.getNativePaths().size() + " native libs");
				}
				if (export) {
					ExportOptions o = new ExportOptions();
					o.sources = sources;
					o.resources = resources;
					o.export = true;
					int n = p.export(o);
					long ms = System.currentTimeMillis() - t0;
					System.out.printf("[+] exported %d file(s) to %s (%d ms)%n", n, out, ms);
				}
				int issues = p.getIssueCount();
				if (issues > 0) {
					System.out.println("[!] decompiler reported " + issues
							+ " issue(s) - output is best effort, review carefully");
				}
			} catch (Exception e) {
				System.err.println("[-] failed on " + in + ": " + e);
				failed++;
			}
		}
		return failed == 0 ? 0 : 1;
	}

	private static void usage(PrintStream out) {
		out.println("""
				JADX Studio CLI - decompile APK/DEX/AAR/AAB/ZIP (best effort)

				Usage: jadx-studio [options] <file ...>
				  -o, --output DIR   output folder (default: <input>_decompiled)
				  -e, --export       export after load
				  --no-src           skip source export
				  --no-res           skip resource export
				  --map FILE         apply deobfuscation mapping (key=new per line)
				  --gui FILE         open GUI with file
				  -q, --quiet        less output
				  -h, --help         show this help

				Note: decompiled Java is reconstructed automatically and may be
				wrong or incomplete. Verify important findings against smali output.""");
	}
}
