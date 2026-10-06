// Ghidra headless post-script: decompile every function of the loaded program to C
// pseudocode and dump a function index (used by JADX Studio native analysis).
//
// @category JADXStudio
// @keybinding
// @menupath
// @toolbar

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileOptions;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.util.task.ConsoleTaskMonitor;

import java.io.File;
import java.io.FileOutputStream;
import java.io.OutputStreamWriter;
import java.io.PrintWriter;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

public class DecompileAll extends GhidraScript {

	@Override
	public void run() throws Exception {
		String[] scriptArgs = getScriptArgs();
		File outDir = new File(scriptArgs.length > 0 ? scriptArgs[0] : "jadxstudio-ghidra");
		File pcDir = new File(outDir, "pseudocode");
		pcDir.mkdirs();

		PrintWriter meta = new PrintWriter(new OutputStreamWriter(
				new FileOutputStream(new File(outDir, "functions.tsv")), StandardCharsets.UTF_8));
		PrintWriter info = new PrintWriter(new OutputStreamWriter(
				new FileOutputStream(new File(outDir, "program.txt")), StandardCharsets.UTF_8));
		try {
			DecompInterface decomp = new DecompInterface();
			decomp.setOptions(new DecompileOptions());
			decomp.openProgram(currentProgram);

			info.println("name=" + currentProgram.getName());
			info.println("language=" + currentProgram.getLanguageID());
			info.println("compilerSpec=" + currentProgram.getCompilerSpec().getCompilerSpecID());
			info.println("imageBase=" + currentProgram.getImageBase());
			info.println("md5=" + currentProgram.getExecutableMD5());

			meta.println("address\telfAddress\tsize\tname\tcalls\tcallsAddrs");
			long imageBase = currentProgram.getImageBase().getOffset();
			List<String> failed = new ArrayList<>();

			FunctionIterator funcs = currentProgram.getFunctionManager().getFunctions(true);
			int done = 0;
			while (funcs.hasNext() && !monitor.isCancelled()) {
				Function f = funcs.next();
				String c = "";
				try {
					DecompileResults res = decomp.decompileFunction(f, 180, new ConsoleTaskMonitor());
					if (res != null && res.decompileCompleted() && res.getDecompiledFunction() != null) {
						c = res.getDecompiledFunction().getC();
					} else {
						failed.add(f.getName() + " @ " + f.getEntryPoint());
					}
				} catch (Exception e) {
					failed.add(f.getName() + " @ " + f.getEntryPoint() + ": " + e);
				}
				String safe = f.getName().replaceAll("[^A-Za-z0-9_.]", "_");
				String fileName = f.getEntryPoint().getOffset() + "_" + safe + ".c";
				try (PrintWriter pw = new PrintWriter(new OutputStreamWriter(
						new FileOutputStream(new File(pcDir, fileName)), StandardCharsets.UTF_8))) {
					pw.print(c);
				}
				StringBuilder names = new StringBuilder();
				StringBuilder addrs = new StringBuilder();
				for (Function callee : f.getCalledFunctions(monitor)) {
					names.append(callee.getName()).append(';');
					addrs.append(callee.getEntryPoint().getOffset()).append(';');
				}
				long ghidraAddr = f.getEntryPoint().getOffset();
				// ELF-relative address (image base of the shared object is 0 in ELF terms),
				// so this matches radare2 / our own ELF parser
				String elfAddr = String.valueOf(ghidraAddr - imageBase);
				meta.println(ghidraAddr + "\t" + elfAddr + "\t" + f.getBody().getNumAddresses() + "\t"
						+ f.getName() + "\t" + names + "\t" + addrs);
				done++;
				if (done % 25 == 0) {
					meta.flush();
					print("decompiled " + done + " functions...");
				}
			}
			decomp.dispose();
			meta.flush();
			info.println("functions=" + done);
			info.println("failed=" + failed.size());
			for (String s : failed) {
				info.println("FAILED " + s);
			}
		} finally {
			meta.close();
			info.close();
		}
		print("JADX Studio: native decompilation finished -> " + outDir.getAbsolutePath());
	}
}