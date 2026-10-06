package com.jadxstudio;

import com.jadxstudio.cli.Cli;
import com.jadxstudio.gui.Launcher;

/** Entry point: CLI when arguments are given, GUI otherwise. */
public final class Main {

	private Main() {
	}

	public static void main(String[] args) {
		if (System.getProperty("org.slf4j.simpleLogger.defaultLogLevel") == null) {
			boolean quiet = false;
			for (String a : args) {
				if (a.equals("-q") || a.equals("--quiet")) {
					quiet = true;
					break;
				}
			}
			System.setProperty("org.slf4j.simpleLogger.defaultLogLevel", quiet ? "error" : "warn");
		}
		if (args.length == 0) {
			Launcher.launch(new String[0]);
			return;
		}
		if (args.length == 1 && (args[0].equals("--gui") || args[0].equals("-g"))) {
			Launcher.launch(new String[0]);
			return;
		}
		int rc = Cli.run(args);
		if (rc != 0) {
			System.exit(rc);
		}
	}
}
