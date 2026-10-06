package com.jadxstudio.gui;

import com.jadxstudio.core.Project;

import javax.swing.SwingUtilities;
import javax.swing.UIManager;
import java.nio.file.Path;
import java.nio.file.Paths;

/** Launches the desktop GUI. */
public final class Launcher {

	private Launcher() {
	}

	public static int launch(String[] args) {
		// FlatLaf keeps the chrome looking modern and matches the editor theme
		try {
			boolean dark = com.jadxstudio.editor.Theme.current().mode()
					== com.jadxstudio.editor.Theme.Mode.DARK;
			UIManager.setLookAndFeel(dark ? "com.formdev.flatlaf.FlatDarkLaf"
					: "com.formdev.flatlaf.FlatLightLaf");
		} catch (Exception ignored) {
			try {
				UIManager.setLookAndFeel(UIManager.getSystemLookAndFeelClassName());
			} catch (Exception ignored2) {
			}
		}
		Path open = args != null && args.length > 0 ? Paths.get(args[0]) : null;
		SwingUtilities.invokeLater(() -> {
			MainWindow w = new MainWindow(new Project());
			w.setVisible(true);
			if (open != null) {
				w.loadFile(open);
			}
		});
		return 0;
	}
}
