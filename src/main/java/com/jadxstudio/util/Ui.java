package com.jadxstudio.util;

import javax.swing.BorderFactory;
import javax.swing.JComponent;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.SwingUtilities;
import java.awt.BorderLayout;
import java.awt.Component;
import java.awt.Dimension;
import java.awt.FlowLayout;
import java.awt.Font;
import java.util.function.Consumer;

public final class Ui {
	public static final Font MONO = new Font(Font.MONOSPACED, Font.PLAIN, 13);
	public static final Font MONO_BOLD = new Font(Font.MONOSPACED, Font.BOLD, 13);
	public static final Font TREE = new Font(Font.SANS_SERIF, Font.PLAIN, 13);
	public static final Font TREE_BOLD = new Font(Font.SANS_SERIF, Font.BOLD, 13);

	private Ui() {
	}

	public static void runOnEdt(Runnable r) {
		if (SwingUtilities.isEventDispatchThread()) {
			r.run();
		} else {
			SwingUtilities.invokeLater(r);
		}
	}

	public static void info(Component parent, String msg) {
		JOptionPane.showMessageDialog(parent, msg, "JADX Studio", JOptionPane.INFORMATION_MESSAGE);
	}

	public static void error(Component parent, String msg) {
		JOptionPane.showMessageDialog(parent, msg, "JADX Studio", JOptionPane.ERROR_MESSAGE);
	}

	public static void warn(Component parent, String msg) {
		JOptionPane.showMessageDialog(parent, msg, "JADX Studio", JOptionPane.WARNING_MESSAGE);
	}

	public static JScrollPane scroll(Component c) {
		JScrollPane sp = new JScrollPane(c);
		sp.setBorder(BorderFactory.createEmptyBorder());
		return sp;
	}

	public static JPanel hBox(Component... comps) {
		JPanel p = new JPanel(new FlowLayout(FlowLayout.LEFT, 6, 4));
		for (Component c : comps) {
			p.add(c);
		}
		return p;
	}

	public static JLabel label(String s) {
		return new JLabel(s);
	}

	public static JScrollPane textArea(java.awt.Container owner, JComponent comp) {
		JScrollPane sp = new JScrollPane(comp);
		sp.setPreferredSize(new Dimension(640, 400));
		return sp;
	}

	public static void whenDone(Component parent, String title, java.util.concurrent.Callable<String> task,
			Consumer<String> onDone) {
		new Thread(() -> {
			String result;
			try {
				result = task.call();
			} catch (Exception e) {
				final String err = e.getMessage() == null ? e.toString() : e.getMessage();
				runOnEdt(() -> error(parent, title + " failed:\n" + err));
				return;
			}
			final String res = result;
			runOnEdt(() -> onDone.accept(res));
		}, title).start();
	}
}
