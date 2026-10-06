package com.jadxstudio.gui;

import javax.swing.JButton;
import javax.swing.JDialog;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTextArea;
import java.awt.BorderLayout;
import java.awt.Dimension;
import java.awt.FlowLayout;
import java.awt.Frame;

/** About / disclaimer dialog. */
public class AboutDialog extends JDialog {

	public AboutDialog(Frame owner) {
		super(owner, "About JADX Studio", true);
		setSize(new Dimension(620, 400));
		setLocationRelativeTo(owner);

		JTextArea ta = new JTextArea();
		ta.setEditable(false);
		ta.setFont(com.jadxstudio.util.Ui.MONO);
		ta.setLineWrap(true);
		ta.setWrapStyleWord(true);
		ta.setText("""
				JADX Studio — APK / DEX / AAR / AAB decompiler GUI + CLI

				Deepest decompilation, resource decoding, navigation, editing and
				analysis are powered by the jadx engine (https://github.com/skylot/jadx)
				used as a library.

				EXPERIMENTAL TOOL - BEST EFFORT ONLY
				- Decompiled Java is reconstructed from Dalvik bytecode and may be
				  wrong, incomplete, or fail to compile. When in doubt, check the
				  Smali view (Split view) which mirrors the actual bytecode.
				- Comments like /* JADX: ... */ mark known decompiler limitations.
				- Always verify findings before relying on them.

				Additional features in this build:
				- Split Java / Smali editor with synchronized navigation
				- In-editor code modification and export of edits
				- Deobfuscation workflow (rename + mapping save/load)
				- ELF .so native library analysis
				- Android binary XML analysis + permission/taint heuristics
				""");
		JPanel p = new JPanel(new BorderLayout());
		p.add(new JScrollPane(ta), BorderLayout.CENTER);
		JPanel b = new JPanel(new FlowLayout(FlowLayout.RIGHT));
		JButton ok = new JButton("Close");
		ok.addActionListener(e -> dispose());
		b.add(ok);
		p.add(b, BorderLayout.SOUTH);
		setContentPane(p);
	}
}
