package com.jadxstudio.gui;

import com.jadxstudio.core.Project;

import javax.swing.BorderFactory;
import javax.swing.JButton;
import javax.swing.JDialog;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTextArea;
import java.awt.BorderLayout;
import java.awt.Dimension;
import java.awt.FlowLayout;
import java.awt.Frame;

/** Shows log/errors produced by the deobfuscation / re-decompile workflow. */
public class DeobfuscationLogDialog extends JDialog {

	public DeobfuscationLogDialog(Frame owner, String title, String text) {
		super(owner, title, false);
		setSize(new Dimension(820, 480));
		setLocationRelativeTo(owner);
		JTextArea ta = new JTextArea(text);
		ta.setEditable(false);
		ta.setFont(com.jadxstudio.util.Ui.MONO);
		JPanel p = new JPanel(new BorderLayout());
		p.add(new JScrollPane(ta), BorderLayout.CENTER);
		JPanel b = new JPanel(new FlowLayout(FlowLayout.RIGHT));
		JButton close = new JButton("Close");
		close.addActionListener(e -> dispose());
		b.add(close);
		p.add(b, BorderLayout.SOUTH);
		p.setBorder(BorderFactory.createEmptyBorder(6, 6, 6, 6));
		setContentPane(p);
	}
}
