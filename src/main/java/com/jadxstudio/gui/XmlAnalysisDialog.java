package com.jadxstudio.gui;

import com.jadxstudio.analysis.xml.AxmlDoc;
import com.jadxstudio.analysis.xml.XmlAnalyzer;

import javax.swing.BorderFactory;
import javax.swing.JButton;
import javax.swing.JDialog;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTabbedPane;
import javax.swing.JTextArea;
import java.awt.BorderLayout;
import java.awt.Dimension;
import java.awt.FlowLayout;
import java.awt.Frame;
import java.nio.file.Path;

/**
 * Android binary XML analysis window: decoded XML, security findings,
 * permission usage and component inventory.
 */
public class XmlAnalysisDialog extends JDialog {

	public XmlAnalysisDialog(Frame owner, Path xmlPath) {
		super(owner, "XML Analysis - " + xmlPath.getFileName(), false);
		setSize(new Dimension(1000, 640));
		setLocationRelativeTo(owner);

		AxmlDoc doc;
		try {
			doc = XmlAnalyzer.analyze(xmlPath);
		} catch (Exception e) {
			doc = new AxmlDoc();
			doc.findings.add("Analysis failed: " + e);
		}

		JTabbedPane tabs = new JTabbedPane();
		tabs.addTab("Decoded XML", new JScrollPane(textArea(doc.xml)));
		tabs.addTab("Findings", new JScrollPane(textArea(doc.findingsText())));
		tabs.addTab("Attributes", new JScrollPane(textArea(doc.attributesText())));

		JPanel p = new JPanel(new BorderLayout());
		p.add(tabs, BorderLayout.CENTER);
		JPanel bottom = new JPanel(new FlowLayout(FlowLayout.RIGHT));
		JButton close = new JButton("Close");
		close.addActionListener(e -> dispose());
		bottom.add(close);
		p.add(bottom, BorderLayout.SOUTH);
		p.setBorder(BorderFactory.createEmptyBorder(6, 6, 6, 6));
		setContentPane(p);
	}

	private static JTextArea textArea(String s) {
		JTextArea ta = new JTextArea(s);
		ta.setEditable(false);
		ta.setFont(com.jadxstudio.util.Ui.MONO);
		ta.setCaretPosition(0);
		return ta;
	}
}
