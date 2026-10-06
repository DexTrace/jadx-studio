package com.jadxstudio.gui;

import com.jadxstudio.analysis.flutter.FlutterAnalyzer;
import com.jadxstudio.core.Project;

import javax.swing.BorderFactory;
import javax.swing.JButton;
import javax.swing.JDialog;
import javax.swing.JFileChooser;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JSplitPane;
import javax.swing.JTabbedPane;
import javax.swing.JTextArea;
import javax.swing.JTree;
import javax.swing.SwingWorker;
import javax.swing.tree.DefaultMutableTreeNode;
import java.awt.BorderLayout;
import java.awt.Dimension;
import java.awt.FlowLayout;
import java.awt.Frame;
import java.io.File;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Flutter / Dart library window: snapshot info, versions and the Dart symbol table
 * (libraries, classes, functions). Runs in the background - the UI stays responsive.
 */
public class FlutterDialog extends JDialog {

	private final Project project;
	private final JTextArea infoArea = new JTextArea();
	private final JTextArea libArea = new JTextArea();
	private final JTextArea classArea = new JTextArea();
	private final JTextArea funcArea = new JTextArea();
	private final JTree tree = new JTree(new DefaultMutableTreeNode("select a Flutter library..."));
	private final JLabel status = new JLabel(" ");
	private final JButton export = new JButton("Export symbols to file...");

	private FlutterAnalyzer analyzer;

	public FlutterDialog(Frame owner, Project project) {
		super(owner, "Flutter / Dart analysis", false);
		this.project = project;
		setSize(new Dimension(1200, 820));
		setLocationRelativeTo(owner);

		for (JTextArea a : List.of(infoArea, libArea, classArea, funcArea)) {
			a.setEditable(false);
			a.setFont(new java.awt.Font(java.awt.Font.MONOSPACED, java.awt.Font.BOLD, 13));
		}
		tree.setFont(com.jadxstudio.util.Ui.TREE);
		tree.setBackground(com.jadxstudio.editor.Theme.current().background());
		tree.setForeground(com.jadxstudio.editor.Theme.current().foreground());

		JPanel top = new JPanel(new FlowLayout(FlowLayout.LEFT, 6, 4));
		top.add(new JLabel("Flutter library:"));
		JButton reload = new JButton("Reload");
		reload.addActionListener(e -> load());
		top.add(reload);
		export.addActionListener(e -> exportSymbols());
		export.setEnabled(false);
		top.add(export);
		JButton pick = new JButton("Pick .so file...");
		pick.addActionListener(e -> pickFile());
		top.add(pick);

		JScrollPane treeScroll = new JScrollPane(tree);
		treeScroll.setBorder(BorderFactory.createTitledBorder("Flutter libraries in this APK"));
		treeScroll.setPreferredSize(new Dimension(330, 100));

		JTabbedPane tabs = new JTabbedPane();
		tabs.addTab("Snapshot info", new JScrollPane(infoArea));
		tabs.addTab("Dart libraries (" + 0 + ")", new JScrollPane(libArea));
		tabs.addTab("Dart classes", new JScrollPane(classArea));
		tabs.addTab("Dart functions", new JScrollPane(funcArea));

		JSplitPane split = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT, treeScroll, tabs);
		split.setDividerLocation(340);

		JPanel p = new JPanel(new BorderLayout());
		p.add(top, BorderLayout.NORTH);
		p.add(split, BorderLayout.CENTER);
		JPanel bottom = new JPanel(new BorderLayout());
		bottom.add(status, BorderLayout.CENTER);
		bottom.setBorder(BorderFactory.createEmptyBorder(3, 8, 5, 8));
		p.add(bottom, BorderLayout.SOUTH);
		setContentPane(p);

		load();
	}

	private void load() {
		DefaultMutableTreeNode root = new DefaultMutableTreeNode("Flutter libraries");
		boolean any = false;
		for (String lib : project.getNativePaths()) {
			String low = lib.toLowerCase();
			if (low.contains("libapp.so") || low.contains("libflutter.so") || low.contains("libmain.so")
					|| low.endsWith(".so") && (low.contains("flutter") || low.contains("app"))) {
				root.add(new DefaultMutableTreeNode(lib));
				any = true;
			}
		}
		tree.setModel(new javax.swing.tree.DefaultTreeModel(root));
		for (int i = 0; i < tree.getRowCount(); i++) {
			tree.expandRow(i);
		}
		tree.addTreeSelectionListener(e -> {
			Object n = tree.getLastSelectedPathComponent();
			if (n instanceof DefaultMutableTreeNode dn && dn.getUserObject() instanceof String s && s.endsWith(".so")) {
				analyze(s);
			}
		});
		if (!any) {
			status.setText("No Flutter libraries detected (looking for libapp.so / libflutter.so)");
		} else {
			status.setText("Select a Flutter library above");
		}
	}

	private void analyze(String libPath) {
		status.setText("Analyzing " + libPath + " ...");
		new SwingWorker<FlutterAnalyzer, Void>() {
			private byte[] data;
			private String tmpName;

			@Override
			protected FlutterAnalyzer doInBackground() {
				try {
					data = project.readResource(libPath);
					if (data == null) {
						return null;
					}
					Path tmp = Files.createTempFile("flutter", ".so");
					Files.write(tmp, data);
					tmpName = tmp.toString();
					return FlutterAnalyzer.analyze(tmp);
				} catch (Exception e) {
					return null;
				}
			}

			@Override
			protected void done() {
				try {
					FlutterAnalyzer a = get();
					if (a == null) {
						status.setText("Could not read " + libPath);
						return;
					}
					showResults(a);
					status.setText(libPath + ": analyzed");
				} catch (Exception e) {
					status.setText("analysis failed: " + e.getMessage());
				}
			}
		}.execute();
	}

	private void showResults(FlutterAnalyzer a) {
		{
			{
					analyzer = a;
					export.setEnabled(true);
					StringBuilder sb = new StringBuilder();
					for (Map.Entry<String, String> e : a.getInfo().entrySet()) {
						sb.append(String.format("%-22s %s%n", e.getKey() + ":", e.getValue()));
					}
					if (!a.getFindings().isEmpty()) {
						sb.append("\nnotes:\n");
						for (String f : a.getFindings()) {
							sb.append("  - ").append(f).append('\n');
						}
					}
					sb.append("\nTip: for instruction-level Dart reconstruction use Blutter on this libapp.so.");
					infoArea.setText(sb.toString());
					infoArea.setCaretPosition(0);
					libArea.setText(String.join("\n", a.getDartLibraries()));
					libArea.setCaretPosition(0);
					classArea.setText(String.join("\n", a.getDartClasses()));
					classArea.setCaretPosition(0);
					funcArea.setText(String.join("\n", a.getDartFunctions()));
					funcArea.setCaretPosition(0);
					status.setText(a.getDartLibraries().size() + " libraries, "
							+ a.getDartClasses().size() + " classes, " + a.getDartFunctions().size() + " functions");
			}
		}
	}

	private void pickFile() {
		JFileChooser fc = new JFileChooser();
		fc.setDialogTitle("Pick a Flutter .so (libapp.so / libflutter.so)");
		fc.setFileFilter(new javax.swing.filechooser.FileNameExtensionFilter("ELF libraries (*.so)", "so"));
		if (fc.showOpenDialog(this) != JFileChooser.APPROVE_OPTION) {
			return;
		}
		File f = fc.getSelectedFile();
		status.setText("Analyzing " + f.getName() + " ...");
		new SwingWorker<FlutterAnalyzer, Void>() {
			@Override
			protected FlutterAnalyzer doInBackground() throws Exception {
				return FlutterAnalyzer.analyze(f.toPath());
			}

			@Override
			protected void done() {
				try {
					showResults(get());
				} catch (Exception e) {
					status.setText("analysis failed: " + e.getMessage());
				}
			}
		}.execute();
	}

	private void exportSymbols() {
		if (analyzer == null) {
			return;
		}
		JFileChooser fc = new JFileChooser();
		fc.setDialogTitle("Export Flutter symbols");
		if (fc.showSaveDialog(this) != JFileChooser.APPROVE_OPTION) {
			return;
		}
		try {
			StringBuilder sb = new StringBuilder();
			sb.append("# Flutter/Dart symbols\n");
			for (Map.Entry<String, String> e : analyzer.getInfo().entrySet()) {
				sb.append("# ").append(e.getKey()).append(": ").append(e.getValue()).append('\n');
			}
			sb.append("\n## Dart libraries\n");
			for (String s : analyzer.getDartLibraries()) {
				sb.append(s).append('\n');
			}
			sb.append("\n## Dart classes\n");
			for (String s : analyzer.getDartClasses()) {
				sb.append(s).append('\n');
			}
			sb.append("\n## Dart functions\n");
			for (String s : analyzer.getDartFunctions()) {
				sb.append(s).append('\n');
			}
			Files.writeString(fc.getSelectedFile().toPath(), sb.toString());
			status.setText("symbols written to " + fc.getSelectedFile());
		} catch (Exception e) {
			status.setText("export failed: " + e.getMessage());
		}
	}
}