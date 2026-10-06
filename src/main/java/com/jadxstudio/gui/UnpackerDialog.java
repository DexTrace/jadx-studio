package com.jadxstudio.gui;

import com.jadxstudio.analysis.pairip.PairipAnalyzer;
import com.jadxstudio.analysis.unpack.PackedPayloadScanner;
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
import javax.swing.JTable;
import javax.swing.JTextArea;
import javax.swing.SwingWorker;
import javax.swing.table.AbstractTableModel;
import java.awt.BorderLayout;
import java.awt.Dimension;
import java.awt.FlowLayout;
import java.awt.Frame;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

/**
 * Unpacker / dumper window: PairIP analysis, packed-payload extraction and
 * ready-to-run Frida scripts for the device-side dumping step.
 */
public class UnpackerDialog extends JDialog {

	private final Project project;
	private final JTextArea pairipInfo = new JTextArea();
	private final JTextArea patchNotes = new JTextArea();
	private final JTextArea payloadInfo = new JTextArea();
	private final JTextArea scriptArea = new JTextArea();
	private final JLabel status = new JLabel(" ");
	private final PayloadModel payloadModel = new PayloadModel();
	private final FieldModel fieldModel = new FieldModel();

	private PairipAnalyzer pairip;
	private List<PackedPayloadScanner.Payload> payloads = List.of();

	public UnpackerDialog(Frame owner, Project project) {
		super(owner, "Unpacker / Dumper (PairIP, jiagu)", false);
		this.project = project;
		setSize(new Dimension(1200, 820));
		setLocationRelativeTo(owner);

		for (JTextArea a : List.of(pairipInfo, patchNotes, payloadInfo, scriptArea)) {
			a.setEditable(false);
			a.setFont(new java.awt.Font(java.awt.Font.MONOSPACED, java.awt.Font.BOLD, 13));
		}

		JTabbedPane tabs = new JTabbedPane();
		tabs.addTab("PairIP", pairipTab());
		tabs.addTab("Packed payloads", payloadsTab());
		tabs.addTab("Frida scripts", scriptsTab());

		JPanel p = new JPanel(new BorderLayout());
		p.add(tabs, BorderLayout.CENTER);
		JPanel bottom = new JPanel(new BorderLayout());
		bottom.add(status, BorderLayout.CENTER);
		bottom.setBorder(BorderFactory.createEmptyBorder(3, 8, 5, 8));
		p.add(bottom, BorderLayout.SOUTH);
		setContentPane(p);

		runScan();
	}

	private JPanel pairipTab() {
		JTable t = new JTable(fieldModel);
		t.setRowHeight(22);
		t.setFont(com.jadxstudio.util.Ui.TREE);
		JPanel right = new JPanel(new BorderLayout());
		right.add(new JScrollPane(pairipInfo), BorderLayout.NORTH);
		right.add(new JScrollPane(patchNotes), BorderLayout.CENTER);
		JSplitPane split = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT,
				new JScrollPane(t), right);
		split.setDividerLocation(520);
		JPanel p = new JPanel(new BorderLayout());
		p.add(split, BorderLayout.CENTER);
		return p;
	}

	private javax.swing.JComponent payloadsTab() {
		JTable t = new JTable(payloadModel);
		t.setRowHeight(22);
		t.setFont(com.jadxstudio.util.Ui.TREE);
		JPanel top = new JPanel(new FlowLayout(FlowLayout.LEFT, 6, 4));
		JButton extract = new JButton("Extract selected to folder...");
		extract.addActionListener(e -> extractSelected());
		top.add(extract);
		JButton rescan = new JButton("Rescan");
		rescan.addActionListener(e -> runScan());
		top.add(rescan);
		JSplitPane split = new JSplitPane(JSplitPane.VERTICAL_SPLIT, top, new JScrollPane(t));
		split.setResizeWeight(0.0);
		JSplitPane outer = new JSplitPane(JSplitPane.VERTICAL_SPLIT, split,
				new JScrollPane(payloadInfo));
		outer.setResizeWeight(0.6);
		return outer;
	}

	private javax.swing.JComponent scriptsTab() {
		JPanel top = new JPanel(new FlowLayout(FlowLayout.LEFT, 6, 4));
		JButton copy = new JButton("Copy to clipboard");
		copy.addActionListener(e -> {
			java.awt.Toolkit.getDefaultToolkit().getSystemClipboard()
					.setContents(new java.awt.datatransfer.StringSelection(scriptArea.getText()), null);
			status.setText("script copied");
		});
		JButton save = new JButton("Save script to file...");
		save.addActionListener(e -> saveScript());
		top.add(copy);
		top.add(save);
		JPanel p = new JPanel(new BorderLayout());
		p.add(top, BorderLayout.NORTH);
		p.add(new JScrollPane(scriptArea), BorderLayout.CENTER);
		return p;
	}

	// ------------------------------------------------------------- actions

	private void runScan() {
		status.setText("Scanning (no decompilation, runs in background)...");
		new SwingWorker<Void, Void>() {
			@Override
			protected Void doInBackground() throws Exception {
				pairip = PairipAnalyzer.analyze(project.getClassPaths(), project.getNativePaths(),
						project.blankStaticFields());
				Path root = project.getRoot();
				if (root != null) {
					payloads = PackedPayloadScanner.scan(root).getPayloads();
				}
				return null;
			}

			@Override
			protected void done() {
				try {
					get();
					pairipInfo.setText(pairipSummary());
					pairipInfo.setCaretPosition(0);
					patchNotes.setText(pairip.patchNotes());
					patchNotes.setCaretPosition(0);
					fieldModel.set(pairip.getFields());
					payloadModel.set(payloads);
					StringBuilder sb = new StringBuilder();
					sb.append("Packed payload candidates (entropy > 7.5 usually = encrypted)\n\n");
					for (PackedPayloadScanner.Payload p : payloads) {
						sb.append(String.format("%-46s %10d  H=%.2f  %s  %s%n", p.entry(), p.size(),
								p.entropy(), p.kind(), p.note()));
					}
					payloadInfo.setText(sb.toString());
					payloadInfo.setCaretPosition(0);
					scriptArea.setText(pairip.isDetected()
							? pairip.fridaScript() + "\n\n" + PackedPayloadScanner.fridaDexDumpScript()
							: PackedPayloadScanner.fridaDexDumpScript());
					scriptArea.setCaretPosition(0);
					status.setText(pairip.isDetected()
							? "PairIP detected" + (pairip.hasVmLayer() ? " (with VM layer)" : "")
							: "No PairIP detected; generic dex-dump script ready");
				} catch (Exception e) {
					status.setText("scan failed: " + e.getMessage());
				}
			}
		}.execute();
	}

	private String pairipSummary() {
		StringBuilder sb = new StringBuilder();
		sb.append("PairIP (Google PLAY Integrity Protect): ")
				.append(pairip.isDetected() ? "DETECTED" : "not detected").append('\n');
		sb.append("VM layer (VMRunner): ").append(pairip.hasVmLayer() ? "YES" : "no").append("\n\n");
		sb.append("PairIP classes: ").append(pairip.getPairipClasses()).append('\n');
		sb.append("PairIP natives: ").append(pairip.getNativeLibs()).append('\n');
		sb.append("Gate methods: ").append(pairip.getGateMethods()).append("\n\n");
		sb.append("Blank static String fields to recover: ").append(pairip.getFields().size()).append('\n');
		for (PairipAnalyzer.ProtectedField f : pairip.getFields()) {
			sb.append("  ").append(f.cls()).append("->").append(f.field()).append("  (").append(f.note())
					.append(")\n");
		}
		for (String n : pairip.getNotes()) {
			sb.append("note: ").append(n).append('\n');
		}
		return sb.toString();
	}

	private void extractSelected() {
		int row = payloadTableRow();
		if (row < 0) {
			return;
		}
		JFileChooser fc = new JFileChooser();
		fc.setDialogTitle("Extract payload to folder");
		fc.setFileSelectionMode(JFileChooser.DIRECTORIES_ONLY);
		if (fc.showSaveDialog(this) != JFileChooser.APPROVE_OPTION) {
			return;
		}
		try {
			PackedPayloadScanner.Payload p = payloads.get(row);
			Path out = fc.getSelectedFile().toPath().resolve(p.entry().replace('/', '_'));
			PackedPayloadScanner.extract(project.getRoot(), p.entry(), out);
			status.setText("extracted " + p.entry() + " -> " + out);
		} catch (Exception e) {
			status.setText("extract failed: " + e.getMessage());
		}
	}

	private int payloadTableRow() {
		for (java.awt.Component c : getContentPane().getComponents()) {
			int[] r = findSelected(c);
			if (r != null) {
				return r[0];
			}
		}
		return -1;
	}

	private int[] findSelected(java.awt.Component c) {
		if (c instanceof JTable t && t.getModel() == payloadModel) {
			return t.getSelectedRow() >= 0 ? new int[] { t.convertRowIndexToModel(t.getSelectedRow()) } : null;
		}
		if (c instanceof java.awt.Container cont) {
			for (java.awt.Component ch : cont.getComponents()) {
				int[] r = findSelected(ch);
				if (r != null) {
					return r;
				}
			}
		}
		return null;
	}

	private void saveScript() {
		JFileChooser fc = new JFileChooser();
		fc.setDialogTitle("Save Frida script");
		fc.setSelectedFile(new java.io.File("dump.js"));
		if (fc.showSaveDialog(this) != JFileChooser.APPROVE_OPTION) {
			return;
		}
		try {
			Files.writeString(fc.getSelectedFile().toPath(), scriptArea.getText());
			status.setText("script saved to " + fc.getSelectedFile());
		} catch (Exception e) {
			status.setText("save failed: " + e.getMessage());
		}
	}

	// --------------------------------------------------------------- models

	private static final class PayloadModel extends AbstractTableModel {
		private List<PackedPayloadScanner.Payload> rows = List.of();

		void set(List<PackedPayloadScanner.Payload> p) {
			rows = p;
			fireTableDataChanged();
		}

		@Override
		public int getRowCount() {
			return rows.size();
		}

		@Override
		public int getColumnCount() {
			return 5;
		}

		@Override
		public String getColumnName(int c) {
			return new String[] { "Entry", "Size", "Entropy", "Kind", "Note" }[c];
		}

		@Override
		public Object getValueAt(int r, int c) {
			PackedPayloadScanner.Payload p = rows.get(r);
			return switch (c) {
				case 0 -> p.entry();
				case 1 -> String.valueOf(p.size());
				case 2 -> String.format("%.2f", p.entropy());
				case 3 -> p.kind();
				default -> p.note();
			};
		}
	}

	private static final class FieldModel extends AbstractTableModel {
		private List<PairipAnalyzer.ProtectedField> rows = List.of();

		void set(List<PairipAnalyzer.ProtectedField> f) {
			rows = f;
			fireTableDataChanged();
		}

		@Override
		public int getRowCount() {
			return rows.size();
		}

		@Override
		public int getColumnCount() {
			return 3;
		}

		@Override
		public String getColumnName(int c) {
			return new String[] { "Class", "Blank static field", "Note" }[c];
		}

		@Override
		public Object getValueAt(int r, int c) {
			PairipAnalyzer.ProtectedField f = rows.get(r);
			return switch (c) {
				case 0 -> f.cls();
				case 1 -> f.field();
				default -> f.note();
			};
		}
	}
}