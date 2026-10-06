package com.jadxstudio.gui;

import com.jadxstudio.analysis.protect.ProtectorScanner;
import com.jadxstudio.core.Project;

import javax.swing.BorderFactory;
import javax.swing.JDialog;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JSplitPane;
import javax.swing.JTable;
import javax.swing.JTextArea;
import javax.swing.SwingWorker;
import javax.swing.table.AbstractTableModel;
import java.awt.BorderLayout;
import java.awt.Dimension;
import java.awt.Frame;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * Packer / protector detection window (dex2c, jiagu, Legu, Bangcle, Ijiami, AppGuard...).
 * Cheap heuristics only - no decompilation - so it stays instant on huge APKs.
 */
public class ProtectorDialog extends JDialog {

	private static final class FindingModel extends AbstractTableModel {
		private final List<ProtectorScanner.Finding> rows = new ArrayList<>();

		void set(List<ProtectorScanner.Finding> f) {
			rows.clear();
			rows.addAll(f);
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
			return new String[] { "Severity", "Finding", "Detail" }[c];
		}

		@Override
		public Object getValueAt(int r, int c) {
			ProtectorScanner.Finding f = rows.get(r);
			return switch (c) {
				case 0 -> f.severity();
				case 1 -> f.title();
				default -> f.detail();
			};
		}

		@Override
		public boolean isCellEditable(int r, int c) {
			return false;
		}
	}

	public ProtectorDialog(Frame owner, Project project) {
		super(owner, "Packer / protector detection", false);
		setSize(new Dimension(1100, 700));
		setLocationRelativeTo(owner);

		FindingModel model = new FindingModel();
		JTable table = new JTable(model);
		table.setRowHeight(22);
		table.setFont(com.jadxstudio.util.Ui.TREE);
		table.getColumnModel().getColumn(0).setPreferredWidth(70);
		table.getColumnModel().getColumn(1).setPreferredWidth(330);

		JTextArea scores = new JTextArea();
		scores.setEditable(false);
		scores.setFont(new java.awt.Font(java.awt.Font.MONOSPACED, java.awt.Font.BOLD, 13));

		JLabel verdict = new JLabel("Analyzing...");

		JPanel top = new JPanel(new BorderLayout());
		top.setBorder(BorderFactory.createEmptyBorder(8, 10, 4, 10));
		top.add(verdict, BorderLayout.CENTER);

		JSplitPane split = new JSplitPane(JSplitPane.VERTICAL_SPLIT, new JScrollPane(table),
				new JScrollPane(scores));
		split.setResizeWeight(0.7);

		JPanel p = new JPanel(new BorderLayout());
		p.add(top, BorderLayout.NORTH);
		p.add(split, BorderLayout.CENTER);
		setContentPane(p);

		new SwingWorker<ProtectorScanner, Void>() {
			@Override
			protected ProtectorScanner doInBackground() {
				// strings come from the project's ELF/string scan of native libs - cheap
				List<String> strings = project.collectStrings();
				return ProtectorScanner.scan(project.getNativePaths(), project.getClassPaths(),
						project.getApplicationClass(), strings);
			}

			@Override
			protected void done() {
				try {
					ProtectorScanner r = get();
					model.set(r.getFindings());
					StringBuilder sb = new StringBuilder();
					sb.append("confidence: ").append(r.getConfidence()).append("%\n\n");
					sb.append("scores:\n");
					for (Map.Entry<String, Integer> e : r.getScores().entrySet()) {
						sb.append(String.format("  %-45s %d%n", e.getKey(), e.getValue()));
					}
					scores.setText(sb.toString());
					scores.setCaretPosition(0);
					verdict.setText(r.isProtected()
							? "PROTECTED / PACKED - some code is hidden (runtime-generated or moved to native)"
							: "No strong packing indicators");
					verdict.setForeground(r.isProtected() ? new java.awt.Color(0xB00020)
							: new java.awt.Color(0x1B5E20));
				} catch (Exception e) {
					verdict.setText("scan failed: " + e.getMessage());
				}
			}
		}.execute();
	}
}