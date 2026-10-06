package com.jadxstudio.gui;

import com.jadxstudio.core.Project;

import javax.swing.BorderFactory;
import javax.swing.JButton;
import javax.swing.JDialog;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JSplitPane;
import javax.swing.JTable;
import javax.swing.JTextField;
import javax.swing.ListSelectionModel;
import javax.swing.table.AbstractTableModel;
import java.awt.BorderLayout;
import java.awt.Dimension;
import java.awt.FlowLayout;
import java.awt.Frame;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Deobfuscation workflow: view/edit renames in the jadx .jobf format
 * ({@code c raw.name = NewName}), apply them (re-decompiles), save/load
 * mapping files. Mapping keys: c=class, m=method, f=field, p=package.
 */
public class DeobfuscationDialog extends JDialog {

	private final Project project;
	private final MappingTableModel classModel = new MappingTableModel("class");
	private final MappingTableModel methodModel = new MappingTableModel("method");
	private final MappingTableModel fieldModel = new MappingTableModel("field");
	private final MappingTableModel pkgModel = new MappingTableModel("package");
	private Runnable onApplied = () -> {
	};

	public DeobfuscationDialog(Frame owner, Project project) {
		super(owner, "Deobfuscation - mapping editor", false);
		this.project = project;
		setSize(new Dimension(1000, 600));
		setLocationRelativeTo(owner);

		classModel.load(project.getMapping());
		methodModel.load(project.getMapping());
		fieldModel.load(project.getMapping());
		pkgModel.load(project.getMapping());

		JPanel top = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 6));
		top.add(new JLabel("Mapping file (.jobf):"));
		JTextField mapPath = new JTextField(
				project.getMappingPath() == null ? "(not loaded)" : project.getMappingPath().toString(), 44);
		top.add(mapPath);
		JButton load = new JButton("Load...");
		load.addActionListener(e -> {
			javax.swing.JFileChooser fc = new javax.swing.JFileChooser();
			fc.setDialogTitle("Load deobfuscation mapping (.jobf)");
			if (fc.showOpenDialog(this) == javax.swing.JFileChooser.APPROVE_OPTION) {
				try {
					Map<String, String> m = Project.readJobf(fc.getSelectedFile().toPath());
					project.getMapping().clear();
					project.getMapping().putAll(m);
					reloadTables();
					mapPath.setText(fc.getSelectedFile().getAbsolutePath());
					JOptionPane.showMessageDialog(this, "Loaded " + m.size() + " mapping entries.");
				} catch (IOException ex) {
					JOptionPane.showMessageDialog(this, "Load failed: " + ex.getMessage(), "Error",
							JOptionPane.ERROR_MESSAGE);
				}
			}
		});
		top.add(load);
		JButton save = new JButton("Save...");
		save.addActionListener(e -> {
			javax.swing.JFileChooser fc = new javax.swing.JFileChooser();
			fc.setDialogTitle("Save deobfuscation mapping (.jobf)");
			if (fc.showSaveDialog(this) == javax.swing.JFileChooser.APPROVE_OPTION) {
				try {
					collectAll();
					Project.writeJobf(fc.getSelectedFile().toPath(), project.getMapping());
					JOptionPane.showMessageDialog(this, "Mapping saved to " + fc.getSelectedFile());
				} catch (IOException ex) {
					JOptionPane.showMessageDialog(this, "Save failed: " + ex.getMessage(), "Error",
							JOptionPane.ERROR_MESSAGE);
				}
			}
		});
		top.add(save);
		top.add(new JLabel(" Format: c com.example.Foo = ReadableName | m com.example.Foo.bar()V = doBar"));

		JPanel body = new JPanel(new BorderLayout());
		body.add(top, BorderLayout.NORTH);
		JSplitPane vertical = new JSplitPane(JSplitPane.VERTICAL_SPLIT,
				tablePanel("Classes (raw name -> new)", classModel),
				new JSplitPane(JSplitPane.VERTICAL_SPLIT, tablePanel("Methods", methodModel),
						new JSplitPane(JSplitPane.HORIZONTAL_SPLIT, tablePanel("Fields", fieldModel),
								tablePanel("Packages", pkgModel))));
		vertical.setResizeWeight(0.5);
		body.add(vertical, BorderLayout.CENTER);

		JPanel bottom = new JPanel(new FlowLayout(FlowLayout.RIGHT, 8, 6));
		bottom.add(addBtn("Add class", classModel));
		bottom.add(addBtn("Add method", methodModel));
		bottom.add(addBtn("Add field", fieldModel));
		bottom.add(addBtn("Add package", pkgModel));
		JButton apply = new JButton("Apply (re-decompile with new names)");
		apply.addActionListener(e -> applyMapping());
		bottom.add(apply);
		JButton close = new JButton("Close");
		close.addActionListener(e -> dispose());
		bottom.add(close);
		body.add(bottom, BorderLayout.SOUTH);
		body.setBorder(BorderFactory.createEmptyBorder(4, 4, 4, 4));
		setContentPane(body);
	}

	private JButton addBtn(String label, MappingTableModel m) {
		JButton b = new JButton(label);
		b.addActionListener(e -> m.addRow());
		return b;
	}

	private JPanel tablePanel(String title, MappingTableModel m) {
		JTable t = new JTable(m);
		t.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
		t.setAutoCreateRowSorter(true);
		t.setRowHeight(22);
		JScrollPane sp = new JScrollPane(t);
		sp.setBorder(BorderFactory.createTitledBorder(title + "  (blank new name = remove)"));
		JPanel p = new JPanel(new BorderLayout());
		p.add(sp, BorderLayout.CENTER);
		return p;
	}

	private void reloadTables() {
		classModel.load(project.getMapping());
		methodModel.load(project.getMapping());
		fieldModel.load(project.getMapping());
		pkgModel.load(project.getMapping());
	}

	private void collectAll() {
		project.getMapping().clear();
		classModel.collect(project.getMapping());
		methodModel.collect(project.getMapping());
		fieldModel.collect(project.getMapping());
		pkgModel.collect(project.getMapping());
	}

	private void applyMapping() {
		collectAll();
		project.setMappingsChanged();
		onApplied.run();
	}

	public void setOnApplied(Runnable r) {
		this.onApplied = r;
	}

	static class MappingTableModel extends AbstractTableModel {
		private final String kind;
		private final String[] cols = { "Kind", "Original (raw id)", "New name" };
		private final List<String[]> rows = new ArrayList<>();

		MappingTableModel(String kind) {
			this.kind = kind;
		}

		void load(Map<String, String> mapping) {
			rows.clear();
			for (Map.Entry<String, String> e : mapping.entrySet()) {
				String k = e.getKey();
				if (k.length() < 3 || k.charAt(1) != ' ') {
					continue;
				}
				char c = k.charAt(0);
				String kd = switch (c) {
					case 'c' -> "class";
					case 'm' -> "method";
					case 'f' -> "field";
					case 'p' -> "package";
					default -> "other";
				};
				if (!kd.equals(kind)) {
					continue;
				}
				rows.add(new String[] { kd, k.substring(2), e.getValue() });
			}
			fireTableDataChanged();
		}

		void collect(Map<String, String> out) {
			for (String[] r : rows) {
				if (r[1] == null || r[1].isBlank() || r[2] == null || r[2].isBlank()) {
					continue;
				}
				char c = switch (r[0]) {
					case "class" -> 'c';
					case "method" -> 'm';
					case "field" -> 'f';
					default -> 'p';
				};
				out.put(c + " " + r[1].trim(), r[2].trim());
			}
		}

		void addRow() {
			rows.add(new String[] { kind, "", "" });
			fireTableRowsInserted(rows.size() - 1, rows.size() - 1);
		}

		@Override
		public int getRowCount() {
			return rows.size();
		}

		@Override
		public int getColumnCount() {
			return cols.length;
		}

		@Override
		public String getColumnName(int c) {
			return cols[c];
		}

		@Override
		public boolean isCellEditable(int r, int c) {
			return true;
		}

		@Override
		public Object getValueAt(int r, int c) {
			return rows.get(r)[c];
		}

		@Override
		public void setValueAt(Object v, int r, int c) {
			rows.get(r)[c] = String.valueOf(v);
			fireTableCellUpdated(r, c);
		}
	}
}
