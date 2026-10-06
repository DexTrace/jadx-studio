package com.jadxstudio.gui;

import javax.swing.BorderFactory;
import javax.swing.DefaultListModel;
import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JDialog;
import javax.swing.JLabel;
import javax.swing.JList;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTextField;
import javax.swing.ListSelectionModel;
import java.awt.BorderLayout;
import java.awt.Dimension;
import java.awt.FlowLayout;
import java.awt.Frame;
import java.util.ArrayList;
import java.util.List;
import java.util.function.Consumer;

/**
 * Search across all text (source, resources, manifest) with a shared
 * result model so the main window can also run it docked.
 */
public class SearchDialog extends JDialog {

	public record Result(String file, int line, String preview) {
	}

	public static class SearchEngine {
		public List<Result> search(List<FileText> files, String query, boolean regex, boolean caseSensitive) {
			List<Result> out = new ArrayList<>();
			if (query.isEmpty()) {
				return out;
			}
			java.util.regex.Pattern pat;
			try {
				pat = regex
						? java.util.regex.Pattern.compile(query, caseSensitive ? 0 : java.util.regex.Pattern.CASE_INSENSITIVE)
						: null;
			} catch (Exception e) {
				return out;
			}
			String needle = caseSensitive ? query : query.toLowerCase();
			for (FileText f : files) {
				String[] lines = f.text().split("\n", -1);
				for (int i = 0; i < lines.length; i++) {
					String line = lines[i];
					boolean hit;
					if (regex) {
						hit = pat.matcher(line).find();
					} else {
						hit = caseSensitive ? line.contains(needle) : line.toLowerCase().contains(needle);
					}
					if (hit) {
						out.add(new Result(f.path(), i + 1, line.trim()));
						if (out.size() >= 5000) {
							return out;
						}
					}
				}
			}
			return out;
		}
	}

	public record FileText(String path, String text) {
	}

	private final JTextField query = new JTextField();
	private final JCheckBox regex = new JCheckBox("Regex");
	private final JCheckBox caseSens = new JCheckBox("Case");
	private final JLabel count = new JLabel(" ");
	private final DefaultListModel<Result> model = new DefaultListModel<>();
	private final JList<Result> list = new JList<>(model);
	private final SearchEngine engine = new SearchEngine();
	private List<FileText> corpus = List.of();
	private Consumer<Result> onOpen;

	public SearchDialog(Frame owner) {
		super(owner, "Search All Text", false);
		setSize(new Dimension(760, 480));
		setLocationRelativeTo(owner);

		list.setFont(com.jadxstudio.util.Ui.MONO);
		list.setCellRenderer(new javax.swing.DefaultListCellRenderer() {
			@Override
			public java.awt.Component getListCellRendererComponent(JList<?> l, Object v, int i, boolean s, boolean f) {
				Result r = (Result) v;
				JLabel lbl = (JLabel) super.getListCellRendererComponent(l, r.file() + ":" + r.line() + "   "
						+ r.preview(), i, s, f);
				lbl.setFont(com.jadxstudio.util.Ui.MONO);
				lbl.setBorder(BorderFactory.createEmptyBorder(2, 6, 2, 6));
				return lbl;
			}
		});
		list.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
		list.addListSelectionListener(e -> {
			if (!e.getValueIsAdjusting() && list.getSelectedValue() != null && onOpen != null) {
				onOpen.accept(list.getSelectedValue());
			}
		});

		JPanel top = new JPanel(new BorderLayout(6, 4));
		top.setBorder(BorderFactory.createEmptyBorder(8, 8, 4, 8));
		top.add(query, BorderLayout.CENTER);
		JPanel opts = new JPanel(new FlowLayout(FlowLayout.RIGHT, 6, 0));
		opts.add(regex);
		opts.add(caseSens);
		top.add(opts, BorderLayout.EAST);

		JPanel bottom = new JPanel(new BorderLayout());
		bottom.setBorder(BorderFactory.createEmptyBorder(4, 8, 8, 8));
		bottom.add(count, BorderLayout.WEST);
		JButton close = new JButton("Close");
		close.addActionListener(e -> dispose());
		JPanel bp = new JPanel(new FlowLayout(FlowLayout.RIGHT));
		bp.add(close);
		bottom.add(bp, BorderLayout.EAST);

		JPanel p = new JPanel(new BorderLayout());
		p.add(top, BorderLayout.NORTH);
		p.add(new JScrollPane(list), BorderLayout.CENTER);
		p.add(bottom, BorderLayout.SOUTH);
		setContentPane(p);

		javax.swing.Timer t = new javax.swing.Timer(250, e -> runSearch());
		t.setRepeats(false);
		query.getDocument().addDocumentListener(new javax.swing.event.DocumentListener() {
			public void insertUpdate(javax.swing.event.DocumentEvent e) {
				t.restart();
			}

			public void removeUpdate(javax.swing.event.DocumentEvent e) {
				t.restart();
			}

			public void changedUpdate(javax.swing.event.DocumentEvent e) {
				t.restart();
			}
		});
		query.addActionListener(e -> runSearch());
	}

	public void setCorpus(List<FileText> corpus) {
		this.corpus = corpus;
	}

	public void setOnOpen(Consumer<Result> c) {
		this.onOpen = c;
	}

	public void openWith(String initialQuery) {
		if (initialQuery != null) {
			query.setText(initialQuery);
		}
		setVisible(true);
		query.requestFocusInWindow();
	}

	public List<Result> searchNow(String q) {
		return engine.search(corpus, q, regex.isSelected(), caseSens.isSelected());
	}

	private void runSearch() {
		String q = query.getText();
		long t0 = System.currentTimeMillis();
		List<Result> res = engine.search(corpus, q, regex.isSelected(), caseSens.isSelected());
		model.clear();
		for (Result r : res) {
			model.addElement(r);
		}
		count.setText(res.size() + " results in " + (System.currentTimeMillis() - t0) + " ms");
	}
}
