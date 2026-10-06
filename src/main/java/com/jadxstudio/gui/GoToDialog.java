package com.jadxstudio.gui;

import com.jadxstudio.core.JavaIndex;

import javax.swing.DefaultListModel;
import javax.swing.JDialog;
import javax.swing.JList;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTextField;
import javax.swing.ListSelectionModel;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;
import java.awt.BorderLayout;
import java.awt.Frame;
import java.awt.Dimension;
import java.util.List;

/** "Go to declaration" dialog: fuzzy search over classes and methods. */
public class GoToDialog extends JDialog {

	private final JTextField field = new JTextField();
	private final DefaultListModel<String> model = new DefaultListModel<>();
	private final JList<String> list = new JList<>(model);
	private String chosen;
	private final JavaIndex index;

	public interface Handler {
		void onGoTo(String entry, GoToDialog dlg);
	}

	public GoToDialog(Frame owner, JavaIndex index, Handler handler) {
		super(owner, "Go to Declaration", true);
		this.index = index;
		setSize(new Dimension(560, 420));
		setLocationRelativeTo(owner);

		field.setFont(com.jadxstudio.util.Ui.MONO);
		list.setFont(com.jadxstudio.util.Ui.TREE);
		list.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);

		JPanel top = new JPanel(new BorderLayout(6, 6));
		top.setBorder(javax.swing.BorderFactory.createEmptyBorder(8, 8, 4, 8));
		top.add(field, BorderLayout.CENTER);

		JPanel p = new JPanel(new BorderLayout());
		p.add(top, BorderLayout.NORTH);
		p.add(new JScrollPane(list), BorderLayout.CENTER);
		setContentPane(p);

		field.getDocument().addDocumentListener(new DocumentListener() {
			public void insertUpdate(DocumentEvent e) {
				refresh();
			}

			public void removeUpdate(DocumentEvent e) {
				refresh();
			}

			public void changedUpdate(DocumentEvent e) {
				refresh();
			}
		});
		list.addListSelectionListener(e -> {
			if (!e.getValueIsAdjusting() && list.getSelectedValue() != null) {
				String v = list.getSelectedValue();
				chosen = v;
				handler.onGoTo(v, this);
			}
		});
		refresh();
		field.requestFocusInWindow();
		setVisible(true);
	}

	private void refresh() {
		String q = field.getText().trim();
		model.clear();
		List<String> res = index.search(q, 200);
		for (String s : res) {
			model.addElement(s);
		}
		if (!model.isEmpty()) {
			list.setSelectedIndex(0);
		}
	}

	public String getChosen() {
		return chosen;
	}
}
