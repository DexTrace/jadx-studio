package com.jadxstudio.gui;

import com.jadxstudio.util.Ui;

import javax.swing.DefaultListCellRenderer;
import javax.swing.DefaultListModel;
import javax.swing.JList;
import java.awt.Component;
import java.util.function.Consumer;

/** Outline list: shows members of the current class, click jumps to line. */
public class OutlineList extends JList<String> {

	public record Item(String kind, String text, int line) {
		@Override
		public String toString() {
			String prefix = switch (kind) {
				case "type" -> "C ";
				case "method" -> "  M ";
				case "ann" -> "  @ ";
				default -> "    ";
			};
			return prefix + text;
		}
	}

	private final DefaultListModel<String> model = new DefaultListModel<>();
	private final java.util.List<Item> items = new java.util.ArrayList<>();
	private Consumer<Integer> onJump = i -> {
	};

	public OutlineList() {
		setModel(model);
		setFont(Ui.TREE);
		setCellRenderer(new DefaultListCellRenderer() {
			@Override
			public Component getListCellRendererComponent(JList<?> list, Object value, int index, boolean isSelected,
					boolean cellHasFocus) {
				super.getListCellRendererComponent(list, value, index, isSelected, cellHasFocus);
				Item it = items.get(index);
				setFont(it.kind().equals("type") ? Ui.TREE_BOLD : Ui.MONO);
				setText(it.toString());
				return this;
			}
		});
		addMouseListener(new java.awt.event.MouseAdapter() {
			@Override
			public void mouseClicked(java.awt.event.MouseEvent e) {
				int i = getSelectedIndex();
				if (i >= 0) {
					onJump.accept(items.get(i).line());
				}
			}
		});
	}

	public void setOnJump(Consumer<Integer> c) {
		this.onJump = c;
	}

	public void clear() {
		model.clear();
		items.clear();
	}

	public void add(String kind, String text, int line) {
		Item it = new Item(kind, text.length() > 120 ? text.substring(0, 120) + "..." : text, line);
		items.add(it);
		model.addElement(it.toString());
	}
}
