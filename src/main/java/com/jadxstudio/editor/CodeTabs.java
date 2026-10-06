package com.jadxstudio.editor;

import com.jadxstudio.util.Ui;

import javax.swing.BorderFactory;
import javax.swing.JComponent;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JPopupMenu;
import javax.swing.JTabbedPane;
import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.Component;
import java.awt.Dimension;
import java.awt.FlowLayout;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Tab container for open documents. Every tab has its own close button (and
 * middle-click / right-click support) so the tab bar never fills up.
 */
public class CodeTabs extends JTabbedPane {

	private final Map<String, EditorTab> tabs = new LinkedHashMap<>();
	private final List<String> order = new ArrayList<>();
	private final Map<String, JLabel> headers = new LinkedHashMap<>();
	private java.util.function.Consumer<String> onSelection;

	public interface EditorTab {
		JComponent component();

		String title();

		default boolean isDirty() {
			return false;
		}

		default void markSaved() {
		}

		default void close() {
		}
	}

	public CodeTabs() {
		addChangeListener(e -> {
			if (onSelection != null) {
				onSelection.accept(currentKey());
			}
		});
	}

	public void setOnSelection(java.util.function.Consumer<String> c) {
		this.onSelection = c;
	}

	public String currentKey() {
		int i = getSelectedIndex();
		return i >= 0 && i < order.size() ? order.get(i) : null;
	}

	public boolean hasKey(String key) {
		return tabs.containsKey(key);
	}

	public EditorTab getTab(String key) {
		return tabs.get(key);
	}

	public List<String> keys() {
		return new ArrayList<>(order);
	}

	public int count() {
		return tabs.size();
	}

	/** Open (or focus) a tab. */
	public void open(String key, EditorTab tab) {
		if (tabs.containsKey(key)) {
			select(key);
			return;
		}
		tabs.put(key, tab);
		order.add(key);
		addTab(tab.title(), tab.component());
		int idx = indexOfComponent(tab.component());
		JLabel header = new JLabel(tab.title());
		header.setFont(Ui.TREE);
		headers.put(key, header);
		setTabComponentAt(idx, new TabHeader(header, key, this));
		setSelectedIndex(idx);
		refreshTitles();
	}

	public void select(String key) {
		int idx = indexOfKey(key);
		if (idx >= 0) {
			setSelectedIndex(idx);
		}
	}

	public void closeKey(String key) {
		EditorTab t = tabs.remove(key);
		order.remove(key);
		headers.remove(key);
		if (t == null) {
			return;
		}
		t.close();
		remove(t.component());
		refreshTitles();
	}

	public void closeCurrent() {
		String k = currentKey();
		if (k != null) {
			closeKey(k);
		}
	}

	public void closeOthers() {
		String keep = currentKey();
		for (String k : new ArrayList<>(order)) {
			if (!k.equals(keep)) {
				closeKey(k);
			}
		}
	}

	public void closeAll() {
		for (String k : new ArrayList<>(order)) {
			closeKey(k);
		}
	}

	public int indexOfKey(String key) {
		int i = order.indexOf(key);
		return i;
	}

	/** Refresh titles + dirty markers. */
	public void refreshTitles() {
		for (int i = 0; i < order.size(); i++) {
			String key = order.get(i);
			EditorTab t = tabs.get(key);
			int idx = indexOfComponent(t.component());
			if (idx < 0) {
				continue;
			}
			String title = t.title() + (t.isDirty() ? " *" : "");
			String existing = getTitleAt(idx);
			if (existing != null && !existing.equals(title)) {
				setTitleAt(idx, title);
			}
			JLabel header = headers.get(key);
			if (header != null && !header.getText().equals(title)) {
				header.setText(title);
			}
		}
	}

	/** Tab header: label + close button, with middle-click and a context menu. */
	private static final class TabHeader extends JPanel {
		private final JLabel label;
		private final String key;
		private final CodeTabs owner;

		TabHeader(JLabel label, String key, CodeTabs owner) {
			super(new FlowLayout(FlowLayout.LEFT, 4, 0));
			this.label = label;
			this.key = key;
			this.owner = owner;
			setOpaque(false);

			JLabel x = new JLabel("✕");
			x.setFont(Ui.TREE);
			x.setToolTipText("Close tab (Ctrl+W)");
			x.setBorder(BorderFactory.createEmptyBorder(0, 4, 0, 6));
			x.setCursor(java.awt.Cursor.getPredefinedCursor(java.awt.Cursor.HAND_CURSOR));
			x.addMouseListener(new MouseAdapter() {
				@Override
				public void mouseClicked(MouseEvent e) {
					owner.closeKey(TabHeader.this.key);
				}
			});
			add(label);
			add(x);

			setBorder(BorderFactory.createEmptyBorder(2, 6, 2, 0));
			setToolTipText("Middle-click or use ✕ to close");

			addMouseListener(new MouseAdapter() {
				@Override
				public void mousePressed(MouseEvent e) {
					maybePopup(e);
				}

				@Override
				public void mouseReleased(MouseEvent e) {
					maybePopup(e);
				}

				private void maybePopup(MouseEvent e) {
					if (SwingUtilities2.isMiddle(e)) {
						owner.closeKey(TabHeader.this.key);
					} else if (e.isPopupTrigger()) {
						owner.select(TabHeader.this.key);
						JPopupMenu menu = new JPopupMenu();
						menu.add("Close").addActionListener(a -> owner.closeKey(TabHeader.this.key));
						menu.add("Close others").addActionListener(a -> owner.closeOthers());
						menu.add("Close all").addActionListener(a -> owner.closeAll());
						menu.show(e.getComponent(), e.getX(), e.getY());
					}
				}
			});
		}

		@Override
		public Dimension getPreferredSize() {
			Dimension d = super.getPreferredSize();
			return new Dimension(Math.max(90, d.width + 6), d.height);
		}
	}

	/** small helper so the header code stays readable */
	private static final class SwingUtilities2 {
		static boolean isMiddle(MouseEvent e) {
			return javax.swing.SwingUtilities.isMiddleMouseButton(e);
		}
	}

	/** Status bar helper. */
	public static JPanel statusBar(JLabel left, JLabel right) {
		JPanel p = new JPanel(new BorderLayout());
		p.setBackground(new Color(0xE8EAED));
		p.setBorder(BorderFactory.createCompoundBorder(
				BorderFactory.createMatteBorder(1, 0, 0, 0, new Color(0xC9CDD2)),
				BorderFactory.createEmptyBorder(3, 8, 3, 8)));
		JPanel l = new JPanel(new FlowLayout(FlowLayout.LEFT, 4, 0));
		l.setOpaque(false);
		l.add(left);
		p.add(l, BorderLayout.WEST);
		JPanel r = new JPanel(new FlowLayout(FlowLayout.RIGHT, 4, 0));
		r.setOpaque(false);
		r.add(right);
		p.add(r, BorderLayout.EAST);
		return p;
	}

	public static void later(Runnable r) {
		Ui.runOnEdt(r);
	}

	/** Component lookup helper used by the main window. */
	public static Component componentOf(EditorTab t) {
		return t == null ? null : t.component();
	}
}