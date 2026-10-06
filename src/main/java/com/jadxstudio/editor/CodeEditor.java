package com.jadxstudio.editor;

import javax.swing.JScrollPane;
import javax.swing.JTextPane;
import javax.swing.text.Element;
import java.awt.Font;

/**
 * Code editor: themed, line numbers, incremental syntax highlighting.
 * Used for Java, smali, C pseudocode, native assembly, XML and plain text.
 */
public class CodeEditor extends javax.swing.JPanel {

	private final JTextPane area;
	private final LineNumbersGutter gutter;
	private final JScrollPane scroll;
	private final CodeDocument doc;

	public CodeEditor(String initialText, boolean highlight) {
		this(initialText, highlight, JavaTokenizer.Lang.JAVA);
	}

	public CodeEditor(String initialText, boolean highlight, JavaTokenizer.Lang lang) {
		area = new JTextPane();
		doc = new CodeDocument();
		doc.setLanguage(lang);
		doc.setHighlightingEnabled(highlight);
		area.setDocument(doc);
		area.setFont(Theme.codeFont(14));
		area.setBackground(Theme.current().background());
		area.setForeground(Theme.current().foreground());
		area.setCaretColor(Theme.current().foreground());
		area.setMargin(new java.awt.Insets(4, 8, 4, 6));
		area.setCaretPosition(0);

		// insert first (highlighting is queued), then paint the initial state synchronously
		if (initialText != null) {
			try {
				doc.insertString(0, initialText, null);
			} catch (Exception ignored) {
			}
		}
		doc.markSaved();
		doc.highlightAll();

		gutter = new LineNumbersGutter(area);
		scroll = new JScrollPane(area);
		scroll.setRowHeaderView(gutter);
		scroll.getViewport().addChangeListener(e -> gutter.repaint());
		scroll.setBorder(javax.swing.BorderFactory.createEmptyBorder());
		scroll.getViewport().setBackground(Theme.current().background());

		setLayout(new java.awt.BorderLayout());
		add(scroll, java.awt.BorderLayout.CENTER);
	}

	public JTextPane getTextComponent() {
		return area;
	}

	public CodeDocument getCodeDocument() {
		return doc;
	}

	public String getText() {
		return area.getText();
	}

	public void setText(String t) {
		area.setText(t == null ? "" : t);
		doc.highlightAll();
		doc.markSaved();
	}

	public void setLanguage(JavaTokenizer.Lang lang) {
		doc.setLanguage(lang);
		doc.highlightAll();
	}

	public void setFontSize(float size) {
		doc.setFontSize(size);
		area.setFont(Theme.codeFont(size));
	}

	public void setTheme(Theme theme) {
		doc.setTheme(theme);
		area.setBackground(theme.background());
		area.setForeground(theme.foreground());
		area.setCaretColor(theme.foreground());
		scroll.getViewport().setBackground(theme.background());
		gutter.applyTheme(theme);
		gutter.repaint();
	}

	public boolean isDirty() {
		return doc.isDirtyFlag();
	}

	public void markSaved() {
		doc.markSaved();
	}

	public void addDirtyListener(Runnable r) {
		doc.addDirtyListener(r);
	}

	public void addCaretListener(javax.swing.event.CaretListener l) {
		area.addCaretListener(l);
	}

	public void gotoLine(int line1Based) {
		Element root = doc.getDefaultRootElement();
		int line = Math.max(1, Math.min(line1Based, root.getElementCount()));
		area.setCaretPosition(root.getElement(line - 1).getStartOffset());
		area.requestFocusInWindow();
	}

	public int getCaretLine() {
		return doc.getDefaultRootElement().getElementIndex(area.getCaretPosition()) + 1;
	}

	public int getCaretOffset() {
		return area.getCaretPosition();
	}

	public void selectRange(int start, int len) {
		int end = Math.min(start + len, getText().length());
		area.setCaretPosition(Math.max(0, start));
		area.moveCaretPosition(Math.max(0, end));
		area.requestFocusInWindow();
	}

	/** Line-number gutter that tracks the editor. */
	static class LineNumbersGutter extends javax.swing.JComponent {
		private final JTextPane area;
		private Theme theme = Theme.current();

		LineNumbersGutter(JTextPane area) {
			this.area = area;
			area.getDocument().addDocumentListener(new javax.swing.event.DocumentListener() {
				public void insertUpdate(javax.swing.event.DocumentEvent e) {
					repaint();
				}

				public void removeUpdate(javax.swing.event.DocumentEvent e) {
					repaint();
				}

				public void changedUpdate(javax.swing.event.DocumentEvent e) {
					repaint();
				}
			});
			area.addCaretListener(e -> repaint());
			area.addComponentListener(new java.awt.event.ComponentAdapter() {
				@Override
				public void componentResized(java.awt.event.ComponentEvent e) {
					repaint();
				}
			});
			setFont(new Font(Font.MONOSPACED, Font.BOLD, 12));
			setOpaque(true);
			applyTheme(theme);
		}

		void applyTheme(Theme theme) {
			this.theme = theme;
			setBackground(theme.gutterBackground());
		}

		@Override
		public java.awt.Dimension getPreferredSize() {
			// height 0 -> the scroll pane stretches the row header to the viewport height
			return new java.awt.Dimension(lineNumberWidth(), 0);
		}

		@Override
		public java.awt.Dimension getMinimumSize() {
			return new java.awt.Dimension(lineNumberWidth(), 1);
		}

		private int lineNumberWidth() {
			Element root = area.getDocument().getDefaultRootElement();
			int digits = String.valueOf(Math.max(1, root.getElementCount())).length();
			return getFontMetrics(getFont()).stringWidth("0".repeat(digits)) + 18;
		}

		@Override
		protected void paintComponent(java.awt.Graphics g) {
			java.awt.Graphics2D g2 = (java.awt.Graphics2D) g.create();
			g2.setColor(theme.gutterBackground());
			g2.fillRect(0, 0, getWidth(), getHeight());
			try {
				g2.setFont(getFont());
				java.awt.FontMetrics fm = g2.getFontMetrics();
				Element root = area.getDocument().getDefaultRootElement();
				int count = root.getElementCount();
				if (count == 0) {
					g2.dispose();
					return;
				}
				int viewTop = area.getInsets().top;
				int start = Math.max(0, area.viewToModel2D(new java.awt.geom.Point2D.Double(0, viewTop)));
				int firstLine = Math.min(count - 1, root.getElementIndex(start));
				Element first = root.getElement(firstLine);
				g2.setColor(theme.gutterForeground());
				int y = viewTop - (start - first.getStartOffset()) + fm.getAscent();
				for (int i = firstLine; i < count && y < getHeight(); i++) {
					String s = String.valueOf(i + 1);
					g2.drawString(s, getWidth() - fm.stringWidth(s) - 7, y);
					y += fm.getHeight();
				}
			} catch (RuntimeException ignored) {
				// view not ready: numbers appear on the next repaint
			}
			g2.dispose();
		}

		@Override
		public void addNotify() {
			super.addNotify();
			javax.swing.SwingUtilities.invokeLater(this::repaint);
		}
	}
}