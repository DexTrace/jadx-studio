package com.jadxstudio.editor;

import javax.swing.SwingUtilities;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;
import javax.swing.text.BadLocationException;
import javax.swing.text.DefaultStyledDocument;
import javax.swing.text.Element;
import javax.swing.text.Style;
import javax.swing.text.StyleConstants;
import java.util.ArrayList;
import java.util.List;

/**
 * Styled document with incremental, theme-aware highlighting.
 *
 * <p>
 * Highlighting must never mutate the document while a document event is being
 * dispatched (Swing throws "Attempt to mutate in notification"), so edits schedule a
 * coalesced re-highlight on the event queue instead of running inline.
 */
public class CodeDocument extends DefaultStyledDocument {

	public static final int MAX_HIGHLIGHT_SIZE = 2_000_000;

	private JavaTokenizer.Lang lang = JavaTokenizer.Lang.JAVA;
	private Theme theme = Theme.current();
	private float fontSize = 14f;

	private boolean highlightingEnabled = true;
	private boolean dirtyFlag;
	private boolean highlightScheduled;
	private int pendingFrom = Integer.MAX_VALUE;
	private int pendingTo = -1;
	private final List<Runnable> dirtyListeners = new ArrayList<>();

	public CodeDocument() {
		applyStyles();
		DocumentListener dl = new DocumentListener() {
			@Override
			public void insertUpdate(DocumentEvent e) {
				onEdit(e.getOffset(), e.getLength());
			}

			@Override
			public void removeUpdate(DocumentEvent e) {
				onEdit(e.getOffset(), e.getLength());
			}

			@Override
			public void changedUpdate(DocumentEvent e) {
				onEdit(e.getOffset(), e.getLength());
			}
		};
		addDocumentListener(dl);
	}

	/** (Re)create the styles for the current theme / language. */
	public void applyStyles() {
		Style def = addStyle("base", null);
		StyleConstants.setForeground(def, theme.foreground());
		StyleConstants.setFontFamily(def, java.awt.Font.MONOSPACED);
		StyleConstants.setFontSize(def, Math.round(fontSize));
		StyleConstants.setBold(def, true);
		for (int kind : new int[] { JavaTokenizer.KW, JavaTokenizer.STR, JavaTokenizer.CHAR,
				JavaTokenizer.CMT, JavaTokenizer.NUM, JavaTokenizer.ANN, JavaTokenizer.TYPE,
				JavaTokenizer.TPL, JavaTokenizer.PRE, JavaTokenizer.ATTR, JavaTokenizer.DESC,
				JavaTokenizer.REG, JavaTokenizer.LABEL }) {
			Style st = addStyle("s" + kind, def);
			StyleConstants.setForeground(st, theme.forKind(kind));
			StyleConstants.setBold(st, theme.isBold(kind));
			StyleConstants.setItalic(st, theme.isItalic(kind));
		}
	}

	public void setLanguage(JavaTokenizer.Lang lang) {
		this.lang = lang;
	}

	public JavaTokenizer.Lang getLanguage() {
		return lang;
	}

	public void setTheme(Theme theme) {
		this.theme = theme;
		applyStyles();
		highlightAll();
	}

	public void setFontSize(float size) {
		this.fontSize = size;
		applyStyles();
		highlightAll();
	}

	public void setHighlightingEnabled(boolean enabled) {
		this.highlightingEnabled = enabled;
	}

	public void addDirtyListener(Runnable r) {
		dirtyListeners.add(r);
	}

	public boolean isDirtyFlag() {
		return dirtyFlag;
	}

	public void markSaved() {
		dirtyFlag = false;
	}

	// --------------------------------------------------------- edit -> async

	private void onEdit(int offset, int length) {
		if (!dirtyFlag) {
			dirtyFlag = true;
			for (Runnable r : dirtyListeners) {
				try {
					r.run();
				} catch (Exception ignored) {
				}
			}
		}
		scheduleHighlight(offset, length);
	}

	private void scheduleHighlight(int offset, int length) {
		if (!highlightingEnabled || getLength() > MAX_HIGHLIGHT_SIZE) {
			return;
		}
		Element root = getDefaultRootElement();
		int p0 = root.getElementIndex(Math.max(0, Math.min(offset, getLength() - 1)));
		int p1 = root.getElementIndex(Math.max(0, Math.min(offset + Math.max(length, 1), getLength() - 1)));
		int startLine = Math.max(0, p0 - 1);
		int endLine = Math.min(root.getElementCount() - 1, p1 + 1);
		int start;
		int end;
		try {
			start = root.getElement(startLine).getStartOffset();
			end = root.getElement(endLine).getEndOffset();
		} catch (Exception e) {
			return;
		}
		pendingFrom = Math.min(pendingFrom, start);
		pendingTo = Math.max(pendingTo, end);
		if (highlightScheduled) {
			return;
		}
		highlightScheduled = true;
		// never mutate the document inside the notification: do it after the event
		SwingUtilities.invokeLater(this::runScheduledHighlight);
	}

	private void runScheduledHighlight() {
		highlightScheduled = false;
		int from = pendingFrom;
		int to = pendingTo;
		pendingFrom = Integer.MAX_VALUE;
		pendingTo = -1;
		if (from == Integer.MAX_VALUE || to < from) {
			return;
		}
		try {
			highlightBlock(from, to);
		} catch (BadLocationException | IllegalStateException ignored) {
			// document changed underneath us: the next edit will refresh
		}
	}

	// ------------------------------------------------------------ highlight

	public void highlightAll() {
		if (!highlightingEnabled || getLength() > MAX_HIGHLIGHT_SIZE) {
			return;
		}
		try {
			highlightBlock(0, getLength());
		} catch (BadLocationException | IllegalStateException ignored) {
		}
	}

	/** Re-tokenize a region, snapping to line boundaries. */
	public void highlightBlock(int from, int to) throws BadLocationException {
		if (to <= from) {
			return;
		}
		from = Math.max(0, from);
		to = Math.min(to, getLength());
		if (to <= from) {
			return;
		}
		int back = Math.min(from, 4000);
		String prev = getText(from - back, back);
		int nl = prev.lastIndexOf('\n');
		int blockStart = nl >= 0 ? from - back + nl + 1 : from;
		int fwd = Math.min(getLength() - to, 4000);
		String next = getText(to, fwd);
		int nl2 = next.indexOf('\n');
		int blockEnd = nl2 >= 0 ? to + nl2 + 1 : to;
		if (blockEnd > getLength()) {
			blockEnd = getLength();
		}
		if (blockEnd <= blockStart) {
			return;
		}
		Style base = getStyle("base");
		setCharacterAttributes(blockStart, blockEnd - blockStart, base, true);
		String block = getText(blockStart, blockEnd - blockStart);
		for (int[] t : JavaTokenizer.tokenize(block, blockStart, lang)) {
			int kind = t[0];
			int s = Math.max(blockStart, t[1]);
			int e = Math.min(blockEnd, t[2]);
			if (e <= s) {
				continue;
			}
			Style st = getStyle("s" + kind);
			if (st != null) {
				setCharacterAttributes(s, e - s, st, false);
			}
		}
	}
}