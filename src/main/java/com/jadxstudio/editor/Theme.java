package com.jadxstudio.editor;

import java.awt.Color;
import java.awt.Font;

/** Colour palettes for the code editors (dark by default, light as an alternative). */
public final class Theme {

	public enum Mode {
		DARK, LIGHT
	}

	private final Mode mode;
	private final Color background;
	private final Color foreground;
	private final Color gutterBg;
	private final Color gutterFg;
	private final Color plain;
	private final Color keyword;
	private final Color string;
	private final Color comment;
	private final Color number;
	private final Color annotation;
	private final Color type;
	private final Color preprocessor;
	private final Color attribute;
	private final Color descriptor;
	private final Color register;
	private final Color label;

	private Theme(Mode mode) {
		this.mode = mode;
		if (mode == Mode.DARK) {
			background = new Color(0x1E1E1E);
			foreground = new Color(0xE6E6E6);
			gutterBg = new Color(0x252526);
			gutterFg = new Color(0x858585);
			plain = foreground;
			keyword = new Color(0x569CD6);
			string = new Color(0xCE9178);
			comment = new Color(0x6A9955);
			number = new Color(0xB5CEA8);
			annotation = new Color(0xC586C0);
			type = new Color(0x4EC9B0);
			preprocessor = new Color(0xDCDCAA);
			attribute = new Color(0x9CDCFE);
			descriptor = new Color(0xDCDCAA);
			register = new Color(0x9CDCFE);
			label = new Color(0xD7BA7D);
		} else {
			background = new Color(0xFFFFFF);
			foreground = new Color(0x1F2328);
			gutterBg = new Color(0xF2F3F5);
			gutterFg = new Color(0x6E7681);
			plain = foreground;
			keyword = new Color(0x0033B3);
			string = new Color(0x067D17);
			comment = new Color(0x5A5A5A);
			number = new Color(0x098658);
			annotation = new Color(0x8F2FBF);
			type = new Color(0x00627A);
			preprocessor = new Color(0x9A6700);
			attribute = new Color(0x0451A5);
			descriptor = new Color(0x9A6700);
			register = new Color(0x0451A5);
			label = new Color(0x953800);
		}
	}

	private static Theme dark = new Theme(Mode.DARK);
	private static Theme light = new Theme(Mode.LIGHT);

	public static Theme get(Mode m) {
		return m == Mode.LIGHT ? light : dark;
	}

	public static Theme current() {
		return current;
	}

	private static Theme current = new Theme(Mode.DARK);

	public static void setMode(Mode m) {
		current = get(m);
	}

	public static Font codeFont(float size) {
		return new Font(Font.MONOSPACED, Font.BOLD, Math.round(size));
	}

	public Color forKind(int kind) {
		return switch (kind) {
			case JavaTokenizer.KW -> keyword;
			case JavaTokenizer.STR, JavaTokenizer.CHAR, JavaTokenizer.TPL -> string;
			case JavaTokenizer.CMT -> comment;
			case JavaTokenizer.NUM -> number;
			case JavaTokenizer.ANN -> annotation;
			case JavaTokenizer.TYPE -> type;
			case JavaTokenizer.PRE -> preprocessor;
			case JavaTokenizer.ATTR -> attribute;
			case JavaTokenizer.DESC -> descriptor;
			case JavaTokenizer.REG -> register;
			case JavaTokenizer.LABEL -> label;
			default -> plain;
		};
	}

	public boolean isBold(int kind) {
		return kind == JavaTokenizer.KW || kind == JavaTokenizer.PRE;
	}

	public boolean isItalic(int kind) {
		return kind == JavaTokenizer.CMT;
	}

	public Mode mode() {
		return mode;
	}

	public Color background() {
		return background;
	}

	public Color foreground() {
		return foreground;
	}

	public Color gutterBackground() {
		return gutterBg;
	}

	public Color gutterForeground() {
		return gutterFg;
	}
}