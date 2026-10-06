package com.jadxstudio.editor;

import javax.swing.text.AbstractDocument;
import javax.swing.text.EditorKit;
import javax.swing.text.View;
import javax.swing.text.ViewFactory;
import javax.swing.text.Element;
import javax.swing.text.StyledEditorKit;
import javax.swing.text.ViewFactory;
import javax.swing.text.BoxView;
import javax.swing.text.ComponentView;
import javax.swing.text.IconView;
import javax.swing.text.LabelView;
import javax.swing.text.ParagraphView;
import javax.swing.text.ZoneView;
import java.awt.Color;

/** EditorKit for plain Java text with syntax highlighting via {@link CodeDocument}. */
public class JavaSyntaxKit extends StyledEditorKit {

	@Override
	public String getContentType() {
		return "text/x-java";
	}

	@Override
	public javax.swing.text.Document createDefaultDocument() {
		return new CodeDocument();
	}

	@Override
	public ViewFactory getViewFactory() {
		return new JavaViewFactory();
	}

	static class JavaViewFactory implements ViewFactory {
		@Override
		public View create(Element elem) {
			String kind = elem.getName();
			if (kind.equals(AbstractDocument.ContentElementName)) {
				return new LabelView(elem);
			}
			if (kind.equals(AbstractDocument.ParagraphElementName)) {
				return new ParagraphView(elem);
			}
			if (kind.equals(AbstractDocument.SectionElementName)) {
				return new BoxView(elem, View.Y_AXIS);
			}
			if (kind.equals(javax.swing.text.StyleConstants.ComponentElementName)) {
				return new ComponentView(elem);
			}
			if (kind.equals(javax.swing.text.StyleConstants.IconElementName)) {
				return new IconView(elem);
			}
			return new LabelView(elem);
		}
	}
}
