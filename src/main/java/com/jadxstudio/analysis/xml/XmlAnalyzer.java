package com.jadxstudio.analysis.xml;

import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NamedNodeMap;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

import javax.xml.parsers.DocumentBuilderFactory;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;

/**
 * Android XML framework:
 * <ul>
 * <li>decodes binary Android XML (AXML) into readable text</li>
 * <li>analyzes text XML (manifest/layout) for security-relevant findings</li>
 * <li>provides fallback manifest decoding for APK/AAB containers</li>
 * </ul>
 */
public final class XmlAnalyzer {

	private static final int RES_STRING_POOL_TYPE = 0x0001;
	private static final int RES_XML_TYPE = 0x0003;
	private static final int RES_XML_START_NAMESPACE = 0x0100;
	private static final int RES_XML_END_NAMESPACE = 0x0101;
	private static final int RES_XML_START_ELEMENT = 0x0102;
	private static final int RES_XML_END_ELEMENT = 0x0103;
	private static final int RES_XML_CDATA = 0x0104;
	private static final int UTF8_FLAG = 0x100;

	private static final Set<String> DANGEROUS_PERMS = Set.of(
			"android.permission.READ_SMS", "android.permission.RECEIVE_SMS",
			"android.permission.SEND_SMS", "android.permission.RECEIVE_MMS",
			"android.permission.READ_CONTACTS", "android.permission.WRITE_CONTACTS",
			"android.permission.GET_ACCOUNTS", "android.permission.READ_CALENDAR",
			"android.permission.WRITE_CALENDAR", "android.permission.READ_CALL_LOG",
			"android.permission.WRITE_CALL_LOG", "android.permission.CALL_PHONE",
			"android.permission.PROCESS_OUTGOING_CALLS", "android.permission.RECORD_AUDIO",
			"android.permission.CAMERA", "android.permission.BODY_SENSORS",
			"android.permission.ACTIVITY_RECOGNITION", "android.permission.READ_PHONE_STATE",
			"android.permission.READ_PHONE_NUMBERS", "android.permission.ANSWER_PHONE_CALLS",
			"android.permission.ACCESS_FINE_LOCATION", "android.permission.ACCESS_COARSE_LOCATION",
			"android.permission.ACCESS_BACKGROUND_LOCATION", "android.permission.READ_EXTERNAL_STORAGE",
			"android.permission.WRITE_EXTERNAL_STORAGE", "android.permission.MANAGE_EXTERNAL_STORAGE",
			"android.permission.REQUEST_INSTALL_PACKAGES", "android.permission.REQUEST_DELETE_PACKAGES",
			"android.permission.SYSTEM_ALERT_WINDOW", "android.permission.QUERY_ALL_PACKAGES",
			"android.permission.READ_MEDIA_IMAGES", "android.permission.READ_MEDIA_VIDEO",
			"android.permission.READ_MEDIA_AUDIO", "android.permission.POST_NOTIFICATIONS",
			"android.permission.BIND_ACCESSIBILITY_SERVICE", "android.permission.BIND_DEVICE_ADMIN",
			"android.permission.BIND_VPN_SERVICE", "android.permission.MOUNT_UNMOUNT_FILESYSTEMS");

	private XmlAnalyzer() {
	}

	// ------------------------------------------------------------- analyze

	/** Analyze any supported XML input: raw .xml, APK/ZIP container, AAB. */
	public static AxmlDoc analyze(Path path) throws IOException {
		byte[] data = Files.readAllBytes(path);
		String name = path.getFileName().toString().toLowerCase(Locale.ROOT);
		if (isZip(data)) {
			try (ZipFile zip = new ZipFile(path.toFile())) {
				ZipEntry manifest = zip.getEntry("AndroidManifest.xml");
				if (manifest == null) {
					AxmlDoc doc = new AxmlDoc();
					doc.findings.add("Archive contains no AndroidManifest.xml");
					listZipEntries(zip, doc);
					return doc;
				}
				byte[] mb = readEntry(zip, manifest);
				AxmlDoc doc = fromBytes(mb, "AndroidManifest.xml");
				listZipEntries(zip, doc);
				return doc;
			}
		}
		if (name.endsWith(".xml") || name.endsWith(".txt") || looksLikeTextXml(data)) {
			return fromBytes(data, path.getFileName().toString());
		}
		return fromBytes(data, path.getFileName().toString());
	}

	private static void listZipEntries(ZipFile zip, AxmlDoc doc) {
		int n = zip.size();
		doc.attributes.add("archive entries: " + n);
		int shown = 0;
		var entries = zip.entries();
		while (entries.hasMoreElements() && shown < 200) {
			ZipEntry e = entries.nextElement();
			doc.attributes.add("  " + e.getName() + "  (" + e.getSize() + " bytes)");
			shown++;
		}
	}

	private static AxmlDoc fromBytes(byte[] data, String name) {
		AxmlDoc doc = new AxmlDoc();
		if (data == null || data.length == 0) {
			doc.findings.add("Empty content for " + name);
			return doc;
		}
		if (isBinaryAxml(data)) {
			try {
				doc.xml = decodeAxml(data);
			} catch (Exception e) {
				doc.findings.add("Binary XML decode failed: " + e);
				doc.xml = "";
				return doc;
			}
			doc.attributes.add("format: binary Android XML (AXML), decoded to text");
		} else if (looksLikeTextXml(data)) {
			doc.xml = new String(data, StandardCharsets.UTF_8);
			doc.attributes.add("format: plain text XML");
		} else {
			doc.findings.add("Unknown XML format (possibly protobuf/XML from AAB) - raw dump below");
			doc.xml = new String(data, 0, Math.min(data.length, 4096), StandardCharsets.ISO_8859_1);
			return doc;
		}
		analyzeXmlText(doc);
		return doc;
	}

	/** Fallback used by Project when jadx could not provide the manifest. */
	public static String decodeManifestFallback(Path input) {
		try {
			byte[] data = Files.readAllBytes(input);
			if (isZip(data)) {
				try (ZipFile zip = new ZipFile(input.toFile())) {
					ZipEntry m = zip.getEntry("AndroidManifest.xml");
					if (m == null) {
						return "";
					}
					byte[] mb = readEntry(zip, m);
					return isBinaryAxml(mb) ? decodeAxml(mb) : new String(mb, StandardCharsets.UTF_8);
				}
			}
			if (isBinaryAxml(data)) {
				return decodeAxml(data);
			}
		} catch (Exception ignored) {
		}
		return "";
	}

	private static boolean isZip(byte[] d) {
		return d.length > 4 && d[0] == 'P' && d[1] == 'K' && (d[2] == 3 || d[2] == 5 || d[2] == 7);
	}

	private static boolean isBinaryAxml(byte[] d) {
		if (d.length < 8) {
			return false;
		}
		int type = (d[0] & 0xff) | ((d[1] & 0xff) << 8);
		return type == RES_XML_TYPE;
	}

	private static boolean looksLikeTextXml(byte[] d) {
		int i = 0;
		while (i < d.length && (d[i] == ' ' || d[i] == '\n' || d[i] == '\r' || d[i] == '\t' || d[i] == (byte) 0xef)) {
			i++;
		}
		return i < d.length && d[i] == '<';
	}

	private static byte[] readEntry(ZipFile zip, ZipEntry e) throws IOException {
		try (var in = zip.getInputStream(e)) {
			return in.readAllBytes();
		}
	}

	// ----------------------------------------------------- binary decoding

	public static String decodeAxml(byte[] data) {
		LittleEndian b = new LittleEndian(data);
		int type = b.u16(0);
		if (type != RES_XML_TYPE) {
			throw new IllegalArgumentException("not RES_XML_TYPE: 0x" + Integer.toHexString(type));
		}
		int fileHeader = b.u16(2);
		StringBuilder out = new StringBuilder();
		StringBuilder openTag = new StringBuilder();
		List<String[]> pendingNs = new ArrayList<>();
		java.util.Map<Integer, String> nsPrefixByUri = new java.util.HashMap<>();
		String pendingText = "";
		int depth = 0;
		int pos = fileHeader;
		while (pos + 8 <= data.length) {
			int ctype = b.u16(pos);
			int chs = b.u16(pos + 2);
			int csize = b.u32(pos + 4);
			if (csize < 8 || pos + csize > data.length) {
				break;
			}
			switch (ctype) {
				case RES_STRING_POOL_TYPE -> {
					// resolved lazily by str()
				}
				case RES_XML_START_NAMESPACE -> {
					int prefix = b.i32(pos + 16);
					int uri = b.i32(pos + 20);
					String p = str(b, pos, prefix);
					pendingNs.add(new String[] { p, str(b, pos, uri) });
					nsPrefixByUri.put(uri, p == null ? "" : p);
				}
				case RES_XML_END_NAMESPACE -> {
					int uri = b.i32(pos + 20);
					nsPrefixByUri.remove(uri);
				}
				case RES_XML_START_ELEMENT -> {
					closeOpenTag(out, openTag, false);
					int name = b.i32(pos + 20);
					// attrExt: ns@+16, name@+20, attributeStart@+24, attributeSize@+26, attributeCount@+28
					int attrStart = b.u16(pos + 24);
					int attrSize = b.u16(pos + 26);
					int attrCount = b.u16(pos + 28);
					indent(out, depth);
					openTag.append('<').append(str(b, pos, name));
					for (String[] ns : pendingNs) {
						openTag.append(" xmlns");
						if (ns[0] != null && !ns[0].isEmpty()) {
							openTag.append(':').append(ns[0]);
						}
						openTag.append("=\"").append(esc(ns[1])).append('"');
					}
					pendingNs.clear();
					int attrBase = pos + 16 + attrStart;
					for (int a = 0; a < attrCount; a++) {
						int ao = attrBase + a * attrSize;
						if (ao + 20 > data.length) {
							break;
						}
						int ans = b.i32(ao);
						int an = b.i32(ao + 4);
						int raw = b.i32(ao + 8);
						int dataType = b.u8(ao + 15);
						int dataVal = b.i32(ao + 16);
						String attrName = str(b, pos, an);
						if (ans >= 0) {
							String pfx = nsPrefixByUri.get(ans);
							if (pfx != null && !pfx.isEmpty()) {
								attrName = pfx + ":" + attrName;
							}
						}
						String val = raw >= 0 ? str(b, pos, raw) : typedValue(dataType, dataVal, b, pos);
						openTag.append(' ').append(attrName).append("=\"").append(esc(val)).append('"');
					}
					depth++;
				}
				case RES_XML_END_ELEMENT -> {
					if (openTag.length() > 0) {
						// element without children -> self closing
						closeOpenTag(out, openTag, true);
						depth = Math.max(0, depth - 1);
					} else {
						depth = Math.max(0, depth - 1);
						indent(out, depth);
						if (pendingText != null && !pendingText.isEmpty()) {
							out.append(esc(pendingText));
							pendingText = "";
						}
						out.append("</").append(str(b, pos, b.i32(pos + 20))).append('>');
					}
				}
				case RES_XML_CDATA -> {
					pendingText = str(b, pos, b.i32(pos + 16));
				}
				default -> {
				}
			}
			pos += csize;
		}
		closeOpenTag(out, openTag, true);
		return out.toString();
	}

	/**
	 * Flushes the buffered start tag. Empty elements are written self-closing
	 * ({@code <tag/>}) instead of an open/close pair.
	 */
	private static void closeOpenTag(StringBuilder out, StringBuilder openTag, boolean selfClose) {
		if (openTag.length() == 0) {
			return;
		}
		out.append(openTag).append(selfClose ? "/>" : ">");
		openTag.setLength(0);
	}

	/** Resolve a string reference for the pool nearest before chunk pos. */
	private static String str(LittleEndian b, int chunkPos, int idx) {
		if (idx < 0) {
			return "";
		}
		// find string pool: search backwards from chunk for a RES_STRING_POOL chunk,
		// but pools always appear before referencing chunks, so scan forward from file start
		int pos = 0;
		int fileHeader = b.u16(2);
		pos = fileHeader;
		String[] pool = null;
		while (pos + 8 <= b.data.length) {
			int type = b.u16(pos);
			int size = b.u32(pos + 4);
			if (size < 8 || pos + size > b.data.length) {
				break;
			}
			if (type == RES_STRING_POOL_TYPE) {
				if (pos > chunkPos) {
					break;
				}
				pool = parsePool(b, pos);
			}
			pos += size;
		}
		if (pool == null || idx >= pool.length) {
			return "";
		}
		return pool[idx];
	}

	private static String[] parsePool(LittleEndian b, int pos) {
		int stringCount = b.u32(pos + 8);
		int flags = b.u32(pos + 16);
		int stringsStart = b.u32(pos + 20);
		int headerSize = b.u16(pos + 2);
		if (stringCount > 200_000) {
			return new String[0];
		}
		String[] out = new String[stringCount];
		boolean utf8 = (flags & UTF8_FLAG) != 0;
		int entries = pos + Math.max(headerSize, 28);
		for (int i = 0; i < stringCount; i++) {
			int off = b.u32(entries + i * 4);
			int spos = pos + stringsStart + off;
			try {
				if (spos >= b.data.length) {
					out[i] = "";
					continue;
				}
				if (utf8) {
					int charLen = b.u8(spos);
					if ((charLen & 0x80) != 0) {
						charLen = ((charLen & 0x7f) << 8) | b.u8(spos + 1);
						spos += 2;
					} else {
						spos += 1;
					}
					int byteLen = b.u8(spos);
					if ((byteLen & 0x80) != 0) {
						byteLen = ((byteLen & 0x7f) << 8) | b.u8(spos + 1);
						spos += 2;
					} else {
						spos += 1;
					}
					if (spos + byteLen <= b.data.length) {
						out[i] = new String(b.data, spos, byteLen, StandardCharsets.UTF_8);
					} else {
						out[i] = "";
					}
				} else {
					int charLen = b.u16(spos);
					spos += 2;
					if ((charLen & 0x8000) != 0) {
						charLen = ((charLen & 0x7fff) << 16) | b.u16(spos);
						spos += 2;
					}
					if (spos + charLen * 2 <= b.data.length) {
						out[i] = new String(b.data, spos, charLen * 2, StandardCharsets.UTF_16LE);
					} else {
						out[i] = "";
					}
				}
			} catch (Exception e) {
				out[i] = "";
			}
		}
		return out;
	}

	private static final class LittleEndian {
		final byte[] data;

		LittleEndian(byte[] data) {
			this.data = data;
		}

		int u8(int i) {
			return i >= 0 && i < data.length ? data[i] & 0xff : 0;
		}

		int u16(int i) {
			return u8(i) | (u8(i + 1) << 8);
		}

		int u32(int i) {
			return (u8(i) | (u8(i + 1) << 8) | (u8(i + 2) << 16) | (u8(i + 3) << 24));
		}

		int i32(int i) {
			return u32(i);
		}
	}

	private static final String[] UNITS = { "", "px", "dip", "sp", "pt", "in", "mm" };

	private static String typedValue(int dataType, int data, LittleEndian b, int chunkPos) {
		return switch (dataType) {
			case 0x00 -> "";
			case 0x01 -> "@0x" + Integer.toHexString(data);
			case 0x02 -> "?0x" + Integer.toHexString(data);
			case 0x03 -> str(b, chunkPos, data);
			case 0x04 -> String.valueOf(Float.intBitsToFloat(data));
			case 0x05 -> {
				float v = complexToFloat(data);
				int unit = data & 0xf;
				yield v + (unit < UNITS.length ? UNITS[unit] : "");
			}
			case 0x06 -> complexToFloat(data) * 100 + "%";
			case 0x10 -> String.valueOf(data);
			case 0x11 -> "0x" + Integer.toHexString(data);
			case 0x12 -> data != 0 ? "true" : "false";
			case 0x1c, 0x1d, 0x1e, 0x1f -> String.format("#%08X", data);
			default -> "0x" + Integer.toHexString(data);
		};
	}

	private static float complexToFloat(int data) {
		float mantissa = data & 0xffffff00;
		mantissa *= RADIX_MULTS[(data >> 4) & 0x3];
		return mantissa / (1 << 8) * (float) Math.pow(2, ((data >> 4) & 0x3) * 8);
	}

	private static final float[] RADIX_MULTS = { 0.00390625f, 3.0517578E-5f, 1.1920929E-7f, 4.656613E-10f };

	private static void indent(StringBuilder sb, int depth) {
		sb.append('\n');
		for (int i = 0; i < depth; i++) {
			sb.append("  ");
		}
	}

	private static String esc(String s) {
		if (s == null) {
			return "";
		}
		return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace("\"", "&quot;");
	}

	// ----------------------------------------------------- text analysis

	public static void analyzeXmlText(AxmlDoc doc) {
		String xml = doc.xml;
		if (xml == null || xml.isBlank()) {
			doc.findings.add("No XML text to analyze");
			return;
		}
		Document dom;
		try {
			DocumentBuilderFactory f = DocumentBuilderFactory.newInstance();
			f.setNamespaceAware(true);
			try {
				f.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
				f.setFeature("http://xml.org/sax/features/external-general-entities", false);
				f.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
			} catch (Exception ignored) {
			}
			f.setXIncludeAware(false);
			f.setExpandEntityReferences(false);
			dom = f.newDocumentBuilder().parse(new ByteArrayInputStream(xml.getBytes(StandardCharsets.UTF_8)));
		} catch (Exception e) {
			doc.findings.add("XML parse warning: " + e.getMessage());
			// fall back to raw scanning
			rawScan(xml, doc);
			return;
		}
		Element root = dom.getDocumentElement();
		if (root == null) {
			doc.findings.add("Empty XML document");
			return;
		}
		if ("manifest".equals(local(root))) {
			analyzeManifest(root, doc);
		} else {
			analyzeGeneric(root, doc);
		}
		collectAttributes(root, doc, 0);
	}

	private static void analyzeManifest(Element root, AxmlDoc doc) {
		String pkg = attr(root, "package");
		if (pkg != null) {
			doc.findings.add("package: " + pkg);
		}
		String shared = attr(root, "sharedUserId");
		if (shared != null) {
			doc.findings.add("WARNING: sharedUserId declared: " + shared);
		}

		NodeList perms = root.getElementsByTagName("uses-permission");
		Set<String> all = new LinkedHashSet<>();
		for (int i = 0; i < perms.getLength(); i++) {
			String n = attr((Element) perms.item(i), "name");
			if (n != null) {
				all.add(n);
			}
		}
		NodeList permsSdk = root.getElementsByTagName("uses-permission-sdk-23");
		for (int i = 0; i < permsSdk.getLength(); i++) {
			String n = attr((Element) permsSdk.item(i), "name");
			if (n != null) {
				all.add(n);
			}
		}
		List<String> dangerous = new ArrayList<>();
		for (String p : all) {
			if (DANGEROUS_PERMS.contains(p)) {
				dangerous.add(p);
			}
		}
		doc.findings.add("declared permissions: " + all.size() + " (dangerous: " + dangerous.size() + ")");
		for (String d : dangerous) {
			doc.findings.add("DANGEROUS permission: " + d);
		}

		NodeList apps = root.getElementsByTagName("application");
		if (apps.getLength() > 0) {
			Element app = (Element) apps.item(0);
			checkAttr(doc, app, "debuggable", "true", "Application is DEBUGGABLE");
			checkAttr(doc, app, "allowBackup", "true", "allowBackup enabled (data can be backed up)");
			checkAttr(doc, app, "usesCleartextTraffic", "true", "cleartext traffic allowed");
			checkAttr(doc, app, "testOnly", "true", "testOnly application");
			String nsc = attr(app, "networkSecurityConfig");
			if (nsc != null) {
				doc.findings.add("networkSecurityConfig: " + nsc);
			}
			String agent = attr(app, "backupAgent");
			if (agent != null) {
				doc.findings.add("backupAgent: " + agent);
			}
		}

		String[] compTags = { "activity", "activity-alias", "service", "receiver", "provider" };
		int total = 0;
		int exportedNoPerm = 0;
		for (String tag : compTags) {
			NodeList list = root.getElementsByTagName(tag);
			for (int i = 0; i < list.getLength(); i++) {
				Element el = (Element) list.item(i);
				total++;
				String exported = attr(el, "exported");
				boolean hasFilter = el.getElementsByTagName("intent-filter").getLength() > 0;
				String perm = attr(el, "permission");
				boolean isExported = "true".equals(exported) || (exported == null && hasFilter);
				if (isExported && perm == null) {
					exportedNoPerm++;
					doc.findings.add("exported without permission: <" + tag + "> " + attr(el, "name")
							+ (hasFilter && exported == null ? " (implicit via intent-filter)" : ""));
				}
				if ("provider".equals(tag) && isExported) {
					String gp = attr(el, "grantUriPermissions");
					doc.findings.add("exported provider: " + attr(el, "name") + " grantUriPermissions=" + gp);
				}
			}
		}
		doc.findings.add("components: " + total + ", exported-without-permission: " + exportedNoPerm);

		NodeList sdk = root.getElementsByTagName("uses-sdk");
		if (sdk.getLength() > 0) {
			Element s = (Element) sdk.item(0);
			String minSdk = attr(s, "minSdkVersion");
			String targetSdk = attr(s, "targetSdkVersion");
			if (minSdk != null) {
				doc.findings.add("minSdkVersion: " + minSdk);
			}
			if (targetSdk != null) {
				doc.findings.add("targetSdkVersion: " + targetSdk);
				try {
					if (Integer.parseInt(targetSdk) < 23) {
						doc.findings.add("OUTDATED: targetSdkVersion < 23 (runtime permissions era)");
					}
				} catch (NumberFormatException ignored) {
				}
			}
		}
		NodeList feats = root.getElementsByTagName("uses-feature");
		doc.findings.add("uses-feature entries: " + feats.getLength());
	}

	private static void analyzeGeneric(Element root, AxmlDoc doc) {
		doc.findings.add("root element: <" + local(root) + "> (non-manifest XML)");
		NodeList all = root.getElementsByTagName("*");
		doc.findings.add("element count: " + (all.getLength() + 1));
		// heuristic: flag obvious risky values anywhere
		String text = root.getTextContent() == null ? "" : root.getTextContent();
		if (text.contains("http://")) {
			doc.findings.add("contains cleartext http:// reference");
		}
	}

	private static void rawScan(String xml, AxmlDoc doc) {
		if (xml.contains("android:debuggable=\"true\"")) {
			doc.findings.add("DEBUGGABLE application (raw scan)");
		}
		if (xml.contains("uses-permission")) {
			doc.findings.add("uses-permission entries present (raw scan, parse failed)");
		}
	}

	private static void collectAttributes(Element el, AxmlDoc doc, int depth) {
		if (doc.attributes.size() < 2000) {
			NamedNodeMap m = el.getAttributes();
			StringBuilder sb = new StringBuilder();
			sb.append("  ".repeat(Math.min(depth, 8))).append('<').append(local(el));
			for (int i = 0; i < m.getLength(); i++) {
				Node a = m.item(i);
				sb.append(' ').append(a.getNodeName()).append('=').append(a.getNodeValue());
			}
			sb.append('>');
			doc.attributes.add(sb.toString());
		}
		NodeList kids = el.getChildNodes();
		for (int i = 0; i < kids.getLength(); i++) {
			if (kids.item(i) instanceof Element e) {
				collectAttributes(e, doc, depth + 1);
			}
		}
	}

	private static void checkAttr(AxmlDoc doc, Element el, String name, String value, String message) {
		if (value.equals(attr(el, name))) {
			doc.findings.add("WARNING: " + message);
		}
	}

	private static String attr(Element el, String localName) {
		String v = el.getAttributeNS("http://schemas.android.com/apk/res/android", localName);
		if (v == null || v.isEmpty()) {
			v = el.getAttribute("android:" + localName);
		}
		if (v == null || v.isEmpty()) {
			v = el.getAttribute(localName);
		}
		return v == null || v.isEmpty() ? null : v;
	}

	private static String local(Element el) {
		String l = el.getLocalName();
		return l != null ? l : el.getTagName();
	}
}
