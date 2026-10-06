package com.jadxstudio.gui;

import com.jadxstudio.analysis.nativecode.NativeAnalysis;
import com.jadxstudio.analysis.nativecode.NativeModel;
import com.jadxstudio.analysis.so.ElfInfo;
import com.jadxstudio.analysis.so.SymbolInfo;
import com.jadxstudio.editor.CodeEditor;
import com.jadxstudio.editor.JavaTokenizer;
import com.jadxstudio.editor.Theme;
import com.jadxstudio.util.Ui;

import javax.swing.BorderFactory;
import javax.swing.JButton;
import javax.swing.JDialog;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JProgressBar;
import javax.swing.JScrollPane;
import javax.swing.JSplitPane;
import javax.swing.JTabbedPane;
import javax.swing.JTable;
import javax.swing.JTextArea;
import javax.swing.JTextField;
import javax.swing.JTree;
import javax.swing.ListSelectionModel;
import javax.swing.RowFilter;
import javax.swing.SwingWorker;
import javax.swing.table.AbstractTableModel;
import javax.swing.table.DefaultTableModel;
import javax.swing.tree.DefaultMutableTreeNode;
import java.awt.BorderLayout;
import java.awt.Dimension;
import java.awt.FlowLayout;
import java.awt.Frame;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Native library window: ELF overview, function list, assembly and C pseudocode.
 *
 * <p>
 * Assembly comes from radare2/rizin, C pseudocode from Ghidra headless (run on demand, cached).
 * Each function shows assembly and its C side by side so calls can be traced between the two.
 */
public class SoAnalysisDialog extends JDialog {

	private static final int MAX_INSNS = 6000;

	private final Path soPath;
	private NativeAnalysis analysis;
	private final JLabel status = new JLabel(" ");
	private final JProgressBar progress = new JProgressBar();
	private final JTabbedPane tabs = new JTabbedPane();
	private final DefaultTableModel funcModel = new DefaultTableModel(
			new Object[] { "Address", "Size", "Name", "Source" }, 0) {
		@Override
		public boolean isCellEditable(int r, int c) {
			return false;
		}
	};
	private final JTable funcTable = new JTable(funcModel);
	private final JTextField filter = new JTextField(14);
	private final CodeEditor asmEditor = new CodeEditor("", true, JavaTokenizer.Lang.ASM);
	private final CodeEditor cEditor = new CodeEditor("", true, JavaTokenizer.Lang.C);
	private final JTextArea xrefArea = new JTextArea();
	private final JTextArea overviewArea = new JTextArea();
	private final JTextArea stringsArea = new JTextArea();
	private final JTextArea findingsArea = new JTextArea();
	private final JTextArea hexArea = new JTextArea();
	private final Map<Long, String> funcByAddr = new LinkedHashMap<>();
	private byte[] rawBytes;
	private final JTree structureTree = new JTree(new DefaultMutableTreeNode("loading..."));
	private final javax.swing.table.TableRowSorter<javax.swing.table.TableModel> sorter =
			new javax.swing.table.TableRowSorter<>(funcModel);
	private List<NativeModel.Func> functions = List.of();

	public SoAnalysisDialog(Frame owner, Path soPath) {
		super(owner, "Native analysis - " + soPath.getFileName(), false);
		this.soPath = soPath;
		setSize(new Dimension(1400, 900));
		setLocationRelativeTo(owner);

		buildTabs();

		JPanel bottom = new JPanel(new BorderLayout(8, 0));
		progress.setVisible(false);
		progress.setStringPainted(true);
		progress.setPreferredSize(new Dimension(200, 16));
		bottom.add(status, BorderLayout.CENTER);
		JPanel right = new JPanel(new FlowLayout(FlowLayout.RIGHT, 6, 2));
		right.add(progress);
		bottom.add(right, BorderLayout.EAST);
		bottom.setBorder(BorderFactory.createEmptyBorder(2, 8, 4, 8));

		JPanel root = new JPanel(new BorderLayout());
		root.add(tabs, BorderLayout.CENTER);
		root.add(bottom, BorderLayout.SOUTH);
		setContentPane(root);

		loadAnalysis();
	}

	// ------------------------------------------------------------------ ui

	private void buildTabs() {
		Theme th = Theme.current();
		for (JTextArea a : List.of(overviewArea, stringsArea, findingsArea, hexArea)) {
			a.setEditable(false);
			a.setFont(new java.awt.Font(java.awt.Font.MONOSPACED, java.awt.Font.BOLD, 14));
			a.setBackground(th.background());
			a.setForeground(th.foreground());
			a.setCaretColor(th.foreground());
			a.setSelectionColor(th.background());
			a.setSelectedTextColor(th.forKind(com.jadxstudio.editor.JavaTokenizer.KW));
		}
		// double-click a string: show which code references it
		stringsArea.addMouseListener(new java.awt.event.MouseAdapter() {
			@Override
			public void mouseClicked(java.awt.event.MouseEvent e) {
				if (e.getClickCount() == 2 && analysis != null) {
					try {
						showStringXrefs(stringsArea.getLineEndOffset(
								stringsArea.viewToModel(new java.awt.Point(e.getX(), e.getY()))));
					} catch (javax.swing.text.BadLocationException ignored) {
					}
				}
			}
		});
		overviewArea.setText("Loading ELF structure...");
		tabs.addTab("Overview", new JScrollPane(overviewArea));
		tabs.addTab("Functions / Assembly / Pseudocode", functionsTab());
		tabs.addTab("Strings", new JScrollPane(stringsArea));
		tabs.addTab("Hex", new JScrollPane(hexArea));
		tabs.addTab("Findings", new JScrollPane(findingsArea));
		tabs.addTab("Structure", new JScrollPane(structureTree));
	}

	private JPanel functionsTab() {
		funcTable.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
		funcTable.setRowHeight(22);
		funcTable.setAutoCreateRowSorter(true);
		funcTable.getColumnModel().getColumn(0).setPreferredWidth(110);
		funcTable.getColumnModel().getColumn(2).setPreferredWidth(320);
		funcTable.setRowSorter(sorter);
		funcTable.getSelectionModel().addListSelectionListener(e -> {
			if (!e.getValueIsAdjusting()) {
				showSelectedFunction();
			}
		});
		filter.addActionListener(e -> applyFilter());
		// double-click a call/branch in the asm to jump to the target function
		asmEditor.addCaretListener(e -> {
		});
		asmEditor.getTextComponent().addMouseListener(new java.awt.event.MouseAdapter() {
			@Override
			public void mouseClicked(java.awt.event.MouseEvent e) {
				if (e.getClickCount() == 2) {
					jumpToCallTarget();
				}
			}
		});
		cEditor.getTextComponent().addMouseListener(new java.awt.event.MouseAdapter() {
			@Override
			public void mouseClicked(java.awt.event.MouseEvent e) {
				if (e.getClickCount() == 2) {
					jumpToCallTarget();
				}
			}
		});

		JPanel top = new JPanel(new FlowLayout(FlowLayout.LEFT, 6, 4));
		top.add(new JLabel("Function filter:"));
		top.add(filter);
		JButton decomp = new JButton("Generate C pseudocode (Ghidra)");
		decomp.addActionListener(e -> runPseudocode());
		top.add(decomp);
		JButton reload = new JButton("Reload functions");
		reload.addActionListener(e -> loadFunctions());
		top.add(reload);
		JButton jump = new JButton("Jump to addr...");
		jump.addActionListener(e -> jumpToAddress());
		top.add(jump);
		JButton export = new JButton("Export asm + C to folder...");
		export.addActionListener(e -> exportAll());
		top.add(export);

		JScrollPane listScroll = new JScrollPane(funcTable);
		listScroll.setBorder(BorderFactory.createTitledBorder("Functions (click to disassemble)"));

		JSplitPane codeSplit = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT,
				titled(asmEditor, "Assembly (radare2/rizin)"), titled(cEditor, "C pseudocode (Ghidra)"));
		codeSplit.setResizeWeight(0.5);

		JPanel right = new JPanel(new BorderLayout());
		right.add(codeSplit, BorderLayout.CENTER);
		Theme xth = Theme.current();
		xrefArea.setEditable(false);
		xrefArea.setFont(new java.awt.Font(java.awt.Font.MONOSPACED, java.awt.Font.BOLD, 13));
		xrefArea.setBackground(xth.background());
		xrefArea.setForeground(xth.foreground());
		xrefArea.setCaretColor(xth.foreground());
		JScrollPane xrefs = new JScrollPane(xrefArea);
		xrefs.setBorder(BorderFactory.createTitledBorder("References to this address"));
		xrefs.setPreferredSize(new Dimension(100, 110));
		right.add(xrefs, BorderLayout.SOUTH);

		JSplitPane split = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT, listScroll, right);
		split.setDividerLocation(430);
		split.setResizeWeight(0.0);

		JPanel p = new JPanel(new BorderLayout());
		p.add(top, BorderLayout.NORTH);
		p.add(split, BorderLayout.CENTER);
		return p;
	}

	private JPanel titled(CodeEditor ed, String title) {
		JPanel p = new JPanel(new BorderLayout());
		p.setBorder(BorderFactory.createTitledBorder(title));
		p.add(ed, BorderLayout.CENTER);
		return p;
	}

	// --------------------------------------------------------------- load

	private void loadAnalysis() {
		status("Reading ELF structure...");
		NativeAnalysis a;
		try {
			a = new NativeAnalysis(soPath);
		} catch (Exception e) {
			Ui.error(this, "Analysis failed: " + e.getMessage());
			return;
		}
		analysis = a;
		ElfInfo elf = a.elf();

		overviewArea.setText(overviewText(a));
		overviewArea.setCaretPosition(0);
		structureTree.setModel(new javax.swing.tree.DefaultTreeModel(structureRoot(a)));
		for (int i = 0; i < structureTree.getRowCount(); i++) {
			structureTree.expandRow(i);
		}
		stringsArea.setText(stringsText(elf));
		stringsArea.setCaretPosition(0);
		try {
			rawBytes = Files.readAllBytes(soPath);
		} catch (Exception e) {
			rawBytes = new byte[0];
		}
		hexArea.setText(hexText());
		hexArea.setCaretPosition(0);
		findingsArea.setText(findingsText(a));
		findingsArea.setCaretPosition(0);
		status(a.statusText().replace('\n', ' ').trim());
		loadFunctions();
	}

	private void loadFunctions() {
		if (analysis == null) {
			return;
		}
		showProgress(true);
		status("Building function list...");
		new SwingWorker<List<NativeModel.Func>, Void>() {
			private List<String> log = new ArrayList<>();

			@Override
			protected List<NativeModel.Func> doInBackground() {
				return analysis.functions(m -> log.add(m));
			}

			@Override
			protected void done() {
				showProgress(false);
				try {
					functions = get();
					funcModel.setRowCount(0);
					funcByAddr.clear();
					for (NativeModel.Func f : functions) {
						funcByAddr.put(f.addr(), f.name());
						funcModel.addRow(new Object[] { NativeModel.hex(f.addr()), f.size(), f.name(), f.source() });
					}
					applyFilter();
					status(functions.size() + " functions" + (log.isEmpty() ? "" : " (" + log + ")"));
					if (!functions.isEmpty() && funcTable.getRowCount() > 0) {
						funcTable.setRowSelectionInterval(0, 0);
					}
				} catch (Exception e) {
					Ui.error(SoAnalysisDialog.this, "Function list failed: " + e.getMessage());
					status("Function list failed");
				}
			}
		}.execute();
	}

	private void applyFilter() {
		String q = filter.getText();
		if (q == null || q.isBlank()) {
			sorter.setRowFilter(null);
			return;
		}
		String pattern = "(?i)" + java.util.regex.Pattern.quote(q.trim());
		sorter.setRowFilter(RowFilter.regexFilter(pattern, 2));
	}

	private void showSelectedFunction() {
		int row = funcTable.getSelectedRow();
		if (row < 0 || analysis == null) {
			return;
		}
		int modelRow = funcTable.convertRowIndexToModel(row);
		Object addrObj = funcModel.getValueAt(modelRow, 0);
		long addr = Long.parseLong(String.valueOf(addrObj).substring(2), 16);
		String name = String.valueOf(funcModel.getValueAt(modelRow, 2));
		status("Disassembling " + name + " ...");
		showProgress(true);
		new SwingWorker<List<NativeModel.Insn>, Void>() {
			@Override
			protected List<NativeModel.Insn> doInBackground() {
				return analysis.assembly(addr, MAX_INSNS, m -> {
				});
			}

			@Override
			protected void done() {
				showProgress(false);
				try {
					List<NativeModel.Insn> insns = get();
					asmEditor.setText(renderAsm(insns, name, addr));
				} catch (Exception e) {
					asmEditor.setText("// disassembly failed: " + e.getMessage());
				}
				String pc = analysis.pseudocode(addr);
				cEditor.setText(pc.isBlank()
						? "// No C pseudocode for this function yet.\n"
								+ "// Click \"Generate C pseudocode (Ghidra)\" to run a Ghidra analysis of this library."
						: pc);
				xrefArea.setText(String.join("\n", analysis.xrefsTo(addr, m -> {
				})));
				xrefArea.setCaretPosition(0);
				status(name + " - " + insnsCount(asmEditor.getText()) + " instructions");
			}
		}.execute();
	}

	private static int insnsCount(String text) {
		int n = 0;
		for (String l : text.split("\n")) {
			if (l.contains("0x")) {
				n++;
			}
		}
		return n;
	}

	private String renderAsm(List<NativeModel.Insn> insns, String funcName, long funcAddr) {
		StringBuilder sb = new StringBuilder();
		sb.append("; ").append(funcName).append(" @ ").append(NativeModel.hex(funcAddr))
				.append(" (").append(insns.size()).append(" instructions)\n");
		sb.append("; source: ").append(analysis.disasm() == null ? "n/a"
				: analysis.disasm().toolName() + " " + analysis.disasm().version()).append("\n\n");
		for (NativeModel.Insn in : insns) {
			sb.append(String.format("%-10s %-30s %s", NativeModel.hex(in.addr()),
					in.bytes() == null ? "" : in.bytes(), in.text()));
			if (in.comment() != null && !in.comment().isBlank()) {
				sb.append("   ; ").append(in.comment());
			}
			sb.append('\n');
		}
		if (insns.isEmpty()) {
			sb.append("; no instructions decoded (backend unavailable or address not executable)\n");
		}
		return sb.toString();
	}

	private void runPseudocode() {
		if (analysis == null) {
			return;
		}
		if (analysis.hasGhidraResults()) {
			Ui.info(this, "Pseudocode already available for this library.");
			showSelectedFunction();
			return;
		}
		int yes = JOptionPane.showConfirmDialog(this,
				"Run Ghidra headless analysis of this library?\n"
						+ "It can take a few seconds to minutes depending on size.\n"
						+ "Results are cached for next time.",
				"Generate pseudocode", JOptionPane.OK_CANCEL_OPTION, JOptionPane.QUESTION_MESSAGE);
		if (yes != JOptionPane.OK_OPTION) {
			return;
		}
		showProgress(true);
		status("Ghidra analysis starting...");
		analysis.analyzePseudocodeAsync(
				this::status,
				() -> {
					showProgress(false);
					status("Pseudocode ready - reloading functions");
					loadFunctions();
					showSelectedFunction();
				},
				err -> {
					showProgress(false);
					Ui.error(this, "Ghidra analysis failed: " + err);
					status("Ghidra analysis failed");
				});
	}

	/** Ask the disassembler which instructions/strings reference a value. */
	private List<String> findStringReferences(String value) {
		if (analysis == null || analysis.disasm() == null) {
			return List.of();
		}
		try {
			return analysis.disasm().stringXrefs(soPath, value);
		} catch (Exception e) {
			return List.of("xref lookup failed: " + e.getMessage());
		}
	}

	// --------------------------------------------------------------- text

	private String overviewText(NativeAnalysis a) {
		ElfInfo elf = a.elf();
		StringBuilder sb = new StringBuilder(elf.headerText());
		sb.append("\n--- backends ---\n").append(a.statusText());
		String info = a.ghidraProgramInfo();
		if (!info.isBlank()) {
			sb.append("\n--- ghidra program ---\n").append(info);
		}
		sb.append("\n--- symbols (").append(elf.symbols.size()).append(") ---\n");
		int n = 0;
		for (SymbolInfo s : elf.symbols) {
			if (n++ > 120) {
				sb.append("...\n");
				break;
			}
			sb.append(String.format("%-50s %s%n", s.name, s.imported ? "[import]" : "[export]"));
		}
		return sb.toString();
	}

	private DefaultMutableTreeNode structureRoot(NativeAnalysis a) {
		ElfInfo elf = a.elf();
		DefaultMutableTreeNode root = new DefaultMutableTreeNode(soPath.getFileName().toString());
		DefaultMutableTreeNode head = new DefaultMutableTreeNode("Header");
		head.add(new DefaultMutableTreeNode("Class: " + elf.header.classHeader));
		head.add(new DefaultMutableTreeNode("Data: " + elf.header.data));
		head.add(new DefaultMutableTreeNode("Type: " + elf.header.type));
		head.add(new DefaultMutableTreeNode("Machine: " + elf.header.machine));
		head.add(new DefaultMutableTreeNode("Entry point: " + NativeModel.hex(elf.header.entry)));
		root.add(head);

		DefaultMutableTreeNode secs = new DefaultMutableTreeNode("Sections");
		for (ElfInfo.Section s : elf.sections) {
			secs.add(new DefaultMutableTreeNode(String.format("%-20s %-10s size=0x%x addr=%s", s.name, s.typeName,
					s.size, NativeModel.hex(s.addr))));
		}
		root.add(secs);

		DefaultMutableTreeNode segs = new DefaultMutableTreeNode("Segments");
		for (ElfInfo.Segment s : elf.segments) {
			segs.add(new DefaultMutableTreeNode(String.format("%-14s off=0x%x vaddr=%s filesz=0x%x memsz=0x%x",
					s.typeName, s.offset, NativeModel.hex(s.vaddr), s.filesz, s.memsz)));
		}
		root.add(segs);
		return root;
	}

	private String stringsText(ElfInfo elf) {
		StringBuilder sb = new StringBuilder();
		for (String s : elf.strings) {
			sb.append(s).append('\n');
		}
		return sb.toString();
	}

	private String findingsText(NativeAnalysis a) {
		StringBuilder sb = new StringBuilder();
		ElfInfo elf = a.elf();
		for (String f : elf.findings) {
			sb.append(" - ").append(f).append('\n');
		}
		if (elf.findings.isEmpty()) {
			sb.append("No ELF-level findings (heuristic scan).\n");
		}
		return sb.toString();
	}

	// ------------------------------------------------------------ RE helpers

	/** Hex + ASCII dump of the whole library (offset / bytes / printable). */
	private String hexText() {
		if (rawBytes == null) {
			return "(no raw data)";
		}
		StringBuilder sb = new StringBuilder();
		sb.append("size: ").append(rawBytes.length).append(" bytes\n\n");
		for (int off = 0; off < rawBytes.length; off += 16) {
			sb.append(String.format("%08x  ", off));
			StringBuilder ascii = new StringBuilder();
			for (int i = 0; i < 16; i++) {
				if (off + i < rawBytes.length) {
					int b = rawBytes[off + i] & 0xff;
					sb.append(String.format("%02x ", b));
					ascii.append(b >= 0x20 && b < 0x7f ? (char) b : '.');
				} else {
					sb.append("   ");
				}
				if (i == 7) {
					sb.append(' ');
				}
			}
			sb.append(' ').append(ascii).append('\n');
		}
		return sb.toString();
	}

	private static int firstOf(String s, char... chars) {
		int best = -1;
		for (char c : chars) {
			int i = s.indexOf(c);
			if (i >= 0 && (best < 0 || i < best)) {
				best = i;
			}
		}
		return best;
	}

	/** Resolve the call/branch under the caret in the asm or C pane and select that function. */
	private void jumpToCallTarget() {
		String target = null;
		for (CodeEditor ed : List.of(asmEditor, cEditor)) {
			String line = currentLine(ed);
			if (line == null) {
				continue;
			}
			String t = extractCallTarget(line);
			if (t != null) {
				target = t;
				break;
			}
		}
		if (target == null) {
			Ui.info(this, "No call/branch target under the caret.");
			return;
		}
		// exact address?
		try {
			long addr = target.startsWith("0x") ? Long.parseLong(target.substring(2), 16) : -1;
			if (addr > 0 && selectFunction(addr)) {
				return;
			}
		} catch (NumberFormatException ignored) {
		}
		// symbol name (may carry a leading module:: or sym. prefix)
		String needle = target;
		int ix = needle.indexOf("::");
		if (ix >= 0) {
			needle = needle.substring(ix + 2);
		}
		for (var e : funcByAddr.entrySet()) {
			String n = e.getValue();
			if (n.equals(target) || n.equals(needle) || n.endsWith("." + needle) || n.endsWith(needle)) {
				selectFunction(e.getKey());
				return;
			}
		}
		for (int i = 0; i < funcModel.getRowCount(); i++) {
			String name = String.valueOf(funcModel.getValueAt(i, 2));
			if (name.contains(needle)) {
				funcTable.setRowSelectionInterval(i, i);
				funcTable.scrollRectToVisible(funcTable.getCellRect(i, 0, true));
				status("jumped to " + name);
				return;
			}
		}
		Ui.info(this, "No function matches '" + target + "'");
	}

	private String currentLine(CodeEditor ed) {
		try {
			String text = ed.getText();
			int off = Math.max(0, Math.min(ed.getCaretOffset(), text.length()));
			int start = text.lastIndexOf('\n', off - 1) + 1;
			int end = text.indexOf('\n', off);
			if (end < 0) {
				end = text.length();
			}
			return text.substring(start, end);
		} catch (Exception e) {
			return null;
		}
	}

	/** Pull the target out of asm (bl/ b/ call/jmp) or C (NAME(); / NAME(&) lines). */
	private static String extractCallTarget(String line) {
		String[] asmOps = { "bl", "blx", "b", "bx", "call", "jmp", "je", "jne", "ja", "jb", "jl", "jg",
				"bne", "beq", "cbz", "cbnz", "b.eq", "b.ne" };
		for (String op : asmOps) {
			int idx = line.indexOf(op + " ");
			if (idx >= 0) {
				String rest = line.substring(idx + op.length() + 1).trim();
				int cut = firstOf(rest, ' ', ',', ';', ')');
				if (cut > 0) {
					rest = rest.substring(0, cut);
				}
				if (!rest.isEmpty()) {
					return rest;
				}
			}
		}
		// C-style: "foo(...)" or "foo(" at the start after a return/statement
		int par = line.indexOf('(');
		if (par > 0) {
			String head = line.substring(0, par).trim();
			int sp = head.lastIndexOf(' ');
			String name = (sp >= 0 ? head.substring(sp + 1) : head).trim();
			if (name.matches("[A-Za-z_][A-Za-z0-9_:.\\/]*")) {
				return name;
			}
		}
		return null;
	}

	private boolean selectFunction(long addr) {
		for (int i = 0; i < funcModel.getRowCount(); i++) {
			String a = String.valueOf(funcModel.getValueAt(i, 0));
			if (a.equals(NativeModel.hex(addr))) {
				funcTable.setRowSelectionInterval(i, i);
				funcTable.scrollRectToVisible(funcTable.getCellRect(i, 0, true));
				status("jumped to " + funcModel.getValueAt(i, 2));
				return true;
			}
		}
		return false;
	}

	private void jumpToAddress() {
		String q = JOptionPane.showInputDialog(this, "Jump to function address (hex):",
				"0x" + Long.toHexString(funcByAddr.isEmpty() ? 0 : funcByAddr.keySet().iterator().next()));
		if (q == null) {
			return;
		}
		q = q.trim().toLowerCase().replace("#", "");
		long addr;
		try {
			addr = q.startsWith("0x") ? Long.parseLong(q.substring(2), 16) : Long.parseLong(q);
		} catch (NumberFormatException e) {
			Ui.error(this, "Not a hex address: " + q);
			return;
		}
		if (!selectFunction(addr)) {
			// not a known function: disassemble at that address instead
			tabs.setSelectedIndex(1);
			showProgress(true);
			new SwingWorker<List<NativeModel.Insn>, Void>() {
				@Override
				protected List<NativeModel.Insn> doInBackground() {
					return analysis.assembly(addr, 400, m -> {
					});
				}

				@Override
				protected void done() {
					showProgress(false);
					try {
						asmEditor.setText(renderAsm(get(), NativeModel.hex(addr), addr));
						status("disassembled " + NativeModel.hex(addr));
					} catch (Exception e) {
						asmEditor.setText("// failed: " + e.getMessage());
					}
				}
			}.execute();
		}
	}

	/** Which code references this string (radare2 cross references). */
	private void showStringXrefs(int modelOffset) {
		try {
			String line = lineOf(stringsArea.getText(), modelOffset);
			if (line == null || line.isBlank()) {
				return;
			}
			status("references for: " + line);
			new SwingWorker<List<String>, Void>() {
				@Override
				protected List<String> doInBackground() {
					return findStringReferences(line);
				}

				@Override
				protected void done() {
					try {
						List<String> refs = get();
						xrefArea.setText(String.join("\n", refs));
						xrefArea.setCaretPosition(0);
						if (refs.isEmpty()) {
							Ui.info(SoAnalysisDialog.this, "No references found (needs r2 analysis).");
						}
					} catch (Exception e) {
						Ui.error(SoAnalysisDialog.this, "xref lookup failed: " + e.getMessage());
					}
				}
			}.execute();
		} catch (Exception e) {
			status("string xref: " + e.getMessage());
		}
	}

	private static String lineOf(String text, int offset) {
		int start = text.lastIndexOf('\n', Math.max(0, offset - 1)) + 1;
		int end = text.indexOf('\n', offset);
		if (end < 0) {
			end = text.length();
		}
		return text.substring(start, end);
	}

	/** Export the whole analysis (functions, assembly, C) to a folder. */
	private void exportAll() {
		javax.swing.JFileChooser fc = new javax.swing.JFileChooser();
		fc.setDialogTitle("Export assembly + pseudocode");
		fc.setFileSelectionMode(javax.swing.JFileChooser.DIRECTORIES_ONLY);
		if (fc.showSaveDialog(this) != javax.swing.JFileChooser.APPROVE_OPTION) {
			return;
		}
		java.nio.file.Path dir = fc.getSelectedFile().toPath();
		showProgress(true);
		status("exporting...");
		new SwingWorker<Integer, String>() {
			@Override
			protected Integer doInBackground() {
				int n = 0;
				try {
					java.nio.file.Path asmDir = dir.resolve("asm");
					java.nio.file.Path cDir = dir.resolve("pseudocode");
					java.nio.file.Files.createDirectories(asmDir);
					java.nio.file.Files.createDirectories(cDir);
					List<NativeModel.Func> all = analysis.functions(m -> {
					});
					java.util.List<String> index = new ArrayList<>();
					for (int i = 0; i < all.size(); i++) {
						NativeModel.Func f = all.get(i);
						if (i % 3 == 0) {
							int pct = (int) (100L * (i + 1) / Math.max(1, all.size()));
							publish(pct + " (" + (i + 1) + "/" + all.size() + ")");
						}
						String safe = f.name().replaceAll("[^A-Za-z0-9_.]", "_");
						String a = renderAsm(analysis.assembly(f.addr(), MAX_INSNS, m -> {
						}), f.name(), f.addr());
						java.nio.file.Files.writeString(asmDir.resolve(f.addr() + "_" + safe + ".asm"), a);
						String c = analysis.pseudocode(f.addr());
						if (!c.isBlank()) {
							java.nio.file.Files.writeString(cDir.resolve(f.addr() + "_" + safe + ".c"), c);
						}
						index.add(NativeModel.hex(f.addr()) + "\t" + f.size() + "\t" + f.name());
						n++;
					}
					java.nio.file.Files.writeString(dir.resolve("functions.tsv"), String.join("\n", index));
					java.nio.file.Files.writeString(dir.resolve("report.txt"), statusText());
				} catch (Exception e) {
					throw new RuntimeException(e);
				}
				return n;
			}

			@Override
			protected void done() {
				showProgress(false);
				try {
					Ui.info(SoAnalysisDialog.this, "Exported " + get() + " functions to " + dir);
					status("export complete");
				} catch (Exception e) {
					Throwable c = e.getCause() != null ? e.getCause() : e;
					Ui.error(SoAnalysisDialog.this, "export failed: " + c.getMessage());
				}
			}
		}.execute();
	}

	private String statusText() {
		return analysis == null ? "" : analysis.statusText();
	}

	private static JTextArea textArea(String s) {
		JTextArea ta = new JTextArea(s);
		ta.setEditable(false);
		ta.setFont(Ui.MONO);
		ta.setCaretPosition(0);
		return ta;
	}

	private void status(String s) {
		status.setText(s);
	}

	private void showProgress(boolean v) {
		progress.setIndeterminate(v);
		progress.setVisible(v);
	}
}