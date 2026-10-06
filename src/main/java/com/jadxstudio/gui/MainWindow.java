package com.jadxstudio.gui;

import com.jadxstudio.core.CodeHolder;
import com.jadxstudio.core.DecompileTarget;
import com.jadxstudio.core.ExportOptions;
import com.jadxstudio.core.JavaIndex;
import com.jadxstudio.core.Progress;
import com.jadxstudio.core.Project;
import com.jadxstudio.editor.CodeEditor;
import com.jadxstudio.editor.JavaTokenizer;
import com.jadxstudio.editor.Theme;
import com.jadxstudio.editor.CodeTabs;
import com.jadxstudio.util.Ui;

import javax.swing.BorderFactory;
import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JFileChooser;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JMenu;
import javax.swing.JMenuBar;
import javax.swing.JMenuItem;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JProgressBar;
import javax.swing.JScrollPane;
import javax.swing.JSplitPane;
import javax.swing.JTabbedPane;
import javax.swing.JTextField;
import javax.swing.JToolBar;
import javax.swing.JTree;
import javax.swing.KeyStroke;
import javax.swing.SwingWorker;
import javax.swing.WindowConstants;
import javax.swing.filechooser.FileNameExtensionFilter;
import javax.swing.tree.DefaultMutableTreeNode;
import javax.swing.tree.DefaultTreeCellRenderer;
import javax.swing.tree.DefaultTreeModel;
import javax.swing.tree.TreePath;
import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.Component;
import java.awt.Dimension;
import java.awt.event.InputEvent;
import java.awt.event.KeyEvent;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

/**
 * Main application window: package/class browser, editor tabs with
 * Java/Split view, search, deobfuscation, resource viewer, analysis tools.
 */
public class MainWindow extends JFrame {

	private final transient Project project;
	private final JavaIndex index = new JavaIndex();
	private final CodeTabs tabs = new CodeTabs();

	private final JTree packageTree = new JTree();
	private final DefaultMutableTreeNode treeRoot = new DefaultMutableTreeNode("No file loaded");
	private final JTextField searchField = new JTextField(18);
	private final JLabel statusLeft = new JLabel("Ready");
	private final JLabel statusRight = new JLabel(" ");
	private final JProgressBar progress = new JProgressBar();
	private final OutlineList outline = new OutlineList();
	private final JCheckBox modeJava = new JCheckBox("Java");
	private final JCheckBox modeSmali = new JCheckBox("Smali");
	private final JCheckBox modeSplit = new JCheckBox("Split");
	private final javax.swing.JComboBox<Project.SearchMode> searchMode =
			new javax.swing.JComboBox<>(Project.SearchMode.values());
	private final JCheckBox searchCase = new JCheckBox("Aa");

	private Map<String, CodeHolder> sourceMap = Map.of();
	private List<String> resourcePaths = List.of();
	private DecompileTarget target = DecompileTarget.JAVA;

	private final List<String> backStack = new ArrayList<>();
	private final List<String> forwardStack = new ArrayList<>();

	public MainWindow(Project project) {
		super("JADX Studio - best-effort decompiler");
		this.project = project;
		buildUi();
	}

	// ------------------------------------------------------------------ UI

	private void buildUi() {
		setDefaultCloseOperation(WindowConstants.DO_NOTHING_ON_CLOSE);
		addWindowListener(new java.awt.event.WindowAdapter() {
			@Override
			public void windowClosing(java.awt.event.WindowEvent e) {
				onExit();
			}
		});
		setPreferredSize(new Dimension(1440, 900));
		setJMenuBar(buildMenu());

		JPanel top = new JPanel(new BorderLayout());
		top.add(buildToolbar(), BorderLayout.CENTER);
		JPanel banner = new JPanel(new BorderLayout());
		banner.setBackground(new Color(0xFFF4CE));
		banner.setBorder(BorderFactory.createCompoundBorder(
				BorderFactory.createMatteBorder(0, 0, 1, 0, new Color(0xE6B94D)),
				BorderFactory.createEmptyBorder(4, 10, 4, 10)));
		JLabel bl = new JLabel(
				"<html><b>Best effort:</b> decompiled Java may be wrong or incomplete - verify against Smali (Split view) and reported errors.</html>");
		bl.setForeground(new Color(0x5C4400));
		banner.add(bl, BorderLayout.CENTER);
		JButton dismiss = new JButton("x");
		dismiss.addActionListener(e -> banner.setVisible(false));
		banner.add(dismiss, BorderLayout.EAST);
		top.add(banner, BorderLayout.NORTH);

		JSplitPane leftSplit = new JSplitPane(JSplitPane.VERTICAL_SPLIT, treePanel(), outlinePanel());
		leftSplit.setResizeWeight(0.66);
		leftSplit.setDividerLocation(560);

		JSplitPane main = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT, leftSplit, tabs);
		main.setDividerLocation(300);

		progress.setVisible(false);
		progress.setStringPainted(true);
		progress.setPreferredSize(new Dimension(190, 18));
		progress.setPreferredSize(new Dimension(160, 18));
		JPanel statusBar = CodeTabs.statusBar(statusLeft, statusRight);
		statusBar.add(progress, BorderLayout.EAST);

		setLayout(new BorderLayout());
		add(top, BorderLayout.NORTH);
		add(main, BorderLayout.CENTER);
		add(statusBar, BorderLayout.SOUTH);
		tabs.setOnSelection(k -> updateStatusForTab());
		pack();
		setLocationRelativeTo(null);
	}

	private JPanel treePanel() {
		packageTree.setFont(Ui.TREE);
		packageTree.setShowsRootHandles(true);
		// without this the tree shows Swing's default "Tree" placeholder and nothing opens
		packageTree.setModel(new DefaultTreeModel(treeRoot));
		packageTree.setCellRenderer(new DefaultTreeCellRenderer() {
			@Override
			public Component getTreeCellRendererComponent(JTree t, Object v, boolean s, boolean e, boolean leaf,
					int row, boolean f) {
				super.getTreeCellRendererComponent(t, v, s, e, leaf, row, f);
				if (v instanceof DefaultMutableTreeNode n && n.getUserObject() instanceof NodeData nd) {
					if (nd.icon != null) {
						setIcon(nd.icon);
					}
					String txt = nd.label;
					if (nd.mark != null && !nd.mark.isBlank()) {
						txt = txt + "  " + nd.mark;
					}
					setText(txt);
				}
				setFont(Ui.TREE);
				return this;
			}
		});
		packageTree.addMouseListener(new MouseAdapter() {
			@Override
			public void mouseClicked(MouseEvent e) {
				if (e.getClickCount() == 2) {
					openSelectedTreeNode();
				}
			}
		});
		JScrollPane sp = new JScrollPane(packageTree);
		sp.setBorder(BorderFactory.createTitledBorder("Packages / Classes / Resources"));
		JPanel p = new JPanel(new BorderLayout());
		p.add(sp, BorderLayout.CENTER);
		return p;
	}

	private JPanel outlinePanel() {
		JScrollPane sp = new JScrollPane(outline);
		sp.setBorder(BorderFactory.createTitledBorder("Outline / Members"));
		JPanel p = new JPanel(new BorderLayout());
		p.add(sp, BorderLayout.CENTER);
		return p;
	}

	private JMenuBar buildMenu() {
		JMenuBar mb = new JMenuBar();

		JMenu file = robustMenu("File");
		file.add(item("Open...", KeyStroke.getKeyStroke(KeyEvent.VK_O, InputEvent.CTRL_DOWN_MASK), this::openDialog));
		file.add(item("Export sources / resources...", null, this::exportDialog));
		file.addSeparator();
		file.add(item("Save current edit", KeyStroke.getKeyStroke(KeyEvent.VK_S, InputEvent.CTRL_DOWN_MASK),
				this::saveCurrent));
		file.add(item("Reload current (discard edits)", null, this::reloadCurrent));
		file.addSeparator();
		file.add(item("Exit", KeyStroke.getKeyStroke(KeyEvent.VK_Q, InputEvent.CTRL_DOWN_MASK), this::onExit));
		mb.add(file);

		JMenu nav = new JMenu("Navigate");
		nav.add(item("Go to declaration...", KeyStroke.getKeyStroke(KeyEvent.VK_G, InputEvent.CTRL_DOWN_MASK),
				this::goTo));
		nav.add(item("Find usages...", KeyStroke.getKeyStroke(KeyEvent.VK_U, InputEvent.CTRL_DOWN_MASK),
				this::findUsages));
		nav.add(item("Search all text...", KeyStroke.getKeyStroke(KeyEvent.VK_F, InputEvent.CTRL_DOWN_MASK),
				this::searchAll));
		nav.add(item("Back", KeyStroke.getKeyStroke(KeyEvent.VK_LEFT, InputEvent.ALT_DOWN_MASK), this::back));
		nav.add(item("Forward", KeyStroke.getKeyStroke(KeyEvent.VK_RIGHT, InputEvent.ALT_DOWN_MASK), this::forward));
		mb.add(nav);

		JMenu view = robustMenu("View");
		view.add(item("Java view", null, () -> setOpenTabMode(DecompileTarget.JAVA)));
		view.add(item("Smali view", null, () -> setOpenTabMode(DecompileTarget.SMALI)));
		view.add(item("Split: Java | Smali", null, () -> setOpenTabMode(DecompileTarget.SPLIT)));
		view.addSeparator();
		view.add(item("Dark / light code theme", null, this::toggleTheme));
		view.add(item("Bigger / smaller editor font", null, this::toggleFontSize));
		view.addSeparator();
		view.add(item("Close current tab", KeyStroke.getKeyStroke(KeyEvent.VK_W, InputEvent.CTRL_DOWN_MASK),
				tabs::closeCurrent));
		view.add(item("Close other tabs", null, tabs::closeOthers));
		view.add(item("Close all tabs", null, tabs::closeAll));
		view.addSeparator();
		view.add(item("New tabs replace current (reuse tab)", null, this::toggleReuseTab));
		mb.add(view);

		JMenu tools = robustMenu("Tools");
		tools.add(item("Deobfuscation / mappings...", null, this::deobfuscation));
		tools.add(item("Analyze .so (native)...", null, this::analyzeSo));
		tools.add(item("Analyze Android XML...", null, this::analyzeXml));
		tools.add(item("Flutter / Dart analysis...", null, () -> new FlutterDialog(this, project).setVisible(true)));
		tools.add(item("Detect packer / protector...", null,
				() -> new ProtectorDialog(this, project).setVisible(true)));
		tools.add(item("Unpacker / Dumper (PairIP, jiagu)...", null,
				() -> new UnpackerDialog(this, project).setVisible(true)));
		tools.addSeparator();
		tools.add(item("Export all edits...", null, this::exportEdits));
		mb.add(tools);

		JMenu help = robustMenu("Help");
		help.add(item("About / disclaimer", null, () -> new AboutDialog(this).setVisible(true)));
		mb.add(help);
		return mb;
	}

	/** Swing's lightweight menu popups can vanish when the pointer leaves them; use heavyweight ones. */
	private static JMenu robustMenu(String title) {
		JMenu m = new JMenu(title);
		m.setDelay(120);
		// heavyweight popup: keeps the menu open when the pointer moves onto an item
		m.getPopupMenu().setLightWeightPopupEnabled(false);
		return m;
	}

	private JMenuItem item(String name, KeyStroke ks, Runnable action) {
		JMenuItem mi = new JMenuItem(name);
		if (ks != null) {
			mi.setAccelerator(ks);
		}
		mi.addActionListener(e -> action.run());
		return mi;
	}

	private JToolBar buildToolbar() {
		JToolBar tb = new JToolBar();
		tb.setFloatable(false);
		tb.setBorder(javax.swing.BorderFactory.createEmptyBorder(4, 6, 4, 6));
		tb.setPreferredSize(new Dimension(10, 38));
		tb.add(btn("Open", this::openDialog));
		tb.add(btn("Export", this::exportDialog));
		tb.addSeparator();
		tb.add(btn("Save", this::saveCurrent));
		tb.add(btn("Reload", this::reloadCurrent));
		tb.addSeparator();
		tb.add(btn("GoTo", this::goTo));
		tb.add(btn("Usages", this::findUsages));
		tb.addSeparator();
		tb.add(new JLabel(" Mode: "));
		modeJava.setSelected(true);
		modeJava.addActionListener(e -> setOpenTabMode(DecompileTarget.JAVA));
		modeSmali.addActionListener(e -> setOpenTabMode(DecompileTarget.SMALI));
		modeSplit.addActionListener(e -> setOpenTabMode(DecompileTarget.SPLIT));
		tb.add(modeJava);
		tb.add(modeSmali);
		tb.add(modeSplit);
		tb.addSeparator();
		tb.add(new JLabel(" Search: "));
		searchField.setFont(Ui.MONO);
		searchField.setPreferredSize(new Dimension(260, 26));
		searchField.setToolTipText("Search: text, symbols, string literals or numbers (Enter to run)");
		searchField.addActionListener(e -> searchAll());
		tb.add(searchField);
		searchMode.setToolTipText("What to look for");
		searchMode.addActionListener(e -> {
			Project.SearchMode m = (Project.SearchMode) searchMode.getSelectedItem();
			searchField.setToolTipText("Searching: " + m.name().toLowerCase()
					+ (m == Project.SearchMode.STRING_LITERAL ? " - string literals (urls, keys)"
							: m == Project.SearchMode.NUMBER ? " - numeric literals"
							: m == Project.SearchMode.SYMBOL ? " - class/method/field declarations" : ""));
		});
		tb.add(searchMode);
		searchCase.setToolTipText("Case sensitive");
		tb.add(searchCase);
		tb.add(btn("Find", this::searchAll));
		return tb;
	}

	private boolean darkTheme = true;
	private float fontSize = 14f;
	private boolean reuseTab = false;

	/** When on, opening another class reuses a single tab instead of piling up tabs. */
	public void toggleReuseTab() {
		reuseTab = !reuseTab;
		status("New tabs replace current: " + (reuseTab ? "on" : "off"));
	}

	/** Re-theme every open editor and newly opened content. */
	public void toggleTheme() {
		darkTheme = !darkTheme;
		Theme.setMode(darkTheme ? Theme.Mode.DARK : Theme.Mode.LIGHT);
		try {
			javax.swing.SwingUtilities.updateComponentTreeUI(this);
		} catch (Exception ignored) {
		}
		applyThemeToOpenTabs();
		status("Editor theme: " + (darkTheme ? "dark" : "light"));
	}

	public void toggleFontSize() {
		fontSize = fontSize >= 20f ? 12f : fontSize + 1f;
		applyThemeToOpenTabs();
		status("Editor font size: " + (int) fontSize);
	}

	private void applyThemeToOpenTabs() {
		Theme th = Theme.current();
		for (String key : tabs.keys()) {
			CodeTabs.EditorTab tab = tabs.getTab(key);
			if (tab == null) {
				continue;
			}
			for (CodeEditor ed : findEditors(tab.component())) {
				ed.setTheme(th);
				ed.setFontSize(fontSize);
			}
		}
	}

	private List<CodeEditor> findEditors(Component c) {
		List<CodeEditor> out = new ArrayList<>();
		if (c instanceof CodeEditor ce) {
			out.add(ce);
			return out;
		}
		if (c instanceof java.awt.Container cont) {
			for (Component ch : cont.getComponents()) {
				out.addAll(findEditors(ch));
			}
		}
		return out;
	}

	private JButton btn(String label, Runnable action) {
		JButton b = new JButton(label);
		b.setMargin(new java.awt.Insets(3, 12, 3, 12));
		b.setFocusPainted(false);
		b.setToolTipText(label);
		b.addActionListener(e -> action.run());
		return b;
	}

	// ------------------------------------------------------------- actions

	private void openDialog() {
		JFileChooser fc = new JFileChooser();
		fc.setDialogTitle("Open APK / DEX / AAR / AAB / ZIP / JAR / CLASS");
		fc.setFileFilter(new FileNameExtensionFilter(
				"Android & archive files (*.apk, *.dex, *.aar, *.aab, *.zip, *.jar, *.class)",
				"apk", "dex", "aar", "aab", "zip", "jar", "class"));
		if (project.getRoot() != null) {
			fc.setCurrentDirectory(project.getRoot().toFile());
		}
		if (fc.showOpenDialog(this) != JFileChooser.APPROVE_OPTION) {
			return;
		}
		loadFile(fc.getSelectedFile().toPath());
	}

	public void loadFile(Path file) {
		status("Loading " + file.getFileName() + " ...");
		project.setProgressListener(this::onProgress);
		showProgress(-1, "Loading " + file.getFileName() + " ...");
		new SwingWorker<Void, Void>() {
			@Override
			protected Void doInBackground() {
				try {
					project.load(file);
				} catch (Exception e) {
					throw new RuntimeException(e);
				}
				return null;
			}

			@Override
			protected void done() {
				showProgress(false);
				try {
					get();
				} catch (Exception e) {
					Throwable c = e.getCause() != null ? e.getCause() : e;
					Ui.error(MainWindow.this, "Failed to open " + file + "\n" + c);
					status("Load failed");
					return;
				}
				status(project.getClassCount() + " classes indexed (decompile on open)");
				refreshAfterLoad();
				status("Opened " + file.getFileName());
			}
		}.execute();
	}

	public void refreshAfterLoad() {
		tabs.closeAll();
		index.clear();
		sourceMap = Map.of();
		resourcePaths = project.getResourcePaths();
		// only index text we already have: decompiled sources are lazy (see Project.getCode)
		index.addText("AndroidManifest.xml", project.getManifestXml());
		outline.clear();
		setTitle("JADX Studio - " + project.getRoot());
		showProgress(true);
		new SwingWorker<Void, Void>() {
			@Override
			protected Void doInBackground() {
				// tree building can be thousands of nodes: keep it off the EDT
				buildTree();
				return null;
			}

			@Override
			protected void done() {
				showProgress(false);
				try {
					get();
					statusRight.setText(project.getClassCount() + " classes, " + resourcePaths.size()
							+ " resources, " + project.getNativePaths().size() + " native");
				} catch (Exception e) {
					Throwable c = e.getCause() != null ? e.getCause() : e;
					status("tree build failed: " + c);
					new RuntimeException(c).printStackTrace();
				}
			}
		}.execute();
	}

	// ------------------------------------------------------------ tree

	static final class NodeData {
		final String label;
		final String kind; // pkg, class, file, root, so
		final String key;
		final javax.swing.Icon icon;
		String mark = "";

		NodeData(String label, String kind, String key, javax.swing.Icon icon) {
			this.label = label;
			this.kind = kind;
			this.key = key;
			this.icon = icon;
		}
	}

	/** Build the whole tree OFF the EDT, then attach it (fast for 20k+ classes). */
	private void buildTree() {
		DefaultMutableTreeNode newRoot = new DefaultMutableTreeNode(new NodeData(
				project.getRoot() == null ? "No file loaded" : project.getRoot().getFileName().toString(),
				"root", null, null));
		if (project.getRoot() != null) {
			newRoot.add(new DefaultMutableTreeNode(new NodeData("AndroidManifest.xml", "file", "__manifest__", null)));

			// packages as real nested folders: com > pocketfm > app > MainActivity.java
			DefaultMutableTreeNode srcRoot = new DefaultMutableTreeNode(new NodeData("Sources", "root", null, null));
			newRoot.add(srcRoot);
			for (String p : project.getClassPaths()) {
				String withoutExt = p.endsWith(".java") ? p.substring(0, p.length() - 5) : p;
				addNested(srcRoot, withoutExt, "class", p, true);
			}
			sortTree(srcRoot);

			// resources as nested folders: res > layout > main.xml
			DefaultMutableTreeNode resRoot = new DefaultMutableTreeNode(new NodeData("Resources", "root", null, null));
			newRoot.add(resRoot);
			for (String p : resourcePaths) {
				addNested(resRoot, p, "file", p, false);
			}
			sortTree(resRoot);

			// native libs as nested folders: lib > arm64-v8a > libfoo.so
			DefaultMutableTreeNode nativeRoot = new DefaultMutableTreeNode(new NodeData("Native (.so)", "root", null, null));
			newRoot.add(nativeRoot);
			for (String p : project.getNativePaths()) {
				addNested(nativeRoot, p, "so", p, false);
			}
			sortTree(nativeRoot);
		}

		// snapshot first: re-parenting mutates newRoot, so iterating it live skips nodes
		List<DefaultMutableTreeNode> built = new ArrayList<>();
		for (int i = 0; i < newRoot.getChildCount(); i++) {
			built.add((DefaultMutableTreeNode) newRoot.getChildAt(i));
		}

		Ui.runOnEdt(() -> {
			treeRoot.setUserObject(newRoot.getUserObject());
			treeRoot.removeAllChildren();
			for (DefaultMutableTreeNode c : built) {
				treeRoot.add(c); // DefaultMutableTreeNode re-parents automatically
			}
			((DefaultTreeModel) packageTree.getModel()).reload();
			packageTree.expandRow(0);
			// show the first level of packages (androidx, android, com, ...) right away
			for (int i = 0; i < treeRoot.getChildCount(); i++) {
				DefaultMutableTreeNode child = (DefaultMutableTreeNode) treeRoot.getChildAt(i);
				if (child.getUserObject() instanceof NodeData nd && nd.kind.equals("root")) {
					packageTree.expandRow(i);
				}
			}
		});
	}

	/**
	 * Insert a path as nested folder nodes. {@code stripExtension} hides ".java" from the
	 * leaf label while the key keeps the full path.
	 */
	private static void addNested(DefaultMutableTreeNode root, String path, String kind, String key,
			boolean stripExtension) {
		if (path == null || path.isBlank()) {
			return;
		}
		String[] parts = path.split("/");
		DefaultMutableTreeNode cur = root;
		for (int i = 0; i < parts.length; i++) {
			boolean last = i == parts.length - 1;
			String label = parts[i];
			if (last && stripExtension && label.endsWith(".java")) {
				label = label.substring(0, label.length() - 5);
			}
			DefaultMutableTreeNode found = findChild(cur, label);
			if (found == null) {
				found = new DefaultMutableTreeNode(
						new NodeData(label, last ? kind : "pkg", last ? key : null, null));
				cur.add(found);
			} else if (last) {
				// same class name listed twice: keep the first key
				return;
			}
			cur = found;
		}
	}

	private static DefaultMutableTreeNode findChild(DefaultMutableTreeNode parent, String label) {
		for (int i = 0; i < parent.getChildCount(); i++) {
			DefaultMutableTreeNode c = (DefaultMutableTreeNode) parent.getChildAt(i);
			if (c.getUserObject() instanceof NodeData nd && nd.label.equals(label)) {
				return c;
			}
		}
		return null;
	}

	/** Folders first, then files, alphabetically. */
	private void sortTree(DefaultMutableTreeNode node) {
		List<DefaultMutableTreeNode> kids = new ArrayList<>();
		for (int i = 0; i < node.getChildCount(); i++) {
			kids.add((DefaultMutableTreeNode) node.getChildAt(i));
		}
		kids.sort((a, b) -> {
			boolean fa = isFolder(a);
			boolean fb = isFolder(b);
			if (fa != fb) {
				return fa ? -1 : 1;
			}
			String la = a.getUserObject() instanceof NodeData n1 ? n1.label : a.getUserObject().toString();
			String lb = b.getUserObject() instanceof NodeData n2 ? n2.label : b.getUserObject().toString();
			return la.compareToIgnoreCase(lb);
		});
		node.removeAllChildren();
		for (DefaultMutableTreeNode k : kids) {
			node.add(k);
			sortTree(k);
		}
	}

	private static boolean isFolder(DefaultMutableTreeNode n) {
		return n.getUserObject() instanceof NodeData nd && "pkg".equals(nd.kind);
	}

	private void openSelectedTreeNode() {
		TreePath p = packageTree.getSelectionPath();
		if (p == null) {
			return;
		}
		Object last = p.getLastPathComponent();
		if (!(last instanceof DefaultMutableTreeNode n) || !(n.getUserObject() instanceof NodeData d)) {
			return;
		}
		switch (d.kind) {
			case "class" -> openClass(d.key.substring(0, d.key.length() - 5));
			case "file" -> openSource(d.key, 1);
			case "so" -> openSo(d.key);
			default -> {
			}
		}
	}

	// ------------------------------------------------------- editor tabs

	public void setOpenTabMode(DecompileTarget t) {
		target = t;
		modeJava.setSelected(t == DecompileTarget.JAVA);
		modeSmali.setSelected(t == DecompileTarget.SMALI);
		modeSplit.setSelected(t == DecompileTarget.SPLIT);
		String key = tabs.currentKey();
		if (key != null && key.startsWith("cls:")) {
			String cls = key.substring(4);
			tabs.closeKey(key);
			openClass(cls);
		}
		status("Mode: " + t);
	}

	public void openClass(String className) {
		String key = "cls:" + className;
		if (tabs.hasKey(key)) {
			tabs.select(key);
			return;
		}
		if (reuseTab) {
			tabs.closeOthers();
		}
		CodeHolder java = project.getCode(className, DecompileTarget.JAVA);
		CodeHolder smali = project.getCode(className, DecompileTarget.SMALI);
		if (java == null && smali == null) {
			Ui.warn(this, "No code available for " + className);
			return;
		}
		DecompileTarget use = java == null ? DecompileTarget.SMALI : target;
		JTabbedPane inner = new JTabbedPane();
		CodeEditor javaEd = java == null ? null : new CodeEditor(java.text, true, JavaTokenizer.Lang.JAVA);
		CodeEditor smaliEd = smali == null ? null : new CodeEditor(smali.text, true, JavaTokenizer.Lang.SMALI);

		if (use == DecompileTarget.SPLIT && javaEd != null && smaliEd != null) {
			JSplitPane sp = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT, wrapEditor(javaEd), wrapEditor(smaliEd));
			sp.setResizeWeight(0.5);
			sp.setBorder(null);
			inner.addTab("Java | Smali", sp);
		} else if (use == DecompileTarget.SMALI && smaliEd != null) {
			inner.addTab("Smali", wrapEditor(smaliEd));
		} else if (javaEd != null) {
			inner.addTab("Java", wrapEditor(javaEd));
		} else {
			inner.addTab("Smali", wrapEditor(smaliEd));
		}

		CodeTabs.EditorTab et = new CodeTabs.EditorTab() {
			@Override
			public javax.swing.JComponent component() {
				return inner;
			}

			@Override
			public String title() {
				return className.substring(className.lastIndexOf('.') + 1);
			}

			@Override
			public boolean isDirty() {
				return (javaEd != null && javaEd.isDirty()) || (smaliEd != null && smaliEd.isDirty());
			}

			@Override
			public void markSaved() {
				if (javaEd != null) {
					javaEd.markSaved();
				}
				if (smaliEd != null) {
					smaliEd.markSaved();
				}
				tabs.refreshTitles();
			}
		};
		if (javaEd != null) {
			javaEd.addDirtyListener(tabs::refreshTitles);
			javaEd.addCaretListener(e -> {
				statusRight.setText(className + " : line " + javaEd.getCaretLine());
				fillOutline(javaEd);
			});
		}
		if (smaliEd != null) {
			smaliEd.addDirtyListener(tabs::refreshTitles);
		}
		outline.setOnJump(line -> {
			CodeEditor ed = javaEd != null ? javaEd : smaliEd;
			if (ed != null) {
				ed.gotoLine(line);
			}
		});
		tabs.open(key, et);
		fillOutline(javaEd != null ? javaEd : smaliEd);
		if (java != null && java.errors != null && !java.errors.isEmpty()) {
			status("Decompiler reported " + java.errors.size() + " issue(s) for " + className);
		}
	}

	private JPanel wrapEditor(CodeEditor ed) {
		JPanel p = new JPanel(new BorderLayout());
		p.add(ed, BorderLayout.CENTER);
		return p;
	}

	public void openSource(String path, int line) {
		String key = "src:" + path;
		if (tabs.hasKey(key)) {
			tabs.select(key);
			CodeTabs.EditorTab t = tabs.getTab(key);
			CodeEditor ed = findEditor(t.component());
			if (ed != null) {
				ed.gotoLine(line);
			}
			return;
		}
		if (reuseTab) {
			tabs.closeOthers();
		}
		String text;
		if (path.equals("__manifest__")) {
			text = project.getManifestXml();
		} else if (path.endsWith(".java")) {
			// decompiled on demand
			CodeHolder h = project.getCode(path, DecompileTarget.JAVA);
			if (h == null) {
				Ui.warn(this, "No decompiled code for " + path);
				return;
			}
			text = h.text;
		} else if (sourceMap.containsKey(path)) {
			text = sourceMap.get(path).text;
		} else if (project.isResourcePath(path)) {
			try {
				byte[] b = project.readResource(path);
				text = b == null ? "" : new String(b, StandardCharsets.UTF_8);
			} catch (Exception e) {
				text = "<error reading resource: " + e.getMessage() + ">";
			}
		} else {
			Ui.warn(this, "Not found: " + path);
			return;
		}
		CodeEditor ed = new CodeEditor(text, isHighlightable(path), languageOf(path));
		ed.setTheme(Theme.current());
		ed.setFontSize(fontSize);
		JPanel panel = wrapEditor(ed);
		ed.addCaretListener(e -> statusRight.setText(path + " : line " + ed.getCaretLine()));
		ed.addDirtyListener(tabs::refreshTitles);
		outline.setOnJump(ed::gotoLine);
		tabs.open(key, new CodeTabs.EditorTab() {
			@Override
			public javax.swing.JComponent component() {
				return panel;
			}

			@Override
			public String title() {
				if (path.equals("__manifest__")) {
					return "AndroidManifest.xml";
				}
				return path.substring(path.lastIndexOf('/') + 1);
			}

			@Override
			public boolean isDirty() {
				return ed.isDirty();
			}

			@Override
			public void markSaved() {
				ed.markSaved();
				tabs.refreshTitles();
			}
		});
		ed.gotoLine(line);
		fillOutline(ed);
	}

	private static JavaTokenizer.Lang languageOf(String path) {
		String p = path.toLowerCase(java.util.Locale.ROOT);
		if (path.equals("__manifest__") || path.endsWith(".xml")) {
			return JavaTokenizer.Lang.XML;
		}
		if (p.endsWith(".smali")) {
			return JavaTokenizer.Lang.SMALI;
		}
		if (p.endsWith(".xml") || p.endsWith(".html") || p.endsWith(".htm") || p.endsWith(".svg")) {
			return JavaTokenizer.Lang.XML;
		}
		if (p.endsWith(".c") || p.endsWith(".h") || p.endsWith(".json") || p.endsWith(".js")
				|| p.endsWith(".txt") || p.endsWith(".properties") || p.endsWith(".gradle")) {
			return JavaTokenizer.Lang.C;
		}
		return JavaTokenizer.Lang.JAVA;
	}

	private boolean isHighlightable(String path) {
		if (path.equals("__manifest__")) {
			return true;
		}
		return path.endsWith(".java") || path.endsWith(".smali") || path.endsWith(".xml") || path.endsWith(".json")
				|| path.endsWith(".js") || path.endsWith(".html") || path.endsWith(".css") || path.endsWith(".gradle")
				|| path.endsWith(".pro") || path.endsWith(".properties") || path.endsWith(".txt");
	}

	private void fillOutline(CodeEditor ed) {
		outline.clear();
		if (ed == null) {
			return;
		}
		String[] lines = ed.getText().split("\n", -1);
		for (int i = 0; i < lines.length; i++) {
			String t = lines[i].trim();
			if (t.startsWith("class ") || t.startsWith("public class") || t.startsWith("public interface")
					|| t.startsWith("interface ") || t.startsWith("public enum") || t.startsWith("enum ")) {
				outline.add("type", t, i + 1);
			} else if (t.startsWith("@") && t.length() > 1 && !t.startsWith("@Override")) {
				outline.add("ann", t, i + 1);
			} else if (looksLikeMember(t)) {
				outline.add("method", t, i + 1);
			}
		}
	}

	private static boolean looksLikeMember(String t) {
		if (t.startsWith("if") || t.startsWith("for") || t.startsWith("while") || t.startsWith("switch")
				|| t.startsWith("return") || t.startsWith("new ") || t.contains("=") && !t.contains("(")) {
			return false;
		}
		boolean mod = t.startsWith("public ") || t.startsWith("private ") || t.startsWith("protected ")
				|| t.startsWith("static ") || t.startsWith("final ") || t.startsWith("abstract ")
				|| t.startsWith("synchronized ") || t.startsWith("native ");
		boolean ret = t.startsWith("void ") || t.startsWith("int ") || t.startsWith("long ")
				|| t.startsWith("boolean ") || t.startsWith("byte ") || t.startsWith("short ")
				|| t.startsWith("char ") || t.startsWith("float ") || t.startsWith("double ")
				|| t.startsWith("String ");
		return (mod || ret) && t.contains("(") && (t.endsWith("{") || t.endsWith(";") || t.endsWith(")") || t.endsWith(","));
	}

	// ------------------------------------------------------ nav history

	private void pushHistory(String key) {
		if (key != null) {
			backStack.add(key);
			forwardStack.clear();
		}
	}

	private void back() {
		if (backStack.isEmpty()) {
			return;
		}
		String k = backStack.remove(backStack.size() - 1);
		String cur = tabs.currentKey();
		if (cur != null) {
			forwardStack.add(cur);
		}
		navigateTo(k);
	}

	private void forward() {
		if (forwardStack.isEmpty()) {
			return;
		}
		String k = forwardStack.remove(forwardStack.size() - 1);
		String cur = tabs.currentKey();
		if (cur != null) {
			backStack.add(cur);
		}
		navigateTo(k);
	}

	private void navigateTo(String key) {
		if (key == null) {
			return;
		}
		if (key.startsWith("cls:")) {
			openClass(key.substring(4));
		} else if (key.startsWith("src:")) {
			openSource(key.substring(4), 1);
		}
	}

	// -------------------------------------------------------- navigation

	private void goTo() {
		new GoToDialog(this, index, (entry, dlg) -> {
			JavaIndex.Entry e = index.resolve(entry);
			if (e == null) {
				return;
			}
			String path = e.target();
			pushHistory(tabs.currentKey());
			if (path.endsWith(".java")) {
				openClass(path.substring(0, path.length() - 5));
			} else {
				openSource(path, e.line());
			}
		});
	}

	private void findUsages() {
		String sel = currentSelectedIdentifier();
		String q = JOptionPane.showInputDialog(this, "Find usages of:", sel == null ? "" : sel);
		if (q == null || q.isBlank()) {
			return;
		}
		showUsages(q.trim(), index.findUsages(q.trim(), true));
	}

	private String currentSelectedIdentifier() {
		CodeEditor ed = currentEditor();
		if (ed == null) {
			return null;
		}
		String sel = ed.getTextComponent().getSelectedText();
		return sel == null || sel.isBlank() ? null : sel.trim();
	}

	private CodeEditor currentEditor() {
		String key = tabs.currentKey();
		if (key == null) {
			return null;
		}
		CodeTabs.EditorTab t = tabs.getTab(key);
		return t == null ? null : findEditor(t.component());
	}

	private CodeEditor findEditor(Component c) {
		if (c instanceof CodeEditor ce) {
			return ce;
		}
		if (c instanceof java.awt.Container cont) {
			for (Component ch : cont.getComponents()) {
				CodeEditor f = findEditor(ch);
				if (f != null) {
					return f;
				}
			}
		}
		return null;
	}

	private void showUsages(String term, List<int[]> hits) {
		if (hits.isEmpty()) {
			Ui.info(this, "No usages found for: " + term);
			return;
		}
		DefaultMutableTreeNode root = new DefaultMutableTreeNode(term + "  (" + hits.size() + " usages)");
		Map<String, DefaultMutableTreeNode> byDoc = new LinkedHashMap<>();
		for (int[] h : hits) {
			String path = index.docPath(h[0]);
			DefaultMutableTreeNode dn = byDoc.get(path);
			if (dn == null) {
				dn = new DefaultMutableTreeNode(path);
				byDoc.put(path, dn);
				root.add(dn);
			}
			dn.add(new DefaultMutableTreeNode(new RefNode(h[0], h[1],
					"L" + h[1] + ": " + lineOf(index.docText(h[0]), h[1]))));
		}
		showResultTree("Usages of " + term, root, (doc, line) -> {
			pushHistory(tabs.currentKey());
			openSource(index.docPath(doc), line);
		});
	}

	record RefNode(int doc, int line, String text) {
		@Override
		public String toString() {
			return text;
		}
	}

	record FileNode(String file, int line, String text) {
		@Override
		public String toString() {
			return text;
		}
	}

	private void showResultTree(String title, DefaultMutableTreeNode root,
			java.util.function.BiConsumer<Integer, Integer> open) {
		JTree tree = new JTree(new DefaultTreeModel(root));
		tree.setFont(Ui.TREE);
		for (int i = 0; i < Math.min(tree.getRowCount(), 400); i++) {
			tree.expandRow(i);
		}
		javax.swing.JDialog dlg = new javax.swing.JDialog(this, title, false);
		dlg.setSize(new Dimension(950, 560));
		dlg.setLocationRelativeTo(this);
		tree.addTreeSelectionListener(e -> {
			Object lp = tree.getLastSelectedPathComponent();
			if (lp instanceof DefaultMutableTreeNode n) {
				if (n.getUserObject() instanceof RefNode u) {
					open.accept(u.doc(), u.line());
					dlg.dispose();
				}
			}
		});
		dlg.add(new JScrollPane(tree));
		dlg.setVisible(true);
	}

	private static String lineOf(String text, int line) {
		String[] lines = text.split("\n", -1);
		return line - 1 < lines.length ? lines[line - 1].trim() : "";
	}

	// ----------------------------------------------------------- search

	private void searchAll() {
		String q = searchField.getText();
		if (q == null || q.isBlank()) {
			Ui.info(this, "Type something to search for.");
			return;
		}
		Project.SearchMode mode = (Project.SearchMode) searchMode.getSelectedItem();
		status("Searching " + project.getClassCount() + " classes (decompiling on demand)...");
		showProgress(0, "Searching...");
		project.setProgressListener(this::onProgress);
		new SwingWorker<List<Project.SearchHit>, Void>() {
			@Override
			protected List<Project.SearchHit> doInBackground() {
				int[] pct = new int[] { 0 };
				return project.search(q, searchCase.isSelected(), 3000, pct, mode);
			}

			@Override
			protected void done() {
				showProgress(-1, "");
				try {
					List<Project.SearchHit> hits = get();
					showSearchResults(q + "  [" + mode + "]", hits);
					status(hits.size() + " results (" + mode.name().toLowerCase() + ")");
				} catch (Exception e) {
					Throwable c = e.getCause() != null ? e.getCause() : e;
					Ui.error(MainWindow.this, "Search failed: " + c);
					status("Search failed");
				}
			}
		}.execute();
	}

	/** Progress callback from the engine: shows a real percentage when known. */
	private void onProgress(Progress p) {
		Ui.runOnEdt(() -> {
			status(p.message());
			showProgress(p.percent(), p.message());
		});
	}

	private void showSearchResults(String q, List<Project.SearchHit> results) {
		DefaultMutableTreeNode root = new DefaultMutableTreeNode(q + "  (" + results.size() + " hits)");
		Map<String, DefaultMutableTreeNode> byFile = new LinkedHashMap<>();
		for (Project.SearchHit r : results) {
			DefaultMutableTreeNode fn = byFile.get(r.path());
			if (fn == null) {
				fn = new DefaultMutableTreeNode(r.path());
				byFile.put(r.path(), fn);
				root.add(fn);
			}
			fn.add(new DefaultMutableTreeNode(
					new SearchDocNode(r.path(), r.line(), "L" + r.line() + ": " + r.preview())));
		}
		JTree tree = new JTree(new DefaultTreeModel(root));
		tree.setFont(Ui.TREE);
		for (int i = 0; i < Math.min(tree.getRowCount(), 400); i++) {
			tree.expandRow(i);
		}
		javax.swing.JDialog dlg = new javax.swing.JDialog(this, "Search: " + q, false);
		dlg.setSize(new Dimension(950, 560));
		dlg.setLocationRelativeTo(this);
		tree.addTreeSelectionListener(e -> {
			Object lp = tree.getLastSelectedPathComponent();
			if (lp instanceof DefaultMutableTreeNode n && n.getUserObject() instanceof SearchDocNode u) {
				pushHistory(tabs.currentKey());
				openSource(u.file, u.line);
				dlg.dispose();
			}
		});
		dlg.add(new JScrollPane(tree));
		dlg.setVisible(true);
	}

	record SearchDocNode(String file, int line, String text) {
		@Override
		public String toString() {
			return text;
		}
	}

	// ------------------------------------------------------- deobfuscate

	private void deobfuscation() {
		DeobfuscationDialog dlg = new DeobfuscationDialog(this, project);
		dlg.setOnApplied(() -> {
			showProgress(true);
			status("Re-decompiling with mappings...");
			new SwingWorker<Void, Void>() {
				@Override
				protected Void doInBackground() {
					try {
						project.reloadWithMappings();
					} catch (Exception e) {
						throw new RuntimeException(e);
					}
					return null;
				}

				@Override
				protected void done() {
					showProgress(false);
					try {
						get();
					} catch (Exception e) {
						Throwable c = e.getCause() != null ? e.getCause() : e;
						new DeobfuscationLogDialog(MainWindow.this, "Re-decompile issues",
								c.getMessage() == null ? c.toString() : c.getMessage()).setVisible(true);
						return;
					}
					tabs.closeAll();
					refreshAfterLoad();
					status("Mappings applied");
				}
			}.execute();
		});
		dlg.setVisible(true);
	}

	// --------------------------------------------------------- analysis

	private void analyzeSo() {
		List<String> natives = project.getNativePaths();
		if (!natives.isEmpty()) {
			String pick = (String) JOptionPane.showInputDialog(this, "Select native library:", "Analyze .so",
					JOptionPane.QUESTION_MESSAGE, null, natives.toArray(), natives.get(0));
			if (pick == null) {
				return;
			}
			openSo(pick);
			return;
		}
		JFileChooser fc = new JFileChooser();
		fc.setFileFilter(new FileNameExtensionFilter("Native libraries (*.so)", "so"));
		if (fc.showOpenDialog(this) != JFileChooser.APPROVE_OPTION) {
			return;
		}
		try {
			new SoAnalysisDialog(this, fc.getSelectedFile().toPath()).setVisible(true);
		} catch (Exception e) {
			Ui.error(this, "SO analysis failed: " + e);
		}
	}

	private void openSo(String path) {
		try {
			byte[] data = project.readResource(path);
			if (data == null) {
				Ui.warn(this, "Cannot read " + path);
				return;
			}
			Path tmp = Files.createTempFile("jadxstudio", ".so");
			Files.write(tmp, data);
			tmp.toFile().deleteOnExit();
			new SoAnalysisDialog(this, tmp).setVisible(true);
		} catch (Exception e) {
			Ui.error(this, "SO analysis failed: " + e);
		}
	}

	private void analyzeXml() {
		JFileChooser fc = new JFileChooser();
		fc.setFileFilter(new FileNameExtensionFilter("Android XML (*.xml)", "xml"));
		if (fc.showOpenDialog(this) != JFileChooser.APPROVE_OPTION) {
			return;
		}
		try {
			new XmlAnalysisDialog(this, fc.getSelectedFile().toPath()).setVisible(true);
		} catch (Exception e) {
			Ui.error(this, "XML analysis failed: " + e);
		}
	}

	// -------------------------------------------------------- save/export

	private void saveCurrent() {
		CodeEditor ed = currentEditor();
		String key = tabs.currentKey();
		if (ed == null || key == null) {
			Ui.info(this, "Nothing to save.");
			return;
		}
		if (key.startsWith("cls:")) {
			String cls = key.substring(4);
			boolean smaliPane = "Smali".equals(currentInnerTabName());
			project.applyEdit(smaliPane ? cls + ".smali" : cls + ".java", ed.getText());
		} else if (key.startsWith("src:")) {
			project.applyEdit(key.substring(4), ed.getText());
		}
		ed.markSaved();
		tabs.refreshTitles();
		status("Saved edit for " + key);
	}

	private String currentInnerTabName() {
		CodeTabs.EditorTab t = tabs.getTab(tabs.currentKey());
		if (!(t instanceof JTabbedPane inner)) {
			return "Java";
		}
		return inner.getTitleAt(inner.getSelectedIndex());
	}

	private void reloadCurrent() {
		String key = tabs.currentKey();
		if (key == null) {
			return;
		}
		tabs.closeKey(key);
		navigateTo(key);
		status("Reloaded " + key);
	}

	private void exportEdits() {
		JFileChooser fc = new JFileChooser();
		fc.setDialogTitle("Choose folder for edited sources");
		fc.setFileSelectionMode(JFileChooser.DIRECTORIES_ONLY);
		if (fc.showSaveDialog(this) != JFileChooser.APPROVE_OPTION) {
			return;
		}
		try {
			int n = project.exportEdits(fc.getSelectedFile().toPath());
			Ui.info(this, "Exported " + n + " edited file(s) to " + fc.getSelectedFile());
		} catch (Exception ex) {
			Ui.error(this, "Export edits failed: " + ex);
		}
	}

	private void exportDialog() {
		JFileChooser fc = new JFileChooser();
		fc.setDialogTitle("Choose output folder");
		fc.setFileSelectionMode(JFileChooser.DIRECTORIES_ONLY);
		if (project.getOutput() != null) {
			fc.setCurrentDirectory(project.getOutput().toFile());
		}
		if (fc.showSaveDialog(this) != JFileChooser.APPROVE_OPTION) {
			return;
		}
		Path out = fc.getSelectedFile().toPath();
		project.setOutput(out);
		showProgress(true);
		status("Exporting to " + out + " ...");
		project.setProgressListener(this::onProgress);
		showProgress(0, "Exporting...");
		new SwingWorker<Integer, Void>() {
			@Override
			protected Integer doInBackground() {
				ExportOptions o = new ExportOptions();
				o.sources = true;
				o.resources = true;
				o.export = true;
				try {
					return project.export(o);
				} catch (Exception e) {
					throw new RuntimeException(e);
				}
			}

			@Override
			protected void done() {
				showProgress(false);
				try {
					int n = get();
					Ui.info(MainWindow.this, "Exported " + n + " file(s) to " + out);
					status("Exported " + n + " files");
				} catch (Exception e) {
					Throwable c = e.getCause() != null ? e.getCause() : e;
					Ui.error(MainWindow.this, "Export failed: " + c);
				}
			}
		}.execute();
	}

	// ---------------------------------------------------------- helpers

	private void updateStatusForTab() {
		String k = tabs.currentKey();
		statusLeft.setText(k == null ? "Ready" : k);
	}

	private void status(String s) {
		statusLeft.setText(s);
	}

	private void showProgress(boolean v) {
		progress.setIndeterminate(v);
		progress.setVisible(v);
	}

	/**
	 * Show real progress. {@code percent < 0} means "unknown" and shows a moving bar;
	 * otherwise a determinate bar with the percentage text.
	 */
	private void showProgress(int percent, String text) {
		progress.setVisible(true);
		if (percent < 0) {
			// jadx's own analysis phase: no percentage available, keep the bar clean
			progress.setIndeterminate(true);
			progress.setString(null);
		} else {
			progress.setIndeterminate(false);
			progress.setMinimum(0);
			progress.setMaximum(100);
			progress.setValue(percent);
			progress.setString(percent + "%");
		}
	}

	private void onExit() {
		long dirty = tabs.keys().stream().filter(k -> tabs.getTab(k) != null && tabs.getTab(k).isDirty()).count();
		if (dirty > 0) {
			int r = JOptionPane.showConfirmDialog(this,
					dirty + " tab(s) have unsaved edits. Exit anyway?", "Unsaved changes",
					JOptionPane.OK_CANCEL_OPTION, JOptionPane.WARNING_MESSAGE);
			if (r != JOptionPane.OK_OPTION) {
				return;
			}
		}
		setVisible(false);
		dispose();
		System.exit(0);
	}
}
