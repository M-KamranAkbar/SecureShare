#include <QApplication>
#include <QWidget>
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QLabel>
#include <QLineEdit>
#include <QPushButton>
#include <QTextEdit>
#include <QGroupBox>
#include <QFrame>
#include <QListWidget>
#include <QListWidgetItem>
#include <QSplitter>
#include <QMainWindow>
#include <QStackedWidget>
#include <QProgressBar>
#include <QTimer>
#include <QThread>
#include <QTabWidget>
#include <QComboBox>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <string>
#include <sstream>

using namespace std;

#define SERVER_IP "127.0.0.1"
#define PORT 8080

string sendCommand(const string& cmd) {
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_port = htons(PORT);
    inet_pton(AF_INET, SERVER_IP, &addr.sin_addr);
    if (connect(sock, (struct sockaddr*)&addr, sizeof(addr)) < 0)
        return "ERROR: Cannot connect to server";
    send(sock, cmd.c_str(), cmd.size(), 0);
    shutdown(sock, SHUT_WR);
    string response;
    char buf[4096];
    int n;
    while ((n = recv(sock, buf, sizeof(buf)-1, 0)) > 0) {
        buf[n] = 0;
        response += buf;
    }
    close(sock);
    return response;
}

QString fileIcon(const QString& filename) {
    QString lower = filename.toLower();
    if (lower.endsWith(".txt") || lower.endsWith(".md")) return "📄";
    if (lower.endsWith(".pdf"))                           return "📕";
    if (lower.endsWith(".jpg") || lower.endsWith(".png")) return "🖼";
    if (lower.endsWith(".zip") || lower.endsWith(".tar")) return "📦";
    if (lower.endsWith(".doc") || lower.endsWith(".docx")) return "📝";
    if (lower.endsWith(".xls") || lower.endsWith(".xlsx")) return "📊";
    if (lower.endsWith(".mp3") || lower.endsWith(".wav"))  return "🎵";
    if (lower.endsWith(".mp4") || lower.endsWith(".avi"))  return "🎬";
    return "📁";
}

const QString STYLE = R"(
QWidget { background-color: #0d1117; color: #c9d1d9; font-family: 'Segoe UI', Arial; font-size: 13px; }
QMainWindow { background-color: #0d1117; }
QTabWidget::pane { border: 1px solid #30363d; background: #161b22; border-radius: 6px; }
QTabBar::tab { background: #21262d; color: #8b949e; padding: 10px 22px; border-radius: 6px 6px 0 0; margin-right: 2px; font-weight: bold; }
QTabBar::tab:selected { background: #1f6feb; color: white; }
QTabBar::tab:hover { background: #388bfd; color: white; }
QPushButton { background: #21262d; color: #c9d1d9; border: 1px solid #30363d; border-radius: 6px; padding: 8px 18px; font-weight: bold; }
QPushButton:hover { background: #30363d; border-color: #58a6ff; color: #58a6ff; }
QPushButton:pressed { background: #1f6feb; color: white; }
QPushButton#primaryBtn { background: #1f6feb; border-color: #1f6feb; color: white; padding: 10px 24px; font-size: 14px; }
QPushButton#primaryBtn:hover { background: #388bfd; }
QPushButton#dangerBtn { background: #da3633; border-color: #f85149; color: white; }
QPushButton#dangerBtn:hover { background: #f85149; }
QPushButton#successBtn { background: #238636; border-color: #2ea043; color: white; }
QPushButton#successBtn:hover { background: #2ea043; }
QPushButton#warnBtn { background: #9e6a03; border-color: #d29922; color: white; }
QPushButton#warnBtn:hover { background: #d29922; }
QPushButton#shareBtn { background: #6e40c9; border-color: #8957e5; color: white; }
QPushButton#shareBtn:hover { background: #8957e5; }
QLineEdit { background: #21262d; border: 1px solid #30363d; border-radius: 6px; padding: 8px 12px; color: #c9d1d9; }
QLineEdit:focus { border-color: #58a6ff; }
QTextEdit { background: #161b22; border: 1px solid #30363d; border-radius: 6px; padding: 8px; color: #58a6ff; font-family: 'Courier New', monospace; font-size: 12px; }
QGroupBox { border: 1px solid #30363d; border-radius: 8px; margin-top: 14px; padding: 14px 10px 10px 10px; font-weight: bold; }
QGroupBox::title { subcontrol-origin: margin; left: 14px; padding: 0 6px; color: #58a6ff; font-size: 13px; }
QListWidget { background: #161b22; border: 1px solid #30363d; border-radius: 6px; padding: 4px; }
QListWidget::item { padding: 6px 8px; border-radius: 4px; border-bottom: 1px solid #21262d; }
QListWidget::item:selected { background: #1f6feb; color: white; }
QListWidget::item:hover { background: #21262d; }
QComboBox { background: #21262d; border: 1px solid #30363d; border-radius: 6px; padding: 6px 12px; color: #c9d1d9; }
QComboBox:focus { border-color: #58a6ff; }
QComboBox::drop-down { border: none; }
QProgressBar { background: #21262d; border: 1px solid #30363d; border-radius: 4px; height: 8px; }
QProgressBar::chunk { background: #1f6feb; border-radius: 4px; }
QFrame#divider { background: #30363d; max-height: 1px; }
QSplitter::handle { background: #30363d; width: 1px; }
)";

class SecureShareApp : public QMainWindow {
    Q_OBJECT

    QString currentToken;
    QString currentUser;
    QStackedWidget* stack;
    QWidget* loginPage;
    QWidget* mainPage;

    // Login
    QLineEdit* loginUser;
    QLineEdit* loginPass;
    QLabel*    loginStatus;

    // Main — Files tab
    QLabel*       userLabel;
    QLineEdit*    filenameInput;
    QTextEdit*    fileContentInput;
    QTextEdit*    outputArea;
    QListWidget*  fileList;
    QProgressBar* progressBar;
    QLabel*       scanLabel;

    // Shared With Me tab
    QListWidget*  sharedList;
    QLineEdit*    shareTargetInput;

    // Permissions tab
    QLineEdit*  permFilename;
    QLineEdit*  permTargetUser;
    QComboBox*  permLevel;

    // Activity log tab
    QTextEdit*  logArea;

public:
    SecureShareApp(QWidget* parent = nullptr) : QMainWindow(parent) {
        setWindowTitle("SecureShare v8.0 — Final");
        setMinimumSize(1000, 700);
        setStyleSheet(STYLE);
        stack = new QStackedWidget();
        setCentralWidget(stack);
        loginPage = buildLoginPage();
        mainPage  = buildMainPage();
        stack->addWidget(loginPage);
        stack->addWidget(mainPage);
        stack->setCurrentWidget(loginPage);
    }

    QWidget* buildLoginPage() {
        QWidget* page = new QWidget();
        QVBoxLayout* layout = new QVBoxLayout(page);
        layout->setAlignment(Qt::AlignCenter);
        layout->setSpacing(16);

        QLabel* lock = new QLabel("🔒");
        lock->setAlignment(Qt::AlignCenter);
        lock->setStyleSheet("font-size: 56px;");
        layout->addWidget(lock);

        QLabel* title = new QLabel("SecureShare");
        title->setAlignment(Qt::AlignCenter);
        title->setStyleSheet("font-size: 32px; font-weight: bold; color: #58a6ff;");
        layout->addWidget(title);

        QLabel* sub = new QLabel("Encrypted LAN File Sharing — OS Lab Project 2026");
        sub->setAlignment(Qt::AlignCenter);
        sub->setStyleSheet("color: #8b949e; font-size: 12px;");
        layout->addWidget(sub);

        QHBoxLayout* badges = new QHBoxLayout();
        badges->setAlignment(Qt::AlignCenter);
        auto badge = [](const QString& t, const QString& bg) {
            QLabel* l = new QLabel(t);
            l->setStyleSheet(QString("background:%1;color:white;border-radius:10px;padding:3px 10px;font-size:11px;font-weight:bold;").arg(bg));
            return l;
        };
        badges->addWidget(badge("AES-256",     "#238636"));
        badges->addWidget(badge("SHA-256",     "#1f6feb"));
        badges->addWidget(badge("5-Layer Scan","#6e40c9"));
        badges->addWidget(badge("Sharing",     "#8957e5"));
        badges->addWidget(badge("Permissions", "#9e6a03"));
        badges->addWidget(badge("Activity Log","#da3633"));
        layout->addLayout(badges);

        QFrame* div = new QFrame(); div->setObjectName("divider"); div->setFrameShape(QFrame::HLine);
        layout->addWidget(div);

        QWidget* form = new QWidget(); form->setMaximumWidth(400);
        QVBoxLayout* fl = new QVBoxLayout(form); fl->setSpacing(12);

        auto lbl = [](const QString& t) {
            QLabel* l = new QLabel(t);
            l->setStyleSheet("color:#8b949e; font-weight:bold; font-size:12px;");
            return l;
        };

        fl->addWidget(lbl("USERNAME"));
        loginUser = new QLineEdit(); loginUser->setPlaceholderText("Enter username"); loginUser->setMinimumHeight(42);
        fl->addWidget(loginUser);

        fl->addWidget(lbl("PASSWORD"));
        loginPass = new QLineEdit(); loginPass->setEchoMode(QLineEdit::Password);
        loginPass->setPlaceholderText("Enter password"); loginPass->setMinimumHeight(42);
        fl->addWidget(loginPass);

        fl->addSpacing(8);

        QPushButton* loginBtn = new QPushButton("Sign In");
        loginBtn->setObjectName("primaryBtn"); loginBtn->setMinimumHeight(46);
        fl->addWidget(loginBtn);

        QPushButton* regBtn = new QPushButton("Create Account");
        regBtn->setObjectName("successBtn"); regBtn->setMinimumHeight(46);
        fl->addWidget(regBtn);

        loginStatus = new QLabel("");
        loginStatus->setAlignment(Qt::AlignCenter);
        loginStatus->setStyleSheet("font-size:12px; padding:4px;");
        fl->addWidget(loginStatus);

        layout->addWidget(form, 0, Qt::AlignCenter);

        QLabel* footer = new QLabel("AES-256-CBC  ·  SHA-256  ·  Unix-style Permissions  ·  User-to-User Sharing  ·  Multithreaded");
        footer->setAlignment(Qt::AlignCenter);
        footer->setStyleSheet("color:#30363d; font-size:11px;");
        layout->addWidget(footer);

        connect(loginBtn,  &QPushButton::clicked,     this, &SecureShareApp::doLogin);
        connect(regBtn,    &QPushButton::clicked,     this, &SecureShareApp::doRegister);
        connect(loginPass, &QLineEdit::returnPressed, this, &SecureShareApp::doLogin);
        return page;
    }

    QWidget* buildMainPage() {
        QWidget* page = new QWidget();
        QVBoxLayout* layout = new QVBoxLayout(page);
        layout->setSpacing(8); layout->setContentsMargins(12,8,12,8);

        // Top bar
        QHBoxLayout* top = new QHBoxLayout();
        QLabel* appName = new QLabel("🔒 SecureShare v8.0");
        appName->setStyleSheet("font-size:18px; font-weight:bold; color:#58a6ff;");
        top->addWidget(appName);
        top->addStretch();
        userLabel = new QLabel("Not logged in");
        userLabel->setStyleSheet("color:#2ea043; font-weight:bold; font-size:12px;");
        top->addWidget(userLabel);
        top->addSpacing(12);
        QPushButton* logoutBtn = new QPushButton("Sign Out");
        logoutBtn->setStyleSheet("background:#21262d; padding:6px 14px; font-size:12px;");
        top->addWidget(logoutBtn);
        layout->addLayout(top);

        QFrame* div = new QFrame(); div->setObjectName("divider"); div->setFrameShape(QFrame::HLine);
        layout->addWidget(div);

        QTabWidget* tabs = new QTabWidget();
        tabs->addTab(buildFilesTab(),       "📁  My Files");
        tabs->addTab(buildSharedTab(),      "🤝  Shared With Me");
        tabs->addTab(buildPermissionsTab(), "🔐  Permissions");
        tabs->addTab(buildActivityTab(),    "📋  Activity Log");
        layout->addWidget(tabs);

        connect(logoutBtn, &QPushButton::clicked, this, &SecureShareApp::doLogout);
        return page;
    }

    // ── TAB 1: MY FILES ──────────────────────────────────
    QWidget* buildFilesTab() {
        QWidget* tab = new QWidget();
        QSplitter* splitter = new QSplitter(Qt::Horizontal, tab);
        QVBoxLayout* layout = new QVBoxLayout(tab);
        layout->addWidget(splitter); layout->setContentsMargins(0,8,0,0);

        // Left
        QWidget* left = new QWidget();
        QVBoxLayout* ll = new QVBoxLayout(left); ll->setSpacing(10);

        QGroupBox* uploadBox = new QGroupBox("Upload File");
        QVBoxLayout* ul = new QVBoxLayout(uploadBox);
        auto lbl = [](const QString& t) {
            QLabel* l = new QLabel(t); l->setStyleSheet("color:#8b949e; font-size:12px;"); return l;
        };
        ul->addWidget(lbl("Filename"));
        filenameInput = new QLineEdit(); filenameInput->setPlaceholderText("e.g. report.txt"); filenameInput->setMinimumHeight(36);
        ul->addWidget(filenameInput);
        ul->addWidget(lbl("File Content"));
        fileContentInput = new QTextEdit();
        fileContentInput->setPlaceholderText("Type or paste content here...\nMax size: 100 MB");
        fileContentInput->setMaximumHeight(100);
        ul->addWidget(fileContentInput);
        scanLabel = new QLabel("Ready to upload");
        scanLabel->setStyleSheet("color:#8b949e; font-size:11px;");
        ul->addWidget(scanLabel);
        progressBar = new QProgressBar();
        progressBar->setRange(0,100); progressBar->setValue(0);
        progressBar->setVisible(false); progressBar->setMaximumHeight(8);
        ul->addWidget(progressBar);
        QPushButton* uploadBtn = new QPushButton("⬆  Upload  (AES-256 + 5-Layer Scan)");
        uploadBtn->setObjectName("primaryBtn"); uploadBtn->setMinimumHeight(42);
        ul->addWidget(uploadBtn);
        ll->addWidget(uploadBox);

        // Share box
        QGroupBox* shareBox = new QGroupBox("Share File");
        QVBoxLayout* sl = new QVBoxLayout(shareBox);
        sl->addWidget(lbl("Select a file above, then enter target username:"));
        shareTargetInput = new QLineEdit();
        shareTargetInput->setPlaceholderText("Target username (e.g. kamriz)");
        shareTargetInput->setMinimumHeight(34);
        sl->addWidget(shareTargetInput);
        QPushButton* shareBtn = new QPushButton("🤝  Share Selected File");
        shareBtn->setObjectName("shareBtn"); shareBtn->setMinimumHeight(36);
        sl->addWidget(shareBtn);
        ll->addWidget(shareBox);

        QGroupBox* actBox = new QGroupBox("File Actions");
        QVBoxLayout* al = new QVBoxLayout(actBox);
        QPushButton* refreshBtn  = new QPushButton("↻  Refresh File List");
        QPushButton* downloadBtn = new QPushButton("⬇  Download Selected");
        QPushButton* deleteBtn   = new QPushButton("🗑  Delete Selected");
        downloadBtn->setObjectName("successBtn");
        deleteBtn->setObjectName("dangerBtn");
        for (auto* b : {refreshBtn, downloadBtn, deleteBtn}) { b->setMinimumHeight(36); al->addWidget(b); }
        ll->addWidget(actBox);
        ll->addStretch();
        splitter->addWidget(left);

        // Right
        QWidget* right = new QWidget();
        QVBoxLayout* rl = new QVBoxLayout(right);

        QGroupBox* filesBox = new QGroupBox("My Files");
        QVBoxLayout* fl = new QVBoxLayout(filesBox);
        QWidget* hdr = new QWidget();
        QHBoxLayout* hl = new QHBoxLayout(hdr); hl->setContentsMargins(8,2,8,2);
        auto mkhdr = [](const QString& t, int w) {
            QLabel* l = new QLabel(t);
            l->setStyleSheet("color:#58a6ff; font-size:11px; font-weight:bold;");
            l->setFixedWidth(w); return l;
        };
        hl->addWidget(mkhdr("",         28));
        hl->addWidget(mkhdr("Filename", 150));
        hl->addWidget(mkhdr("Size",      60));
        hl->addWidget(mkhdr("Uploaded", 130));
        hl->addWidget(mkhdr("Enc",       30));
        fl->addWidget(hdr);
        fileList = new QListWidget(); fileList->setMinimumHeight(200);
        fl->addWidget(fileList);
        rl->addWidget(filesBox);

        QGroupBox* outBox = new QGroupBox("Server Output");
        QVBoxLayout* ol = new QVBoxLayout(outBox);
        outputArea = new QTextEdit(); outputArea->setReadOnly(true); outputArea->setMinimumHeight(130);
        ol->addWidget(outputArea);
        QPushButton* clearBtn = new QPushButton("Clear");
        clearBtn->setStyleSheet("background:#21262d; padding:5px; font-size:12px;");
        ol->addWidget(clearBtn);
        rl->addWidget(outBox);

        splitter->addWidget(right);
        splitter->setSizes({300, 660});

        connect(uploadBtn,   &QPushButton::clicked, this, &SecureShareApp::doUpload);
        connect(refreshBtn,  &QPushButton::clicked, this, &SecureShareApp::doList);
        connect(downloadBtn, &QPushButton::clicked, this, &SecureShareApp::doDownload);
        connect(deleteBtn,   &QPushButton::clicked, this, &SecureShareApp::doDelete);
        connect(shareBtn,    &QPushButton::clicked, this, &SecureShareApp::doShare);
        connect(clearBtn,    &QPushButton::clicked, outputArea, &QTextEdit::clear);
        connect(fileList,    &QListWidget::itemClicked, this, &SecureShareApp::onFileSelected);
        return tab;
    }

    // ── TAB 2: SHARED WITH ME ────────────────────────────
    QWidget* buildSharedTab() {
        QWidget* tab = new QWidget();
        QVBoxLayout* layout = new QVBoxLayout(tab);
        layout->setSpacing(12); layout->setContentsMargins(16,12,16,12);

        QLabel* info = new QLabel("Files other users have shared with you. Click a file then download it.");
        info->setStyleSheet("color:#8b949e; font-size:12px; padding:6px; background:#161b22; border-radius:6px; border:1px solid #30363d;");
        layout->addWidget(info);

        QGroupBox* sharedBox = new QGroupBox("Shared With Me");
        QVBoxLayout* sl = new QVBoxLayout(sharedBox);

        // Column headers
        QWidget* hdr = new QWidget();
        QHBoxLayout* hl = new QHBoxLayout(hdr); hl->setContentsMargins(8,2,8,2);
        auto mkhdr = [](const QString& t, int w) {
            QLabel* l = new QLabel(t);
            l->setStyleSheet("color:#58a6ff; font-size:11px; font-weight:bold;");
            l->setFixedWidth(w); return l;
        };
        hl->addWidget(mkhdr("",       28));
        hl->addWidget(mkhdr("Owner",  110));
        hl->addWidget(mkhdr("Filename", 150));
        hl->addWidget(mkhdr("Size",    60));
        hl->addWidget(mkhdr("Shared",  130));
        sl->addWidget(hdr);

        sharedList = new QListWidget(); sharedList->setMinimumHeight(280);
        sl->addWidget(sharedList);
        layout->addWidget(sharedBox);

        QHBoxLayout* btnRow = new QHBoxLayout();
        QPushButton* refreshSharedBtn  = new QPushButton("↻  Refresh");
        QPushButton* downloadSharedBtn = new QPushButton("⬇  Download Selected");
        refreshSharedBtn->setMinimumHeight(36);
        downloadSharedBtn->setObjectName("successBtn"); downloadSharedBtn->setMinimumHeight(36);
        btnRow->addWidget(refreshSharedBtn);
        btnRow->addWidget(downloadSharedBtn);
        layout->addLayout(btnRow);
        layout->addStretch();

        connect(refreshSharedBtn,  &QPushButton::clicked, this, &SecureShareApp::doListShared);
        connect(downloadSharedBtn, &QPushButton::clicked, this, &SecureShareApp::doDownloadShared);
        return tab;
    }

    // ── TAB 3: PERMISSIONS ───────────────────────────────
    QWidget* buildPermissionsTab() {
        QWidget* tab = new QWidget();
        QVBoxLayout* layout = new QVBoxLayout(tab);
        layout->setSpacing(16); layout->setContentsMargins(20,16,20,16);

        QLabel* info = new QLabel(
            "Set access permissions for your files — inspired by Unix chmod.\n"
            "Owner: full control  |  Read-Only: can download, cannot delete  |  No Access: blocked"
        );
        info->setStyleSheet("color:#8b949e; font-size:12px; padding:8px; background:#161b22; border-radius:6px; border:1px solid #30363d;");
        info->setWordWrap(true);
        layout->addWidget(info);

        QGroupBox* permBox = new QGroupBox("Set File Permission");
        QVBoxLayout* pl = new QVBoxLayout(permBox); pl->setSpacing(12);
        auto lbl = [](const QString& t) {
            QLabel* l = new QLabel(t);
            l->setStyleSheet("color:#8b949e; font-size:12px; font-weight:bold;");
            return l;
        };

        pl->addWidget(lbl("Filename (must be your file)"));
        permFilename = new QLineEdit(); permFilename->setPlaceholderText("e.g. report.txt"); permFilename->setMinimumHeight(36);
        pl->addWidget(permFilename);

        pl->addWidget(lbl("Target Username (who you're giving access to)"));
        permTargetUser = new QLineEdit(); permTargetUser->setPlaceholderText("e.g. alice"); permTargetUser->setMinimumHeight(36);
        pl->addWidget(permTargetUser);

        pl->addWidget(lbl("Permission Level"));
        permLevel = new QComboBox(); permLevel->setMinimumHeight(36);
        permLevel->addItem("🔒  No Access   (blocked completely)", "no_access");
        permLevel->addItem("👁  Read-Only   (can download only)",  "read_only");
        permLevel->addItem("👑  Owner       (full control)",       "owner");
        pl->addWidget(permLevel);

        QPushButton* setPermBtn = new QPushButton("Apply Permission");
        setPermBtn->setObjectName("warnBtn"); setPermBtn->setMinimumHeight(42);
        pl->addWidget(setPermBtn);

        QPushButton* getPermBtn = new QPushButton("Check My Permission on This File");
        getPermBtn->setMinimumHeight(36);
        pl->addWidget(getPermBtn);

        layout->addWidget(permBox);

        QGroupBox* permOutBox = new QGroupBox("Permission Output");
        QVBoxLayout* pol = new QVBoxLayout(permOutBox);
        QTextEdit* permOutput = new QTextEdit(); permOutput->setReadOnly(true); permOutput->setMinimumHeight(120);
        pol->addWidget(permOutput);
        layout->addWidget(permOutBox);
        layout->addStretch();

        connect(setPermBtn, &QPushButton::clicked, [this, permOutput]() {
            if (currentToken.isEmpty()) { permOutput->append("[!] Please login first"); return; }
            string filename   = permFilename->text().toStdString();
            string targetUser = permTargetUser->text().toStdString();
            string permission = permLevel->currentData().toString().toStdString();
            if (filename.empty() || targetUser.empty()) { permOutput->append("[!] Filename and target user required"); return; }
            string response = sendCommand("SETPERM " + currentToken.toStdString() + ":" + filename + ":" + targetUser + ":" + permission);
            permOutput->append(QString::fromStdString(response));
        });

        connect(getPermBtn, &QPushButton::clicked, [this, permOutput]() {
            if (currentToken.isEmpty()) { permOutput->append("[!] Please login first"); return; }
            string filename = permFilename->text().toStdString();
            if (filename.empty()) { permOutput->append("[!] Enter filename"); return; }
            string response = sendCommand("GETPERM " + currentToken.toStdString() + ":" + filename);
            permOutput->append(QString::fromStdString(response));
        });

        return tab;
    }

    // ── TAB 4: ACTIVITY LOG ──────────────────────────────
    QWidget* buildActivityTab() {
        QWidget* tab = new QWidget();
        QVBoxLayout* layout = new QVBoxLayout(tab);
        layout->setSpacing(12); layout->setContentsMargins(20,16,20,16);

        QLabel* info = new QLabel("Your personal activity log — all file operations timestamped and recorded.");
        info->setStyleSheet("color:#8b949e; font-size:12px;");
        layout->addWidget(info);

        QGroupBox* logBox = new QGroupBox("Activity Log (Last 20 Operations)");
        QVBoxLayout* ll = new QVBoxLayout(logBox);
        logArea = new QTextEdit(); logArea->setReadOnly(true); logArea->setMinimumHeight(320);
        logArea->setStyleSheet("font-family:'Courier New',monospace; font-size:12px; color:#2ea043; background:#0d1117;");
        ll->addWidget(logArea);
        QPushButton* refreshLog = new QPushButton("↻  Refresh Log");
        refreshLog->setObjectName("successBtn"); refreshLog->setMinimumHeight(36);
        ll->addWidget(refreshLog);
        layout->addWidget(logBox);
        layout->addStretch();

        connect(refreshLog, &QPushButton::clicked, this, &SecureShareApp::doRefreshLog);
        return tab;
    }

    // ── FILE ROW HELPERS ─────────────────────────────────
    void addFileRow(const QString& filename, const QString& size, const QString& date) {
        QListWidgetItem* item = new QListWidgetItem(fileList);
        item->setSizeHint(QSize(0, 38));
        item->setData(Qt::UserRole, filename);
        QWidget* row = new QWidget();
        QHBoxLayout* rl = new QHBoxLayout(row); rl->setContentsMargins(6,2,6,2);
        QLabel* icon = new QLabel(fileIcon(filename)); icon->setFixedWidth(26); icon->setStyleSheet("font-size:16px;");
        rl->addWidget(icon);
        QLabel* name = new QLabel(filename); name->setFixedWidth(148); name->setStyleSheet("color:#c9d1d9; font-weight:bold;");
        rl->addWidget(name);
        QLabel* sz = new QLabel(size); sz->setFixedWidth(58); sz->setStyleSheet("color:#8b949e; font-size:11px;");
        rl->addWidget(sz);
        QLabel* dt = new QLabel(date); dt->setFixedWidth(128); dt->setStyleSheet("color:#8b949e; font-size:11px;");
        rl->addWidget(dt);
        QLabel* enc = new QLabel("🔒"); enc->setStyleSheet("font-size:13px;"); enc->setToolTip("AES-256 Encrypted");
        rl->addWidget(enc);
        fileList->setItemWidget(item, row);
    }

    void addSharedRow(const QString& owner, const QString& filename,
                      const QString& size,  const QString& date) {
        QListWidgetItem* item = new QListWidgetItem(sharedList);
        item->setSizeHint(QSize(0, 38));
        item->setData(Qt::UserRole, owner + "|" + filename);
        QWidget* row = new QWidget();
        QHBoxLayout* rl = new QHBoxLayout(row); rl->setContentsMargins(6,2,6,2);
        QLabel* icon = new QLabel(fileIcon(filename)); icon->setFixedWidth(26); icon->setStyleSheet("font-size:16px;");
        rl->addWidget(icon);
        QLabel* ownLbl = new QLabel(owner); ownLbl->setFixedWidth(108);
        ownLbl->setStyleSheet("color:#8957e5; font-weight:bold; font-size:11px;");
        rl->addWidget(ownLbl);
        QLabel* name = new QLabel(filename); name->setFixedWidth(148); name->setStyleSheet("color:#c9d1d9; font-weight:bold;");
        rl->addWidget(name);
        QLabel* sz = new QLabel(size); sz->setFixedWidth(58); sz->setStyleSheet("color:#8b949e; font-size:11px;");
        rl->addWidget(sz);
        QLabel* dt = new QLabel(date); dt->setFixedWidth(128); dt->setStyleSheet("color:#8b949e; font-size:11px;");
        rl->addWidget(dt);
        sharedList->setItemWidget(item, row);
    }

public slots:
    void onFileSelected(QListWidgetItem* item) {
        filenameInput->setText(item->data(Qt::UserRole).toString());
    }

    void doRegister() {
        string user = loginUser->text().toStdString();
        string pass = loginPass->text().toStdString();
        if (user.empty() || pass.empty()) { loginStatus->setText("Fill in both fields"); return; }
        string response = sendCommand("REGISTER " + user + ":" + pass);
        bool ok = response.find("SUCCESS") != string::npos;
        loginStatus->setStyleSheet(ok ? "color:#2ea043;" : "color:#f85149;");
        loginStatus->setText(QString::fromStdString(response));
    }

    void doLogin() {
        string user = loginUser->text().toStdString();
        string pass = loginPass->text().toStdString();
        if (user.empty() || pass.empty()) { loginStatus->setText("Fill in both fields"); return; }
        string response = sendCommand("LOGIN " + user + ":" + pass);
        if (response.find("SUCCESS") != string::npos) {
            size_t pos = response.find("TOKEN: ");
            if (pos != string::npos) {
                currentToken = QString::fromStdString(response.substr(pos + 7)).trimmed();
                currentUser  = QString::fromStdString(user);
                userLabel->setText("Signed in as: " + currentUser);
                stack->setCurrentWidget(mainPage);
                doList();
                doListShared();
            }
        } else {
            loginStatus->setStyleSheet("color:#f85149;");
            loginStatus->setText("Invalid credentials");
        }
    }

    void doLogout() {
        currentToken.clear(); currentUser.clear();
        loginUser->clear(); loginPass->clear(); loginStatus->clear();
        fileList->clear(); sharedList->clear(); outputArea->clear();
        stack->setCurrentWidget(loginPage);
    }

    void doUpload() {
        if (currentToken.isEmpty()) return;
        string filename = filenameInput->text().toStdString();
        string content  = fileContentInput->toPlainText().toStdString();
        if (filename.empty() || content.empty()) { outputArea->append("[!] Filename and content required"); return; }

        scanLabel->setText("Running 5-layer security scan...");
        scanLabel->setStyleSheet("color:#d29922; font-size:11px;");
        progressBar->setVisible(true); progressBar->setValue(0);
        for (int i = 0; i <= 80; i += 20) {
            progressBar->setValue(i);
            QApplication::processEvents();
            QThread::msleep(50);
        }
        string response = sendCommand("UPLOAD " + currentToken.toStdString() + ":" + filename + ":" + content);
        progressBar->setValue(100);
        QApplication::processEvents();
        QTimer::singleShot(600, [this]() { progressBar->setVisible(false); progressBar->setValue(0); });

        if (response.find("SECURITY_BLOCK") != string::npos) {
            scanLabel->setText("BLOCKED: Security scan failed");
            scanLabel->setStyleSheet("color:#f85149; font-size:11px;");
            outputArea->append("[BLOCKED] " + QString::fromStdString(response));
        } else if (response.find("SUCCESS") != string::npos) {
            scanLabel->setText("Scan passed — uploaded and encrypted");
            scanLabel->setStyleSheet("color:#2ea043; font-size:11px;");
            outputArea->append("[OK] " + QString::fromStdString(response));
            filenameInput->clear(); fileContentInput->clear();
            doList();
        } else {
            scanLabel->setText("Upload failed");
            scanLabel->setStyleSheet("color:#f85149; font-size:11px;");
            outputArea->append("[ERR] " + QString::fromStdString(response));
        }
    }

    void doList() {
        if (currentToken.isEmpty()) return;
        string response = sendCommand("MYFILES " + currentToken.toStdString());
        fileList->clear();
        istringstream ss(response);
        string line;
        while (getline(ss, line)) {
            if (line.find("  - ") != string::npos) {
                string entry = line.substr(4);
                size_t p1 = entry.find('|'), p2 = entry.find('|', p1+1);
                QString fname, fsize, fdate;
                if (p1 != string::npos && p2 != string::npos) {
                    fname = QString::fromStdString(entry.substr(0, p1));
                    fsize = QString::fromStdString(entry.substr(p1+1, p2-p1-1));
                    fdate = QString::fromStdString(entry.substr(p2+1));
                } else { fname = QString::fromStdString(entry); fsize = "—"; fdate = "—"; }
                addFileRow(fname, fsize, fdate);
            }
        }
        outputArea->append(QString::fromStdString(response));
    }

    void doListShared() {
        if (currentToken.isEmpty()) return;
        string response = sendCommand("SHAREDWITHME " + currentToken.toStdString());
        sharedList->clear();
        istringstream ss(response);
        string line;
        while (getline(ss, line)) {
            if (line.find("  - ") != string::npos) {
                string entry = line.substr(4);
                // format: owner|filename|size|date
                size_t p1 = entry.find('|');
                size_t p2 = entry.find('|', p1+1);
                size_t p3 = entry.find('|', p2+1);
                if (p1 != string::npos && p2 != string::npos && p3 != string::npos) {
                    QString owner = QString::fromStdString(entry.substr(0, p1));
                    QString fname = QString::fromStdString(entry.substr(p1+1, p2-p1-1));
                    QString fsize = QString::fromStdString(entry.substr(p2+1, p3-p2-1));
                    QString fdate = QString::fromStdString(entry.substr(p3+1));
                    addSharedRow(owner, fname, fsize, fdate);
                }
            }
        }
    }

    void doDownload() {
        if (currentToken.isEmpty()) return;
        QString sel = filenameInput->text();
        if (sel.isEmpty() && fileList->currentItem())
            sel = fileList->currentItem()->data(Qt::UserRole).toString();
        if (sel.isEmpty()) { outputArea->append("[!] Select a file or enter filename"); return; }
        string response = sendCommand("DOWNLOAD " + currentToken.toStdString() + ":" + sel.toStdString());
        outputArea->append("[DOWNLOAD] " + sel + "\n" + QString::fromStdString(response));
    }

    void doDownloadShared() {
        if (currentToken.isEmpty()) return;
        if (!sharedList->currentItem()) { outputArea->append("[!] Select a shared file first"); return; }
        QString data = sharedList->currentItem()->data(Qt::UserRole).toString();
        int sep = data.indexOf('|');
        if (sep < 0) return;
        QString owner    = data.left(sep);
        QString filename = data.mid(sep + 1);
        string response = sendCommand("DOWNLOADAS " + currentToken.toStdString() + ":" +
                                      owner.toStdString() + ":" + filename.toStdString());
        outputArea->append("[SHARED DL] " + owner + "/" + filename + "\n" + QString::fromStdString(response));
    }

    void doDelete() {
        if (currentToken.isEmpty()) return;
        QString sel = filenameInput->text();
        if (sel.isEmpty() && fileList->currentItem())
            sel = fileList->currentItem()->data(Qt::UserRole).toString();
        if (sel.isEmpty()) { outputArea->append("[!] Select a file or enter filename"); return; }
        string response = sendCommand("DELETE " + currentToken.toStdString() + ":" + sel.toStdString());
        outputArea->append("[DELETE] " + QString::fromStdString(response));
        doList();
    }

    void doShare() {
        if (currentToken.isEmpty()) return;
        QString filename = filenameInput->text();
        if (filename.isEmpty() && fileList->currentItem())
            filename = fileList->currentItem()->data(Qt::UserRole).toString();
        QString target = shareTargetInput->text().trimmed();
        if (filename.isEmpty()) { outputArea->append("[!] Select a file to share first"); return; }
        if (target.isEmpty())   { outputArea->append("[!] Enter target username"); return; }
        string response = sendCommand("SHARE " + currentToken.toStdString() + ":" +
                                      filename.toStdString() + ":" + target.toStdString());
        outputArea->append("[SHARE] " + QString::fromStdString(response));
        if (response.find("SUCCESS") != string::npos)
            shareTargetInput->clear();
    }

    void doRefreshLog() {
        if (currentToken.isEmpty()) return;
        string response = sendCommand("MYLOG " + currentToken.toStdString());
        logArea->setPlainText(QString::fromStdString(response));
    }
};

#include "main.moc"

int main(int argc, char* argv[]) {
    QApplication app(argc, argv);
    app.setApplicationName("SecureShare");
    app.setApplicationVersion("8.0");
    SecureShareApp window;
    window.show();
    return app.exec();
}
