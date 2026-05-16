#include <iostream>
#include <string>
#include <thread>
#include <semaphore>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <sqlite3.h>
#include <sstream>
#include <iomanip>
#include <mutex>
#include <map>
#include <ctime>
#include <cstring>
#include <vector>
#include <algorithm>
#include <set>

using namespace std;

#define PORT           8080
#define MAX_CLIENTS    10
#define AES_IV_SIZE    16
#define AES_BLOCK      16
#define MAX_FILE_BYTES (100 * 1024 * 1024)

counting_semaphore<MAX_CLIENTS> sem(MAX_CLIENTS);
mutex db_mutex;
sqlite3* db;
map<string, string> sessions;

// ── SHA-256 ───────────────────────────────────────────────
string sha256(const string& input) {
    unsigned char digest[SHA256_DIGEST_LENGTH];
    SHA256((unsigned char*)input.c_str(), input.size(), digest);
    stringstream ss;
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++)
        ss << hex << setw(2) << setfill('0') << (int)digest[i];
    return ss.str();
}

// ── AES-256 ───────────────────────────────────────────────
string deriveKey(const string& password) {
    unsigned char digest[SHA256_DIGEST_LENGTH];
    SHA256((unsigned char*)password.c_str(), password.size(), digest);
    return string((char*)digest, SHA256_DIGEST_LENGTH);
}

string encryptAES(const string& plaintext, const string& password) {
    string key = deriveKey(password);
    unsigned char iv[AES_IV_SIZE];
    RAND_bytes(iv, AES_IV_SIZE);
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, (unsigned char*)key.c_str(), iv);
    vector<unsigned char> ciphertext(plaintext.size() + AES_BLOCK);
    int len = 0, total = 0;
    EVP_EncryptUpdate(ctx, ciphertext.data(), &len, (unsigned char*)plaintext.c_str(), plaintext.size());
    total += len;
    EVP_EncryptFinal_ex(ctx, ciphertext.data() + total, &len);
    total += len;
    EVP_CIPHER_CTX_free(ctx);
    string result(iv, iv + AES_IV_SIZE);
    result += string(ciphertext.begin(), ciphertext.begin() + total);
    return result;
}

string decryptAES(const string& ciphertext, const string& password) {
    if (ciphertext.size() < AES_IV_SIZE) return "";
    string key = deriveKey(password);
    unsigned char iv[AES_IV_SIZE];
    memcpy(iv, ciphertext.c_str(), AES_IV_SIZE);
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, (unsigned char*)key.c_str(), iv);
    vector<unsigned char> plaintext(ciphertext.size());
    int len = 0, total = 0;
    EVP_DecryptUpdate(ctx, plaintext.data(), &len, (unsigned char*)ciphertext.c_str() + AES_IV_SIZE, ciphertext.size() - AES_IV_SIZE);
    total += len;
    EVP_DecryptFinal_ex(ctx, plaintext.data() + total, &len);
    total += len;
    EVP_CIPHER_CTX_free(ctx);
    return string(plaintext.begin(), plaintext.begin() + total);
}

string toHex(const string& data) {
    ostringstream oss;
    for (unsigned char c : data)
        oss << hex << setw(2) << setfill('0') << (int)c;
    return oss.str();
}

string fromHex(const string& hex) {
    string result;
    for (size_t i = 0; i + 1 < hex.size(); i += 2) {
        unsigned char byte = stoi(hex.substr(i, 2), nullptr, 16);
        result += byte;
    }
    return result;
}

// ── 5-LAYER SECURITY SCAN ─────────────────────────────────
string securityScan(const string& filename, const string& content) {
    set<string> blockedExt = {
        ".exe",".bat",".sh",".php",".js",".py",
        ".rb",".pl",".vbs",".cmd",".ps1",".msi",
        ".dll",".so",".elf",".bin"
    };
    size_t dot = filename.rfind('.');
    if (dot != string::npos) {
        string ext = filename.substr(dot);
        transform(ext.begin(), ext.end(), ext.begin(), ::tolower);
        if (blockedExt.count(ext))
            return "SECURITY_BLOCK: Extension '" + ext + "' not allowed";
    }
    if (content.size() > MAX_FILE_BYTES)
        return "SECURITY_BLOCK: File too large (max 100 MB)";

    vector<string> malwareSigs = {
        "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR",
        "TVqQAAMAAAAEAAAA","#!/bin/sh","#!/bin/bash",
        "<script>","eval(base64_decode","exec(","system(",
        "shell_exec(","powershell -","cmd.exe","nc -e",
        "wget http","curl http","chmod +x"
    };
    string lower = content;
    transform(lower.begin(), lower.end(), lower.begin(), ::tolower);
    for (const string& sig : malwareSigs) {
        string ls = sig;
        transform(ls.begin(), ls.end(), ls.begin(), ::tolower);
        if (lower.find(ls) != string::npos)
            return "SECURITY_BLOCK: Malware signature detected";
    }
    int nullCount = 0;
    for (unsigned char c : content) if (c == 0x00) nullCount++;
    if (nullCount > 5)
        return "SECURITY_BLOCK: Binary file detected";

    vector<string> injPatterns = {
        "'; drop table","' or '1'='1","union select",
        "insert into","delete from","xp_cmdshell",
        "<iframe","javascript:","onerror=","onload="
    };
    for (const string& p : injPatterns)
        if (lower.find(p) != string::npos)
            return "SECURITY_BLOCK: Injection pattern detected";

    return "CLEAN";
}

// ── DATABASE ──────────────────────────────────────────────
void initDatabase() {
    sqlite3_open("secureshare.db", &db);
    const char* sql =
        "CREATE TABLE IF NOT EXISTS users "
        "(username TEXT PRIMARY KEY, password_hash TEXT NOT NULL);"

        "CREATE TABLE IF NOT EXISTS sessions "
        "(token TEXT PRIMARY KEY, username TEXT NOT NULL);"

        "CREATE TABLE IF NOT EXISTS files "
        "(id INTEGER PRIMARY KEY, owner TEXT NOT NULL, "
        "filename TEXT NOT NULL, content TEXT NOT NULL, "
        "filesize INTEGER DEFAULT 0, upload_time INTEGER DEFAULT 0);"

        "CREATE TABLE IF NOT EXISTS permissions "
        "(id INTEGER PRIMARY KEY, filename TEXT NOT NULL, "
        "owner TEXT NOT NULL, target_user TEXT NOT NULL, "
        "permission TEXT NOT NULL DEFAULT 'no_access');"

        "CREATE TABLE IF NOT EXISTS shared_files "
        "(id INTEGER PRIMARY KEY, owner TEXT NOT NULL, "
        "filename TEXT NOT NULL, shared_with TEXT NOT NULL, "
        "shared_time INTEGER DEFAULT 0);"

        "CREATE TABLE IF NOT EXISTS activity_log "
        "(id INTEGER PRIMARY KEY, username TEXT NOT NULL, "
        "action TEXT NOT NULL, detail TEXT, "
        "timestamp INTEGER NOT NULL);";

    sqlite3_exec(db, sql, 0, 0, 0);
    sqlite3_exec(db, "ALTER TABLE files ADD COLUMN filesize INTEGER DEFAULT 0;", 0, 0, 0);
    sqlite3_exec(db, "ALTER TABLE files ADD COLUMN upload_time INTEGER DEFAULT 0;", 0, 0, 0);
    cout << "[DATABASE] Ready — users, files, permissions, shared_files, activity_log" << endl;
}

// ── ACTIVITY LOG ──────────────────────────────────────────
void logActivity(const string& username, const string& action, const string& detail) {
    lock_guard<mutex> lock(db_mutex);
    sqlite3_stmt* stmt;
    sqlite3_prepare_v2(db,
        "INSERT INTO activity_log (username, action, detail, timestamp) VALUES (?, ?, ?, ?);",
        -1, &stmt, 0);
    sqlite3_bind_text(stmt, 1, username.c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 2, action.c_str(),   -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 3, detail.c_str(),   -1, SQLITE_STATIC);
    sqlite3_bind_int64(stmt, 4, (long long)time(nullptr));
    sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    cout << "[LOG] " << username << " | " << action << " | " << detail << endl;
}

string getActivityLog(const string& username) {
    lock_guard<mutex> lock(db_mutex);
    sqlite3_stmt* stmt;
    sqlite3_prepare_v2(db,
        "SELECT action, detail, timestamp FROM activity_log "
        "WHERE username=? ORDER BY timestamp DESC LIMIT 20;",
        -1, &stmt, 0);
    sqlite3_bind_text(stmt, 1, username.c_str(), -1, SQLITE_STATIC);
    string result = "Activity Log:\n";
    while (sqlite3_step(stmt) == SQLITE_ROW) {
        string action = (const char*)sqlite3_column_text(stmt, 0);
        string detail = (const char*)sqlite3_column_text(stmt, 1);
        long long ts  = sqlite3_column_int64(stmt, 2);
        char tbuf[32];
        time_t t = (time_t)ts;
        strftime(tbuf, sizeof(tbuf), "%Y-%m-%d %H:%M:%S", localtime(&t));
        result += "  [" + string(tbuf) + "] " + action + " — " + detail + "\n";
    }
    sqlite3_finalize(stmt);
    return result;
}

// ── AUTH ──────────────────────────────────────────────────
bool registerUser(const string& username, const string& password) {
    lock_guard<mutex> lock(db_mutex);
    string hash = sha256(password);
    sqlite3_stmt* stmt;
    sqlite3_prepare_v2(db, "INSERT INTO users (username, password_hash) VALUES (?, ?);", -1, &stmt, 0);
    sqlite3_bind_text(stmt, 1, username.c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 2, hash.c_str(),     -1, SQLITE_STATIC);
    int rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    return rc == SQLITE_DONE;
}

string loginUser(const string& username, const string& password) {
    lock_guard<mutex> lock(db_mutex);
    string hash = sha256(password);
    sqlite3_stmt* stmt;
    sqlite3_prepare_v2(db, "SELECT username FROM users WHERE username=? AND password_hash=?;", -1, &stmt, 0);
    sqlite3_bind_text(stmt, 1, username.c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 2, hash.c_str(),     -1, SQLITE_STATIC);
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        sqlite3_finalize(stmt);
        string token = sha256(username + password + to_string(time(nullptr)));
        sqlite3_stmt* ts;
        sqlite3_prepare_v2(db, "INSERT INTO sessions (token, username) VALUES (?, ?);", -1, &ts, 0);
        sqlite3_bind_text(ts, 1, token.c_str(),    -1, SQLITE_STATIC);
        sqlite3_bind_text(ts, 2, username.c_str(), -1, SQLITE_STATIC);
        sqlite3_step(ts);
        sqlite3_finalize(ts);
        sessions[token] = username;
        return token;
    }
    sqlite3_finalize(stmt);
    return "";
}

string getUsername(const string& token) {
    lock_guard<mutex> lock(db_mutex);
    if (sessions.count(token)) return sessions[token];
    sqlite3_stmt* stmt;
    sqlite3_prepare_v2(db, "SELECT username FROM sessions WHERE token=?;", -1, &stmt, 0);
    sqlite3_bind_text(stmt, 1, token.c_str(), -1, SQLITE_STATIC);
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        string user = (char*)sqlite3_column_text(stmt, 0);
        sqlite3_finalize(stmt);
        sessions[token] = user;
        return user;
    }
    sqlite3_finalize(stmt);
    return "";
}

// ── PERMISSIONS ───────────────────────────────────────────
string getFileOwner(const string& filename) {
    lock_guard<mutex> lock(db_mutex);
    sqlite3_stmt* stmt;
    sqlite3_prepare_v2(db, "SELECT owner FROM files WHERE filename=?;", -1, &stmt, 0);
    sqlite3_bind_text(stmt, 1, filename.c_str(), -1, SQLITE_STATIC);
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        string owner = (char*)sqlite3_column_text(stmt, 0);
        sqlite3_finalize(stmt);
        return owner;
    }
    sqlite3_finalize(stmt);
    return "";
}

string getPermission(const string& filename, const string& owner, const string& requester) {
    if (owner == requester) return "owner";
    lock_guard<mutex> lock(db_mutex);
    sqlite3_stmt* stmt;
    sqlite3_prepare_v2(db,
        "SELECT permission FROM permissions WHERE filename=? AND owner=? AND target_user=?;",
        -1, &stmt, 0);
    sqlite3_bind_text(stmt, 1, filename.c_str(),  -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 2, owner.c_str(),     -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 3, requester.c_str(), -1, SQLITE_STATIC);
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        string perm = (char*)sqlite3_column_text(stmt, 0);
        sqlite3_finalize(stmt);
        return perm;
    }
    sqlite3_finalize(stmt);
    return "no_access";
}

bool setPermission(const string& filename, const string& owner,
                   const string& targetUser, const string& permission) {
    lock_guard<mutex> lock(db_mutex);
    sqlite3_stmt* stmt;
    sqlite3_prepare_v2(db,
        "DELETE FROM permissions WHERE filename=? AND owner=? AND target_user=?;",
        -1, &stmt, 0);
    sqlite3_bind_text(stmt, 1, filename.c_str(),   -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 2, owner.c_str(),      -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 3, targetUser.c_str(), -1, SQLITE_STATIC);
    sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    sqlite3_prepare_v2(db,
        "INSERT INTO permissions (filename, owner, target_user, permission) VALUES (?, ?, ?, ?);",
        -1, &stmt, 0);
    sqlite3_bind_text(stmt, 1, filename.c_str(),   -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 2, owner.c_str(),      -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 3, targetUser.c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 4, permission.c_str(), -1, SQLITE_STATIC);
    int rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    return rc == SQLITE_DONE;
}

// ── FILE OPERATIONS ───────────────────────────────────────
bool saveFile(const string& owner, const string& filename, const string& content) {
    lock_guard<mutex> lock(db_mutex);
    string encrypted   = encryptAES(content, "secureshare_master_key");
    string hex_content = toHex(encrypted);
    long long filesize    = content.size();
    long long upload_time = time(nullptr);
    sqlite3_stmt* stmt;
    sqlite3_prepare_v2(db, "DELETE FROM files WHERE owner=? AND filename=?;", -1, &stmt, 0);
    sqlite3_bind_text(stmt, 1, owner.c_str(),    -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 2, filename.c_str(), -1, SQLITE_STATIC);
    sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    sqlite3_prepare_v2(db,
        "INSERT INTO files (owner, filename, content, filesize, upload_time) VALUES (?, ?, ?, ?, ?);",
        -1, &stmt, 0);
    sqlite3_bind_text(stmt,  1, owner.c_str(),       -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt,  2, filename.c_str(),    -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt,  3, hex_content.c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_int64(stmt, 4, filesize);
    sqlite3_bind_int64(stmt, 5, upload_time);
    int rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    return rc == SQLITE_DONE;
}

string loadFile(const string& owner, const string& filename) {
    lock_guard<mutex> lock(db_mutex);
    sqlite3_stmt* stmt;
    sqlite3_prepare_v2(db,
        "SELECT content FROM files WHERE owner=? AND filename=?;",
        -1, &stmt, 0);
    sqlite3_bind_text(stmt, 1, owner.c_str(),    -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 2, filename.c_str(), -1, SQLITE_STATIC);
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        string hex_content = (const char*)sqlite3_column_text(stmt, 0);
        sqlite3_finalize(stmt);
        return decryptAES(fromHex(hex_content), "secureshare_master_key");
    }
    sqlite3_finalize(stmt);
    return "";
}

string listFiles(const string& owner) {
    lock_guard<mutex> lock(db_mutex);
    sqlite3_stmt* stmt;
    sqlite3_prepare_v2(db,
        "SELECT filename, filesize, upload_time FROM files WHERE owner=? ORDER BY upload_time DESC;",
        -1, &stmt, 0);
    sqlite3_bind_text(stmt, 1, owner.c_str(), -1, SQLITE_STATIC);
    string result = "Files:\n";
    int count = 0;
    while (sqlite3_step(stmt) == SQLITE_ROW) {
        string fname  = (const char*)sqlite3_column_text(stmt, 0);
        long long fsz = sqlite3_column_int64(stmt, 1);
        long long ft  = sqlite3_column_int64(stmt, 2);
        string sizeStr;
        if (fsz < 1024) sizeStr = to_string(fsz) + "B";
        else if (fsz < 1024*1024) sizeStr = to_string(fsz/1024) + "KB";
        else sizeStr = to_string(fsz/(1024*1024)) + "MB";
        char tbuf[32];
        time_t t = (time_t)ft;
        strftime(tbuf, sizeof(tbuf), "%Y-%m-%d %H:%M", localtime(&t));
        result += "  - " + fname + "|" + sizeStr + "|" + string(tbuf) + "\n";
        count++;
    }
    sqlite3_finalize(stmt);
    if (count == 0) return "No files found\n";
    return result;
}

bool deleteFile(const string& owner, const string& filename) {
    lock_guard<mutex> lock(db_mutex);
    sqlite3_stmt* stmt;
    sqlite3_prepare_v2(db, "DELETE FROM files WHERE owner=? AND filename=?;", -1, &stmt, 0);
    sqlite3_bind_text(stmt, 1, owner.c_str(),    -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 2, filename.c_str(), -1, SQLITE_STATIC);
    int rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    // remove permissions
    sqlite3_prepare_v2(db, "DELETE FROM permissions WHERE filename=? AND owner=?;", -1, &stmt, 0);
    sqlite3_bind_text(stmt, 1, filename.c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 2, owner.c_str(),    -1, SQLITE_STATIC);
    sqlite3_step(stmt); sqlite3_finalize(stmt);
    // remove shares
    sqlite3_prepare_v2(db, "DELETE FROM shared_files WHERE filename=? AND owner=?;", -1, &stmt, 0);
    sqlite3_bind_text(stmt, 1, filename.c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 2, owner.c_str(),    -1, SQLITE_STATIC);
    sqlite3_step(stmt); sqlite3_finalize(stmt);
    return rc == SQLITE_DONE;
}

// ── SHARING ───────────────────────────────────────────────
bool shareFile(const string& owner, const string& filename, const string& target) {
    lock_guard<mutex> lock(db_mutex);
    // verify file exists
    sqlite3_stmt* chk;
    sqlite3_prepare_v2(db, "SELECT id FROM files WHERE owner=? AND filename=?;", -1, &chk, 0);
    sqlite3_bind_text(chk, 1, owner.c_str(),    -1, SQLITE_STATIC);
    sqlite3_bind_text(chk, 2, filename.c_str(), -1, SQLITE_STATIC);
    if (sqlite3_step(chk) != SQLITE_ROW) { sqlite3_finalize(chk); return false; }
    sqlite3_finalize(chk);
    // verify target user exists
    sqlite3_stmt* uchk;
    sqlite3_prepare_v2(db, "SELECT username FROM users WHERE username=?;", -1, &uchk, 0);
    sqlite3_bind_text(uchk, 1, target.c_str(), -1, SQLITE_STATIC);
    if (sqlite3_step(uchk) != SQLITE_ROW) { sqlite3_finalize(uchk); return false; }
    sqlite3_finalize(uchk);
    // remove old share
    sqlite3_stmt* del;
    sqlite3_prepare_v2(db,
        "DELETE FROM shared_files WHERE owner=? AND filename=? AND shared_with=?;",
        -1, &del, 0);
    sqlite3_bind_text(del, 1, owner.c_str(),    -1, SQLITE_STATIC);
    sqlite3_bind_text(del, 2, filename.c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_text(del, 3, target.c_str(),   -1, SQLITE_STATIC);
    sqlite3_step(del); sqlite3_finalize(del);
    // insert share
    sqlite3_stmt* stmt;
    sqlite3_prepare_v2(db,
        "INSERT INTO shared_files (owner, filename, shared_with, shared_time) VALUES (?, ?, ?, ?);",
        -1, &stmt, 0);
    sqlite3_bind_text(stmt,  1, owner.c_str(),    -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt,  2, filename.c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt,  3, target.c_str(),   -1, SQLITE_STATIC);
    sqlite3_bind_int64(stmt, 4, time(nullptr));
    int rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    return rc == SQLITE_DONE;
}

string listSharedWithMe(const string& username) {
    lock_guard<mutex> lock(db_mutex);
    sqlite3_stmt* stmt;
    sqlite3_prepare_v2(db,
        "SELECT sf.owner, sf.filename, f.filesize, sf.shared_time "
        "FROM shared_files sf "
        "JOIN files f ON f.owner=sf.owner AND f.filename=sf.filename "
        "WHERE sf.shared_with=? ORDER BY sf.shared_time DESC;",
        -1, &stmt, 0);
    sqlite3_bind_text(stmt, 1, username.c_str(), -1, SQLITE_STATIC);
    string result = "SharedWithMe:\n";
    int count = 0;
    while (sqlite3_step(stmt) == SQLITE_ROW) {
        string owner = (const char*)sqlite3_column_text(stmt, 0);
        string fname = (const char*)sqlite3_column_text(stmt, 1);
        long long sz = sqlite3_column_int64(stmt, 2);
        long long st = sqlite3_column_int64(stmt, 3);
        string sizeStr;
        if (sz < 1024) sizeStr = to_string(sz) + "B";
        else if (sz < 1024*1024) sizeStr = to_string(sz/1024) + "KB";
        else sizeStr = to_string(sz/(1024*1024)) + "MB";
        char tbuf[32];
        time_t t = (time_t)st;
        strftime(tbuf, sizeof(tbuf), "%Y-%m-%d %H:%M", localtime(&t));
        result += "  - " + owner + "|" + fname + "|" + sizeStr + "|" + string(tbuf) + "\n";
        count++;
    }
    sqlite3_finalize(stmt);
    if (count == 0) return "No shared files\n";
    return result;
}

// ── COMMAND PARSER ────────────────────────────────────────
string parseCommand(const string& cmd) {

    // REGISTER user:pass
    if (cmd.substr(0, 9) == "REGISTER ") {
        string data = cmd.substr(9);
        size_t c = data.find(':');
        if (c == string::npos) return "ERROR: Invalid format";
        string user = data.substr(0, c);
        string pass = data.substr(c + 1);
        if (registerUser(user, pass)) {
            logActivity(user, "REGISTER", "New account created");
            return "SUCCESS: User " + user + " registered";
        }
        return "ERROR: Username already exists";
    }

    // LOGIN user:pass
    if (cmd.substr(0, 6) == "LOGIN ") {
        string data = cmd.substr(6);
        size_t c = data.find(':');
        if (c == string::npos) return "ERROR: Invalid format";
        string user = data.substr(0, c);
        string pass = data.substr(c + 1);
        string token = loginUser(user, pass);
        if (!token.empty()) {
            logActivity(user, "LOGIN", "Login successful");
            return "SUCCESS: Login successful\nTOKEN: " + token;
        }
        return "ERROR: Invalid credentials";
    }

    // UPLOAD token:filename:content
    if (cmd.substr(0, 7) == "UPLOAD ") {
        string data = cmd.substr(7);
        size_t c1 = data.find(':');
        string token    = data.substr(0, c1);
        string rest     = data.substr(c1 + 1);
        size_t c2       = rest.find(':');
        string filename = rest.substr(0, c2);
        string content  = rest.substr(c2 + 1);
        string owner    = getUsername(token);
        if (owner.empty()) return "ERROR: Invalid token";
        string scan = securityScan(filename, content);
        if (scan != "CLEAN") {
            logActivity(owner, "UPLOAD_BLOCKED", filename + " — " + scan);
            return scan;
        }
        if (saveFile(owner, filename, content)) {
            logActivity(owner, "UPLOAD", filename + " (" + to_string(content.size()) + "B)");
            return "SUCCESS: File " + filename + " uploaded (AES-256 encrypted, scan passed)";
        }
        return "ERROR: Upload failed";
    }

    // DOWNLOAD token:filename
    if (cmd.substr(0, 9) == "DOWNLOAD ") {
        string data      = cmd.substr(9);
        size_t c         = data.find(':');
        string token     = data.substr(0, c);
        string filename  = data.substr(c + 1);
        string requester = getUsername(token);
        if (requester.empty()) return "ERROR: Invalid token";
        string owner = getFileOwner(filename);
        if (owner.empty()) return "ERROR: File not found";
        string perm = getPermission(filename, owner, requester);
        if (perm == "no_access")
            return "ERROR: Access denied — no permission to read this file";
        string content = loadFile(owner, filename);
        if (!content.empty()) {
            logActivity(requester, "DOWNLOAD", filename);
            return "FILE CONTENT:\n" + content;
        }
        return "ERROR: File not found";
    }

    // DOWNLOADAS token:owner:filename  (shared file download)
    if (cmd.substr(0, 11) == "DOWNLOADAS ") {
        string data = cmd.substr(11);
        size_t c1 = data.find(':');
        size_t c2 = data.find(':', c1 + 1);
        if (c1 == string::npos || c2 == string::npos) return "ERROR: Invalid format";
        string token     = data.substr(0, c1);
        string owner     = data.substr(c1 + 1, c2 - c1 - 1);
        string filename  = data.substr(c2 + 1);
        string requester = getUsername(token);
        if (requester.empty()) return "ERROR: Invalid token";
        // check share exists
        sqlite3_stmt* stmt;
        sqlite3_prepare_v2(db,
            "SELECT id FROM shared_files WHERE owner=? AND filename=? AND shared_with=?;",
            -1, &stmt, 0);
        sqlite3_bind_text(stmt, 1, owner.c_str(),     -1, SQLITE_STATIC);
        sqlite3_bind_text(stmt, 2, filename.c_str(),  -1, SQLITE_STATIC);
        sqlite3_bind_text(stmt, 3, requester.c_str(), -1, SQLITE_STATIC);
        if (sqlite3_step(stmt) != SQLITE_ROW) {
            sqlite3_finalize(stmt);
            return "ERROR: File not shared with you";
        }
        sqlite3_finalize(stmt);
        string content = loadFile(owner, filename);
        if (!content.empty()) {
            logActivity(requester, "DOWNLOAD_SHARED", owner + "/" + filename);
            return "FILE CONTENT:\n" + content;
        }
        return "ERROR: File not found";
    }

    // MYFILES token
    if (cmd.substr(0, 7) == "MYFILES") {
        string token = cmd.substr(8);
        string owner = getUsername(token);
        if (owner.empty()) return "ERROR: Invalid token";
        logActivity(owner, "LIST_FILES", "Listed files");
        return listFiles(owner);
    }

    // DELETE token:filename
    if (cmd.substr(0, 7) == "DELETE ") {
        string data     = cmd.substr(7);
        size_t c        = data.find(':');
        string token    = data.substr(0, c);
        string filename = data.substr(c + 1);
        string owner    = getUsername(token);
        if (owner.empty()) return "ERROR: Invalid token";
        string fileOwner = getFileOwner(filename);
        if (fileOwner != owner)
            return "ERROR: Access denied — only the owner can delete";
        if (deleteFile(owner, filename)) {
            logActivity(owner, "DELETE", filename);
            return "SUCCESS: File " + filename + " deleted";
        }
        return "ERROR: Delete failed";
    }

    // SHARE token:filename:targetuser
    if (cmd.substr(0, 6) == "SHARE ") {
        string data = cmd.substr(6);
        size_t c1 = data.find(':');
        size_t c2 = data.find(':', c1 + 1);
        if (c1 == string::npos || c2 == string::npos) return "ERROR: Invalid format";
        string token    = data.substr(0, c1);
        string filename = data.substr(c1 + 1, c2 - c1 - 1);
        string target   = data.substr(c2 + 1);
        string owner    = getUsername(token);
        if (owner.empty()) return "ERROR: Invalid token";
        if (owner == target) return "ERROR: Cannot share with yourself";
        if (shareFile(owner, filename, target)) {
            logActivity(owner, "SHARE", filename + " → " + target);
            return "SUCCESS: " + filename + " shared with " + target;
        }
        return "ERROR: Share failed (file not found or user does not exist)";
    }

    // SHAREDWITHME token
    if (cmd.substr(0, 13) == "SHAREDWITHME ") {
        string token = cmd.substr(13);
        string user  = getUsername(token);
        if (user.empty()) return "ERROR: Invalid token";
        return listSharedWithMe(user);
    }

    // SETPERM token:filename:targetuser:permission
    if (cmd.substr(0, 8) == "SETPERM ") {
        string data = cmd.substr(8);
        size_t c1 = data.find(':');
        size_t c2 = data.find(':', c1 + 1);
        size_t c3 = data.find(':', c2 + 1);
        if (c1 == string::npos || c2 == string::npos || c3 == string::npos)
            return "ERROR: Invalid format";
        string token      = data.substr(0, c1);
        string filename   = data.substr(c1 + 1, c2 - c1 - 1);
        string targetUser = data.substr(c2 + 1, c3 - c2 - 1);
        string permission = data.substr(c3 + 1);
        string owner      = getUsername(token);
        if (owner.empty()) return "ERROR: Invalid token";
        string fileOwner = getFileOwner(filename);
        if (fileOwner != owner)
            return "ERROR: Only the file owner can set permissions";
        if (permission != "owner" && permission != "read_only" && permission != "no_access")
            return "ERROR: Invalid permission. Use: owner | read_only | no_access";
        if (setPermission(filename, owner, targetUser, permission)) {
            logActivity(owner, "SETPERM", filename + " → " + targetUser + ":" + permission);
            return "SUCCESS: " + targetUser + " now has " + permission + " access to " + filename;
        }
        return "ERROR: Failed to set permission";
    }

    // GETPERM token:filename
    if (cmd.substr(0, 8) == "GETPERM ") {
        string data     = cmd.substr(8);
        size_t c        = data.find(':');
        string token    = data.substr(0, c);
        string filename = data.substr(c + 1);
        string requester = getUsername(token);
        if (requester.empty()) return "ERROR: Invalid token";
        string owner = getFileOwner(filename);
        if (owner.empty()) return "ERROR: File not found";
        string perm = getPermission(filename, owner, requester);
        return "PERMISSION: " + requester + " has " + perm + " access to " + filename;
    }

    // MYLOG token
    if (cmd.substr(0, 6) == "MYLOG ") {
        string token = cmd.substr(6);
        string user  = getUsername(token);
        if (user.empty()) return "ERROR: Invalid token";
        return getActivityLog(user);
    }

    return "ERROR: Unknown command";
}

// ── CLIENT HANDLER ────────────────────────────────────────
void handleClient(int fd) {
    sem.acquire();
    const size_t BUFSIZE = 104857600;
    vector<char> buffer(BUFSIZE, 0);
    int total = 0, n;
    while ((n = read(fd, buffer.data() + total, BUFSIZE - total - 1)) > 0)
        total += n;
    buffer[total] = 0;
    string request(buffer.data(), total);
    string response = parseCommand(request);
    cout << "[IN]  " << request.substr(0, 80) << endl;
    cout << "[OUT] " << response.substr(0, 80) << endl;
    send(fd, response.c_str(), response.size(), 0);
    close(fd);
    sem.release();
}

// ── MAIN ──────────────────────────────────────────────────
int main() {
    initDatabase();
    int server_fd, client_fd;
    struct sockaddr_in address;
    int addrlen = sizeof(address);
    server_fd = socket(AF_INET, SOCK_STREAM, 0);
    int opt = 1;
    setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    address.sin_family      = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port        = htons(PORT);
    bind(server_fd,   (struct sockaddr*)&address, sizeof(address));
    listen(server_fd, 10);

    cout << "\n========================================" << endl;
    cout << "  SECURESHARE SERVER v8.0 — FINAL" << endl;
    cout << "  Port        : " << PORT << endl;
    cout << "  Encryption  : AES-256-CBC" << endl;
    cout << "  Auth        : SHA-256 + Session Tokens" << endl;
    cout << "  Storage     : SQLite3 (persistent)" << endl;
    cout << "  Max File    : 100 MB" << endl;
    cout << "  Security    : 5-Layer Scan" << endl;
    cout << "  Permissions : Owner / Read-Only / No-Access" << endl;
    cout << "  Sharing     : User-to-User" << endl;
    cout << "  Activity Log: Enabled" << endl;
    cout << "  Threads     : " << MAX_CLIENTS << " max (semaphore)" << endl;
    cout << "========================================\n" << endl;

    while (true) {
        client_fd = accept(server_fd, (struct sockaddr*)&address, (socklen_t*)&addrlen);
        thread(handleClient, client_fd).detach();
    }
    return 0;
}
