#include <iostream>
#include <string>
#include <sqlite3.h>

using namespace std;

sqlite3* db;

// Open or create the database
bool initDB(const string& db_path) {
    int rc = sqlite3_open(db_path.c_str(), &db);
    if (rc != SQLITE_OK) {
        cerr << "[!] Cannot open database: " << sqlite3_errmsg(db) << endl;
        return false;
    }

    // Create users table if not exists
    const char* sql =
        "CREATE TABLE IF NOT EXISTS users ("
        "username TEXT PRIMARY KEY,"
        "password_hash TEXT NOT NULL"
        ");"
        "CREATE TABLE IF NOT EXISTS sessions ("
        "token TEXT PRIMARY KEY,"
        "username TEXT NOT NULL"
        ");"
        "CREATE TABLE IF NOT EXISTS files ("
        "filename TEXT NOT NULL,"
        "owner TEXT NOT NULL,"
        "permission TEXT DEFAULT 'owner'"
        ");";

    char* err = nullptr;
    rc = sqlite3_exec(db, sql, 0, 0, &err);
    if (rc != SQLITE_OK) {
        cerr << "[!] SQL error: " << err << endl;
        sqlite3_free(err);
        return false;
    }

    cout << "[+] Database initialized: " << db_path << endl;
    return true;
}

// Save user to DB
bool saveUser(const string& username, const string& hash) {
    string sql = "INSERT INTO users (username, password_hash) VALUES ('" 
                 + username + "', '" + hash + "');";
    char* err = nullptr;
    int rc = sqlite3_exec(db, sql.c_str(), 0, 0, &err);
    if (rc != SQLITE_OK) {
        cerr << "[!] User already exists or DB error: " << err << endl;
        sqlite3_free(err);
        return false;
    }
    cout << "[+] User saved to DB: " << username << endl;
    return true;
}

// Get stored hash for username
string getHash(const string& username) {
    string hash = "";
    string sql = "SELECT password_hash FROM users WHERE username='" 
                 + username + "';";

    sqlite3_stmt* stmt;
    sqlite3_prepare_v2(db, sql.c_str(), -1, &stmt, 0);
    if (sqlite3_step(stmt) == SQLITE_ROW)
        hash = (char*)sqlite3_column_text(stmt, 0);
    sqlite3_finalize(stmt);
    return hash;
}

// Save session token
bool saveSession(const string& token, const string& username) {
    string sql = "INSERT INTO sessions (token, username) VALUES ('"
                 + token + "', '" + username + "');";
    char* err = nullptr;
    sqlite3_exec(db, sql.c_str(), 0, 0, &err);
    return true;
}

// Validate session token
string validateSession(const string& token) {
    string username = "";
    string sql = "SELECT username FROM sessions WHERE token='" + token + "';";
    sqlite3_stmt* stmt;
    sqlite3_prepare_v2(db, sql.c_str(), -1, &stmt, 0);
    if (sqlite3_step(stmt) == SQLITE_ROW)
        username = (char*)sqlite3_column_text(stmt, 0);
    sqlite3_finalize(stmt);
    return username;
}

// Close DB
void closeDB() {
    sqlite3_close(db);
    cout << "[-] Database closed" << endl;
}

// Test main
int main() {
    cout << "==========================================" << endl;
    cout << "   SecureShare Storage Module v1.0" << endl;
    cout << "==========================================" << endl;

    initDB("secureshare.db");

    saveUser("saad", "hashedpassword123");
    saveUser("maarij", "hashedpassword456");
    saveUser("saad", "duplicate"); // should fail

    cout << "------------------------------------------" << endl;

    string hash = getHash("saad");
    cout << "[*] Hash for saad: " << hash << endl;

    saveSession("token_abc123", "saad");
    string user = validateSession("token_abc123");
    cout << "[*] Token owner: " << user << endl;

    cout << "==========================================" << endl;
    closeDB();
    return 0;
}
