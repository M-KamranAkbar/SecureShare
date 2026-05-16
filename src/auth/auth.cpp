#include <iostream>
#include <string>
#include <unordered_map>
#include <openssl/sha.h>
#include <sstream>
#include <iomanip>

using namespace std;

// Store users: username -> hashed password
unordered_map<string, string> users_db;

// Store sessions: token -> username
unordered_map<string, string> sessions_db;

// SHA-256 hash function
string hashPassword(const string& password) {
    unsigned char digest[SHA256_DIGEST_LENGTH];
    SHA256((unsigned char*)password.c_str(), password.size(), digest);

    ostringstream oss;
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++)
        oss << hex << setw(2) << setfill('0') << (int)digest[i];

    return oss.str();
}

// Register new user
bool registerUser(const string& username, const string& password) {
    if (users_db.count(username)) {
        cout << "[!] Username already exists: " << username << endl;
        return false;
    }
    users_db[username] = hashPassword(password);
    cout << "[+] User registered: " << username << endl;
    return true;
}

// Login user
string loginUser(const string& username, const string& password) {
    if (!users_db.count(username)) {
        cout << "[!] User not found: " << username << endl;
        return "";
    }
    if (users_db[username] != hashPassword(password)) {
        cout << "[!] Wrong password for: " << username << endl;
        return "";
    }
    // Generate simple session token
    string token = hashPassword(username + password + "session");
    sessions_db[token] = username;
    cout << "[+] Login successful: " << username << endl;
    cout << "[+] Session token: " << token.substr(0, 16) << "..." << endl;
    return token;
}

// Validate session token
bool validateToken(const string& token) {
    return sessions_db.count(token) > 0;
}

// Test main
int main() {
    cout << "==========================================" << endl;
    cout << "   SecureShare Auth System v1.0" << endl;
    cout << "==========================================" << endl;

    // Register users
    registerUser("saad", "password123");
    registerUser("maarij", "securepass");
    registerUser("saad", "tryagain"); // should fail

    cout << "------------------------------------------" << endl;

    // Login tests
    string token1 = loginUser("saad", "password123");   // should work
    string token2 = loginUser("saad", "wrongpass");      // should fail
    string token3 = loginUser("ghost", "nopass");        // should fail

    cout << "------------------------------------------" << endl;

    // Validate tokens
    if (!token1.empty()) {
        cout << "[*] Token valid: " << validateToken(token1) << endl;
    }

    cout << "==========================================" << endl;
    return 0;
}
