#include <iostream>
#include <string>
#include <vector>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <sstream>
#include <iomanip>
#include <cstring>

using namespace std;

#define AES_KEY_SIZE 32
#define AES_IV_SIZE  16
#define AES_BLOCK    16

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
    EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL,
                       (unsigned char*)key.c_str(), iv);

    vector<unsigned char> ciphertext(plaintext.size() + AES_BLOCK);
    int len = 0, total = 0;

    EVP_EncryptUpdate(ctx, ciphertext.data(), &len,
                      (unsigned char*)plaintext.c_str(), plaintext.size());
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
    EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL,
                       (unsigned char*)key.c_str(), iv);

    vector<unsigned char> plaintext(ciphertext.size());
    int len = 0, total = 0;

    EVP_DecryptUpdate(ctx, plaintext.data(), &len,
                      (unsigned char*)ciphertext.c_str() + AES_IV_SIZE,
                      ciphertext.size() - AES_IV_SIZE);
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

int main() {
    cout << "========================================" << endl;
    cout << "  SECURESHARE Crypto Module v2.0" << endl;
    cout << "========================================" << endl;

    string password = "secureshare_secret_key";
    string message  = "This is a secret file content!";

    cout << "[>] Original  : " << message << endl;

    string encrypted = encryptAES(message, password);
    cout << "[+] Encrypted : " << toHex(encrypted).substr(0, 32) << "..." << endl;

    string decrypted = decryptAES(encrypted, password);
    cout << "[+] Decrypted : " << decrypted << endl;

    if (message == decrypted)
        cout << "[*] AES-256 SUCCESS" << endl;
    else
        cout << "[!] FAILED" << endl;

    cout << "========================================" << endl;
    return 0;
}
