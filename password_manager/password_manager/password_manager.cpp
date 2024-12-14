#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <sstream>
#include <iomanip>
#include <windows.h>
#include <wincrypt.h>

using namespace std;

// Utility function to hash the master password using Windows CryptoAPI
string hashPassword(const string& password) {
    HCRYPTPROV hProv = 0;
    HCRYPTHASH hHash = 0;
    BYTE hash[32]; // SHA-256 produces a 32-byte hash
    DWORD hashLength = 32;

    if (!CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {
        cerr << "Failed to acquire cryptography context." << endl;
        exit(1);
    }

    if (!CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash)) {
        cerr << "Failed to create hash object." << endl;
        CryptReleaseContext(hProv, 0);
        exit(1);
    }

    if (!CryptHashData(hHash, reinterpret_cast<const BYTE*>(password.c_str()), password.length(), 0)) {
        cerr << "Failed to hash data." << endl;
        CryptDestroyHash(hHash);
        CryptReleaseContext(hProv, 0);
        exit(1);
    }

    if (!CryptGetHashParam(hHash, HP_HASHVAL, hash, &hashLength, 0)) {
        cerr << "Failed to retrieve hash value." << endl;
        CryptDestroyHash(hHash);
        CryptReleaseContext(hProv, 0);
        exit(1);
    }

    CryptDestroyHash(hHash);
    CryptReleaseContext(hProv, 0);

    stringstream ss;
    for (DWORD i = 0; i < hashLength; i++) {
        ss << hex << setw(2) << setfill('0') << static_cast<int>(hash[i]);
    }
    return ss.str();
}

// Save the master password hash and credentials to a file
void saveToFile(const string& masterHash, const vector<pair<string, string>>& credentials) {
    ofstream file("passwords.dat");
    if (!file.is_open()) {
        cerr << "Failed to open the file for writing." << endl;
        return;
    }

    file << masterHash << endl;
    for (const auto& credential : credentials) {
        file << credential.first << ":" << credential.second << endl;
    }
    file.close();
}

// Load the master password hash and credentials from a file
bool loadFromFile(string& masterHash, vector<pair<string, string>>& credentials) {
    ifstream file("passwords.dat");
    if (!file.is_open()) {
        return false; // No file exists yet
    }

    getline(file, masterHash);
    string line;
    while (getline(file, line)) {
        size_t pos = line.find(':');
        if (pos != string::npos) {
            string username = line.substr(0, pos);
            string password = line.substr(pos + 1);
            credentials.emplace_back(username, password);
        }
    }
    file.close();
    return true;
}

// Add a new username and password
void addCredential(vector<pair<string, string>>& credentials) {
    string username, password;
    cout << "Enter username: ";
    cin >> username;
    cout << "Enter password: ";
    cin >> password;
    credentials.emplace_back(username, password);
    cout << "Credential added successfully!" << endl;
}

// Display all stored usernames and passwords
void displayCredentials(const vector<pair<string, string>>& credentials) {
    cout << "Stored credentials:" << endl;
    for (const auto& credential : credentials) {
        cout << "Username: " << credential.first << ", Password: " << credential.second << endl;
    }
}

int main() {
    string masterHash;
    vector<pair<string, string>> credentials;

    // Load existing data
    if (!loadFromFile(masterHash, credentials)) {
        cout << "No master password set. Please set a new master password: ";
        string masterPassword;
        cin >> masterPassword;
        masterHash = hashPassword(masterPassword);
        cout << "Master password set successfully!" << endl;
    }

    // Verify master password
    while (true) {
        cout << "Enter master password to unlock the password manager: ";
        string masterPassword;
        cin >> masterPassword;
        if (hashPassword(masterPassword) == masterHash) {
            cout << "Access granted!" << endl;
            break;
        }
        else {
            cout << "Invalid master password. Try again." << endl;
        }
    }

    // Main menu
    int choice;
    do {
        cout << "\nPassword Manager Menu:" << endl;
        cout << "1. Add a new credential" << endl;
        cout << "2. View all credentials" << endl;
        cout << "3. Exit" << endl;
        cout << "Enter your choice: ";
        cin >> choice;

        switch (choice) {
        case 1:
            addCredential(credentials);
            break;
        case 2:
            displayCredentials(credentials);
            break;
        case 3:
            saveToFile(masterHash, credentials);
            cout << "Data saved. Exiting..." << endl;
            break;
        default:
            cout << "Invalid choice. Please try again." << endl;
        }
    } while (choice != 3);

    return 0;
}

