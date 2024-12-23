#include <iostream>
#include <iomanip>
#include <openssl/md5.h>
#include <openssl/sha.h>
#include <string.h>

void generateMD5(const std::string &plaintext) {
    unsigned char digest[MD5_DIGEST_LENGTH];
    MD5((unsigned char*)plaintext.c_str(), plaintext.size(), (unsigned char*)&digest);

    std::cout << "MD5 Hash: ";
    for (int i = 0; i < MD5_DIGEST_LENGTH; i++) {
        std::cout << std::hex << std::setw(2) << std::setfill('0') << (int)digest[i];
    }
    std::cout << std::endl;
}

void generateSHA1(const std::string &plaintext) {
    unsigned char digest[SHA_DIGEST_LENGTH];
    SHA1((unsigned char*)plaintext.c_str(), plaintext.size(), (unsigned char*)&digest);

    std::cout << "SHA1 Hash: ";
    for (int i = 0; i < SHA_DIGEST_LENGTH; i++) {
        std::cout << std::hex << std::setw(2) << std::setfill('0') << (int)digest[i];
    }
    std::cout << std::endl;
}

int main() {
    std::string plaintext;
    std::cout << "Masukkan plaintext: ";
    std::getline(std::cin, plaintext);

    generateMD5(plaintext);
    generateSHA1(plaintext);

    return 0;
}
