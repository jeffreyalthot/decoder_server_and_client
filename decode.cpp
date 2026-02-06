#include <openssl/evp.h>
#include <openssl/sha.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>

#include <cstring>
#include <iostream>
#include <regex>
#include <stdexcept>
#include <string>
#include <vector>

namespace {
std::vector<unsigned char> base64Decode(const std::string &input) {
    BIO *bio = BIO_new_mem_buf(input.data(), static_cast<int>(input.size()));
    if (!bio) {
        throw std::runtime_error("Failed to allocate BIO");
    }
    BIO *b64 = BIO_new(BIO_f_base64());
    if (!b64) {
        BIO_free(bio);
        throw std::runtime_error("Failed to allocate base64 BIO");
    }
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
    bio = BIO_push(b64, bio);

    std::vector<unsigned char> buffer(input.size());
    int decodedLen = BIO_read(bio, buffer.data(), static_cast<int>(buffer.size()));
    BIO_free_all(bio);
    if (decodedLen < 0) {
        throw std::runtime_error("Base64 decode failed");
    }
    buffer.resize(static_cast<size_t>(decodedLen));
    return buffer;
}

std::vector<unsigned char> deriveKey(const std::string &password,
                                     const std::vector<unsigned char> &salt,
                                     int iterations,
                                     size_t keyLen) {
    std::vector<unsigned char> key(keyLen);
    if (!PKCS5_PBKDF2_HMAC(password.c_str(), static_cast<int>(password.size()),
                           salt.data(), static_cast<int>(salt.size()),
                           iterations, EVP_sha512(), static_cast<int>(keyLen),
                           key.data())) {
        throw std::runtime_error("PBKDF2 derivation failed");
    }
    return key;
}

std::vector<unsigned char> aes256CbcDecrypt(const std::vector<unsigned char> &ciphertext,
                                            const std::vector<unsigned char> &key,
                                            const std::vector<unsigned char> &iv) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        throw std::runtime_error("Failed to create cipher context");
    }

    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, key.data(), iv.data()) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("DecryptInit failed");
    }

    std::vector<unsigned char> plaintext(ciphertext.size() + EVP_CIPHER_block_size(EVP_aes_256_cbc()));
    int outLen1 = 0;
    if (EVP_DecryptUpdate(ctx, plaintext.data(), &outLen1, ciphertext.data(), static_cast<int>(ciphertext.size())) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("DecryptUpdate failed");
    }

    int outLen2 = 0;
    if (EVP_DecryptFinal_ex(ctx, plaintext.data() + outLen1, &outLen2) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("DecryptFinal failed (wrong password or corrupted data)");
    }
    EVP_CIPHER_CTX_free(ctx);
    plaintext.resize(static_cast<size_t>(outLen1 + outLen2));
    return plaintext;
}

std::string readAllStdin() {
    std::string data;
    std::string line;
    while (std::getline(std::cin, line)) {
        data.append(line);
        data.push_back('\n');
    }
    return data;
}

std::string findBase64Token(const std::string &text) {
    std::regex base64Pattern(R"(([A-Za-z0-9+/]{20,}={0,2}))");
    std::smatch match;
    std::string::const_iterator searchStart(text.cbegin());
    std::string best;
    while (std::regex_search(searchStart, text.cend(), match, base64Pattern)) {
        if (match[1].length() > best.length()) {
            best = match[1];
        }
        searchStart = match.suffix().first;
    }
    return best;
}

int findSpinCount(const std::string &text, int fallback) {
    std::regex spinPattern(R"(Spin count[^0-9]*([0-9]+))", std::regex::icase);
    std::smatch match;
    if (std::regex_search(text, match, spinPattern)) {
        return std::stoi(match[1]);
    }
    return fallback;
}

std::vector<unsigned char> findHexValue(const std::string &text, const std::string &label) {
    std::regex pattern(label + R"([^0-9a-fA-F]*([0-9a-fA-F]{16,}))", std::regex::icase);
    std::smatch match;
    if (!std::regex_search(text, match, pattern)) {
        return {};
    }

    const std::string hex = match[1];
    if (hex.size() % 2 != 0) {
        throw std::runtime_error("Hex string must have even length");
    }
    std::vector<unsigned char> out(hex.size() / 2);
    for (size_t i = 0; i < out.size(); ++i) {
        unsigned int byte = 0;
        if (sscanf(hex.c_str() + (i * 2), "%2x", &byte) != 1) {
            throw std::runtime_error("Invalid hex string");
        }
        out[i] = static_cast<unsigned char>(byte);
    }
    return out;
}

bool findSizes(const std::string &text, size_t &saltSize, size_t &ivSize) {
    std::regex sizePattern(R"(Sz:\s*([0-9]+)[_x]([0-9]+))", std::regex::icase);
    std::smatch match;
    if (!std::regex_search(text, match, sizePattern)) {
        return false;
    }
    saltSize = static_cast<size_t>(std::stoul(match[1]));
    ivSize = static_cast<size_t>(std::stoul(match[2]));
    return true;
}
}

int main(int argc, char **argv) {
    if (argc < 2) {
        std::cerr << "Usage:\n";
        std::cerr << "  " << argv[0]
                  << " <base64_blob> <password> <salt_hex> <iv_hex> [iterations]\n";
        std::cerr << "  " << argv[0]
                  << " <password> < input.txt\n";
        std::cerr << "Example:\n  " << argv[0]
                  << " 'MJIgcw...' '2026-02-06' 00112233445566778899aabbccddeeff 0102030405060708090a0b0c0d0e0f10 82925\n";
        return 1;
    }

    std::string base64Blob;
    std::string password;
    std::vector<unsigned char> salt;
    std::vector<unsigned char> iv;
    std::vector<unsigned char> ciphertext;
    int iterations = 82925;

    auto hexToBytes = [](const std::string &hex) {
        if (hex.size() % 2 != 0) {
            throw std::runtime_error("Hex string must have even length");
        }
        std::vector<unsigned char> out(hex.size() / 2);
        for (size_t i = 0; i < out.size(); ++i) {
            unsigned int byte = 0;
            if (sscanf(hex.c_str() + (i * 2), "%2x", &byte) != 1) {
                throw std::runtime_error("Invalid hex string");
            }
            out[i] = static_cast<unsigned char>(byte);
        }
        return out;
    };

    if (argc >= 5) {
        base64Blob = argv[1];
        password = argv[2];
        salt = hexToBytes(argv[3]);
        iv = hexToBytes(argv[4]);
        iterations = (argc > 5) ? std::stoi(argv[5]) : iterations;
    } else {
        password = argv[1];
        const std::string inputText = readAllStdin();
        base64Blob = findBase64Token(inputText);
        if (base64Blob.empty()) {
            std::cerr << "Error: No base64 payload found in input.\n";
            return 1;
        }
        iterations = findSpinCount(inputText, iterations);
        salt = findHexValue(inputText, "salt");
        iv = findHexValue(inputText, "iv");

        if (salt.empty() || iv.empty()) {
            size_t saltSize = 0;
            size_t ivSize = 0;
            if (findSizes(inputText, saltSize, ivSize)) {
                std::vector<unsigned char> raw = base64Decode(base64Blob);
                if (raw.size() < saltSize + ivSize) {
                    std::cerr << "Error: Payload too small to split salt/iv by size.\n";
                    return 1;
                }
                salt.assign(raw.begin(), raw.begin() + static_cast<long>(saltSize));
                iv.assign(raw.begin() + static_cast<long>(saltSize),
                          raw.begin() + static_cast<long>(saltSize + ivSize));
                ciphertext.assign(raw.begin() + static_cast<long>(saltSize + ivSize), raw.end());
            }
        }

        if (salt.empty() || iv.empty()) {
            std::cerr << "Error: Salt/IV missing. Provide them as hex in input or use the explicit arguments.\n";
            return 1;
        }
    }

    try {
        if (ciphertext.empty()) {
            ciphertext = base64Decode(base64Blob);
        }
        std::vector<unsigned char> key = deriveKey(password, salt, iterations, 32);

        std::vector<unsigned char> plaintext = aes256CbcDecrypt(ciphertext, key, iv);
        std::cout.write(reinterpret_cast<const char *>(plaintext.data()), static_cast<std::streamsize>(plaintext.size()));
        std::cout << "\n";
    } catch (const std::exception &ex) {
        std::cerr << "Error: " << ex.what() << "\n";
        return 1;
    }

    return 0;
}
