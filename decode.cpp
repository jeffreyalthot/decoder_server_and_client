#include <openssl/evp.h>
#include <openssl/sha.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>

#include <cstring>
#include <iostream>
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
}

int main(int argc, char **argv) {
    if (argc < 5) {
        std::cerr << "Usage: " << argv[0]
                  << " <base64_blob> <password> <salt_hex> <iv_hex> [iterations]\n";
        std::cerr << "Example: " << argv[0]
                  << " 'MJIgcw...' '2026-02-06' 00112233445566778899aabbccddeeff 0102030405060708090a0b0c0d0e0f10 82925\n";
        return 1;
    }

    std::string base64Blob = argv[1];
    std::string password = argv[2];
    std::string saltHex = argv[3];
    std::string ivHex = argv[4];
    int iterations = (argc > 5) ? std::stoi(argv[5]) : 82925;

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

    try {
        std::vector<unsigned char> salt = hexToBytes(saltHex);
        std::vector<unsigned char> iv = hexToBytes(ivHex);
        std::vector<unsigned char> ciphertext = base64Decode(base64Blob);
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
