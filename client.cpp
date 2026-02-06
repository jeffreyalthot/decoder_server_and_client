#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <openssl/evp.h>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#include "counter_sink.h"

#include <iostream>
#include <limits>
#include <regex>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

namespace {
std::string base64Encode(const std::string &input) {
    BIO *bio = BIO_new(BIO_s_mem());
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

    BIO_write(bio, input.data(), static_cast<int>(input.size()));
    BIO_flush(bio);

    BUF_MEM *bufferPtr = nullptr;
    BIO_get_mem_ptr(bio, &bufferPtr);
    std::string encoded(bufferPtr->data, bufferPtr->length);
    BIO_free_all(bio);
    return encoded;
}

std::string jsonEscape(const std::string &value) {
    std::string out;
    out.reserve(value.size());
    for (char ch : value) {
        if (ch == '"' || ch == '\\') {
            out.push_back('\\');
        }
        out.push_back(ch);
    }
    return out;
}

std::string jsonField(const std::string &line, const std::string &key) {
    std::regex pattern("\"" + key + "\"\\s*:\\s*\"([^\"]*)\"");
    std::smatch match;
    if (!std::regex_search(line, match, pattern)) {
        return "";
    }
    return match[1];
}

int jsonIntField(const std::string &line, const std::string &key, int fallback) {
    std::regex pattern("\"" + key + "\"\\s*:\\s*([0-9]+)");
    std::smatch match;
    if (!std::regex_search(line, match, pattern)) {
        return fallback;
    }
    return std::stoi(match[1]);
}

std::string readLine(int fd) {
    std::string line;
    char ch;
    while (true) {
        ssize_t n = recv(fd, &ch, 1, 0);
        if (n <= 0) {
            return "";
        }
        if (ch == '\n') {
            break;
        }
        if (ch != '\r') {
            line.push_back(ch);
        }
    }
    return line;
}

bool writeLine(int fd, const std::string &line) {
    std::string payload = line + "\n";
    const char *data = payload.c_str();
    size_t total = 0;
    while (total < payload.size()) {
        ssize_t sent = send(fd, data + total, payload.size() - total, 0);
        if (sent <= 0) {
            return false;
        }
        total += static_cast<size_t>(sent);
    }
    return true;
}

std::string readMultilinePayload() {
    std::cout << "Enter data to send (type END on its own line to finish):\n";
    std::string payload;
    std::string line;
    while (std::getline(std::cin, line)) {
        if (line == "END") {
            break;
        }
        payload.append(line);
        payload.push_back('\n');
    }
    return payload;
}

unsigned long long safePow(unsigned long long base, int exp) {
    unsigned long long result = 1;
    for (int i = 0; i < exp; ++i) {
        if (result > std::numeric_limits<unsigned long long>::max() / base) {
            return std::numeric_limits<unsigned long long>::max();
        }
        result *= base;
    }
    return result;
}

std::string counterValueForIndex(unsigned long long index,
                                 const std::string &alphabet,
                                 int maxLen) {
    if (index == 0) {
        return "";
    }
    const unsigned long long base = alphabet.size();
    unsigned long long remaining = index;
    for (int length = 1; length <= maxLen; ++length) {
        unsigned long long count = safePow(base, length);
        if (remaining > count) {
            remaining -= count;
            continue;
        }

        unsigned long long offset = remaining - 1;
        std::string value(length, alphabet[0]);
        for (int pos = length - 1; pos >= 0; --pos) {
            unsigned long long digit = offset % base;
            value[static_cast<size_t>(pos)] = alphabet[digit];
            offset /= base;
        }
        return value;
    }
    return "";
}

bool processWorkRange(unsigned long long workNumber, int fd) {
    const std::string alphabet =
        "abcdefghijklmnopqrstuvwxyz"
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        "0123456789"
        "!@#$%^&*()_-+=";
    const int maxLen = 12;
    const unsigned long long range = 100000ULL;
    unsigned long long startIndex = workNumber * range;

    for (unsigned long long i = 0; i < range; ++i) {
        unsigned long long index = startIndex + i;
        std::string value = counterValueForIndex(index, alphabet, maxLen);
        if (value.empty()) {
            break;
        }
        handleCounterValue(value);
    }

    std::ostringstream share;
    share << "{"
          << "\"type\":\"share\","
          << "\"number\":" << workNumber
          << "}";
    return writeLine(fd, share.str());
}
}

int main(int argc, char **argv) {
    std::string host = "127.0.0.1";
    int port = 9090;
    if (argc > 1) {
        host = argv[1];
    }
    if (argc > 2) {
        port = std::stoi(argv[2]);
    }

    std::cout << "Client menu:\n";
    std::cout << "1) Send key set to server\n";
    std::cout << "2) Start counter worker\n";
    std::cout << "Select option: ";
    int option = 0;
    std::cin >> option;
    std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');

    int clientFd = socket(AF_INET, SOCK_STREAM, 0);
    if (clientFd < 0) {
        std::cerr << "Failed to create socket.\n";
        return 1;
    }

    sockaddr_in serverAddr{};
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_port = htons(static_cast<uint16_t>(port));
    if (inet_pton(AF_INET, host.c_str(), &serverAddr.sin_addr) <= 0) {
        std::cerr << "Invalid server address.\n";
        close(clientFd);
        return 1;
    }

    if (connect(clientFd, reinterpret_cast<sockaddr *>(&serverAddr), sizeof(serverAddr)) != 0) {
        std::cerr << "Failed to connect to server.\n";
        close(clientFd);
        return 1;
    }

    if (option == 2) {
        if (!writeLine(clientFd, "{\"type\":\"ping\"}")) {
            std::cerr << "Failed to send ping.\n";
            close(clientFd);
            return 1;
        }

        while (true) {
            std::string workLine = readLine(clientFd);
            if (workLine.empty()) {
                std::cerr << "Connection closed by server.\n";
                close(clientFd);
                return 1;
            }

            std::string workType = jsonField(workLine, "type");
            if (workType == "error") {
                std::cerr << "Server error: " << jsonField(workLine, "message") << "\n";
                close(clientFd);
                return 1;
            }
            if (workType != "work") {
                std::cerr << "Unexpected work response.\n";
                close(clientFd);
                return 1;
            }

            unsigned long long workNumber =
                static_cast<unsigned long long>(jsonIntField(workLine, "number", 0));
            if (workNumber == 0) {
                std::cerr << "Invalid work number.\n";
                close(clientFd);
                return 1;
            }

            try {
                if (!processWorkRange(workNumber, clientFd)) {
                    std::cerr << "Failed to send share.\n";
                    close(clientFd);
                    return 1;
                }
            } catch (const std::exception &ex) {
                std::cerr << "Counter processing failed: " << ex.what() << "\n";
                close(clientFd);
                return 1;
            }
        }
    }

    if (option != 1) {
        std::cerr << "Only options 1 or 2 are supported.\n";
        close(clientFd);
        return 1;
    }

    std::string payload = readMultilinePayload();
    if (payload.empty()) {
        std::cerr << "No data provided.\n";
        close(clientFd);
        return 1;
    }

    std::string payloadB64;
    try {
        payloadB64 = base64Encode(payload);
    } catch (const std::exception &ex) {
        std::cerr << "Encoding failed: " << ex.what() << "\n";
        close(clientFd);
        return 1;
    }

    std::ostringstream submit;
    submit << "{"
           << "\"type\":\"submit\","
           << "\"payload_b64\":\"" << jsonEscape(payloadB64) << "\""
           << "}";
    if (!writeLine(clientFd, submit.str())) {
        std::cerr << "Failed to send payload.\n";
        close(clientFd);
        return 1;
    }

    std::string response = readLine(clientFd);
    if (response.empty()) {
        std::cerr << "No response from server.\n";
        close(clientFd);
        return 1;
    }

    std::string responseType = jsonField(response, "type");
    if (responseType == "error") {
        std::cerr << "Server error: " << jsonField(response, "message") << "\n";
        close(clientFd);
        return 1;
    }

    if (responseType != "extracted") {
        std::cerr << "Unexpected response.\n";
        close(clientFd);
        return 1;
    }

    std::string base64Token = jsonField(response, "base64");
    std::string saltHex = jsonField(response, "salt_hex");
    std::string ivHex = jsonField(response, "iv_hex");
    int iterations = jsonIntField(response, "iterations", 0);

    std::cout << "Server extracted:\n";
    std::cout << "  base64: " << base64Token << "\n";
    std::cout << "  salt_hex: " << saltHex << "\n";
    std::cout << "  iv_hex: " << ivHex << "\n";
    std::cout << "  iterations: " << iterations << "\n";

    std::cout << "Enter email to associate with this data: ";
    std::string email;
    std::getline(std::cin, email);
    if (email.empty()) {
        std::cerr << "Email is required.\n";
        close(clientFd);
        return 1;
    }

    std::ostringstream finalize;
    finalize << "{"
             << "\"type\":\"finalize\","
             << "\"email\":\"" << jsonEscape(email) << "\","
             << "\"payload_b64\":\"" << jsonEscape(payloadB64) << "\","
             << "\"base64\":\"" << jsonEscape(base64Token) << "\","
             << "\"salt_hex\":\"" << jsonEscape(saltHex) << "\","
             << "\"iv_hex\":\"" << jsonEscape(ivHex) << "\","
             << "\"iterations\":" << iterations
             << "}";
    if (!writeLine(clientFd, finalize.str())) {
        std::cerr << "Failed to finalize.\n";
        close(clientFd);
        return 1;
    }

    std::string finalizeResp = readLine(clientFd);
    if (finalizeResp.empty()) {
        std::cerr << "No finalize response.\n";
        close(clientFd);
        return 1;
    }

    std::string finalizeType = jsonField(finalizeResp, "type");
    if (finalizeType == "error") {
        std::cerr << "Server error: " << jsonField(finalizeResp, "message") << "\n";
        close(clientFd);
        return 1;
    }

    std::cout << "Server response: " << jsonField(finalizeResp, "message") << "\n";
    close(clientFd);
    return 0;
}
