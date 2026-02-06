#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <openssl/evp.h>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#include <chrono>
#include <ctime>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <regex>
#include <sstream>
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

std::string bytesToHex(const std::vector<unsigned char> &bytes) {
    std::ostringstream oss;
    for (unsigned char byte : bytes) {
        oss << std::hex << std::setw(2) << std::setfill('0')
            << static_cast<int>(byte);
    }
    return oss.str();
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

std::string timestampNow() {
    auto now = std::chrono::system_clock::now();
    std::time_t timeValue = std::chrono::system_clock::to_time_t(now);
    std::tm tmValue{};
    localtime_r(&timeValue, &tmValue);
    std::ostringstream oss;
    oss << std::put_time(&tmValue, "%Y-%m-%d %H:%M:%S");
    return oss.str();
}

struct ExtractedInfo {
    std::string base64;
    std::string saltHex;
    std::string ivHex;
    int iterations = 82925;
};

ExtractedInfo extractInfo(const std::string &payload) {
    ExtractedInfo info;
    info.base64 = findBase64Token(payload);
    info.iterations = findSpinCount(payload, info.iterations);

    std::vector<unsigned char> salt = findHexValue(payload, "salt");
    std::vector<unsigned char> iv = findHexValue(payload, "iv");

    if ((salt.empty() || iv.empty()) && !info.base64.empty()) {
        size_t saltSize = 0;
        size_t ivSize = 0;
        if (findSizes(payload, saltSize, ivSize)) {
            std::vector<unsigned char> raw = base64Decode(info.base64);
            if (raw.size() >= saltSize + ivSize) {
                salt.assign(raw.begin(), raw.begin() + static_cast<long>(saltSize));
                iv.assign(raw.begin() + static_cast<long>(saltSize),
                          raw.begin() + static_cast<long>(saltSize + ivSize));
            }
        }
    }

    if (!salt.empty()) {
        info.saltHex = bytesToHex(salt);
    }
    if (!iv.empty()) {
        info.ivHex = bytesToHex(iv);
    }
    return info;
}

struct StoredEntry {
    int id;
    std::string receivedAt;
    std::string email;
    std::string payload;
    ExtractedInfo info;
};

void appendToStorage(const StoredEntry &entry, const std::string &path) {
    std::ofstream out(path, std::ios::app);
    if (!out) {
        throw std::runtime_error("Failed to open storage file");
    }
    out << "{"
        << "\"id\":" << entry.id << ","
        << "\"received_at\":\"" << jsonEscape(entry.receivedAt) << "\","
        << "\"email\":\"" << jsonEscape(entry.email) << "\","
        << "\"payload\":\"" << jsonEscape(entry.payload) << "\","
        << "\"base64\":\"" << jsonEscape(entry.info.base64) << "\","
        << "\"salt_hex\":\"" << jsonEscape(entry.info.saltHex) << "\","
        << "\"iv_hex\":\"" << jsonEscape(entry.info.ivHex) << "\","
        << "\"iterations\":" << entry.info.iterations
        << "}\n";
}
}

int main(int argc, char **argv) {
    int port = 9090;
    if (argc > 1) {
        port = std::stoi(argv[1]);
    }

    int serverFd = socket(AF_INET, SOCK_STREAM, 0);
    if (serverFd < 0) {
        std::cerr << "Failed to create socket\n";
        return 1;
    }
    int opt = 1;
    setsockopt(serverFd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(static_cast<uint16_t>(port));

    if (bind(serverFd, reinterpret_cast<sockaddr *>(&addr), sizeof(addr)) != 0) {
        std::cerr << "Bind failed\n";
        close(serverFd);
        return 1;
    }

    if (listen(serverFd, 5) != 0) {
        std::cerr << "Listen failed\n";
        close(serverFd);
        return 1;
    }

    std::cout << "Server listening on port " << port << "\n";

    std::vector<StoredEntry> entries;
    const std::string storagePath = "server_storage.jsonl";
    int nextId = 1;

    while (true) {
        sockaddr_in clientAddr{};
        socklen_t clientLen = sizeof(clientAddr);
        int clientFd = accept(serverFd, reinterpret_cast<sockaddr *>(&clientAddr), &clientLen);
        if (clientFd < 0) {
            std::cerr << "Accept failed\n";
            continue;
        }

        std::string line = readLine(clientFd);
        if (line.empty()) {
            close(clientFd);
            continue;
        }

        std::string type = jsonField(line, "type");
        if (type != "submit") {
            writeLine(clientFd, "{\"type\":\"error\",\"message\":\"Expected submit\"}");
            close(clientFd);
            continue;
        }

        std::string payloadB64 = jsonField(line, "payload_b64");
        if (payloadB64.empty()) {
            writeLine(clientFd, "{\"type\":\"error\",\"message\":\"Missing payload\"}");
            close(clientFd);
            continue;
        }

        std::string payload;
        try {
            std::vector<unsigned char> decoded = base64Decode(payloadB64);
            payload.assign(decoded.begin(), decoded.end());
        } catch (const std::exception &ex) {
            writeLine(clientFd, std::string("{\"type\":\"error\",\"message\":\"") + jsonEscape(ex.what()) + "\"}");
            close(clientFd);
            continue;
        }

        ExtractedInfo info = extractInfo(payload);
        if (info.base64.empty() || info.saltHex.empty() || info.ivHex.empty()) {
            writeLine(clientFd, "{\"type\":\"error\",\"message\":\"Missing base64/salt/iv\"}");
            close(clientFd);
            continue;
        }

        std::ostringstream response;
        response << "{"
                 << "\"type\":\"extracted\","
                 << "\"base64\":\"" << jsonEscape(info.base64) << "\","
                 << "\"salt_hex\":\"" << jsonEscape(info.saltHex) << "\","
                 << "\"iv_hex\":\"" << jsonEscape(info.ivHex) << "\","
                 << "\"iterations\":" << info.iterations
                 << "}";
        if (!writeLine(clientFd, response.str())) {
            close(clientFd);
            continue;
        }

        std::string finalizeLine = readLine(clientFd);
        if (finalizeLine.empty()) {
            close(clientFd);
            continue;
        }

        std::string finalizeType = jsonField(finalizeLine, "type");
        if (finalizeType != "finalize") {
            writeLine(clientFd, "{\"type\":\"error\",\"message\":\"Expected finalize\"}");
            close(clientFd);
            continue;
        }

        std::string email = jsonField(finalizeLine, "email");
        std::string payloadB64Finalize = jsonField(finalizeLine, "payload_b64");
        if (email.empty() || payloadB64Finalize.empty()) {
            writeLine(clientFd, "{\"type\":\"error\",\"message\":\"Missing email/payload\"}");
            close(clientFd);
            continue;
        }

        StoredEntry entry;
        entry.id = nextId++;
        entry.receivedAt = timestampNow();
        entry.email = email;
        entry.payload = payload;
        entry.info = info;
        entries.push_back(entry);

        try {
            appendToStorage(entry, storagePath);
        } catch (const std::exception &ex) {
            writeLine(clientFd, std::string("{\"type\":\"error\",\"message\":\"") + jsonEscape(ex.what()) + "\"}");
            close(clientFd);
            continue;
        }

        writeLine(clientFd, "{\"type\":\"stored\",\"message\":\"Entry saved\"}");
        close(clientFd);
    }

    close(serverFd);
    return 0;
}
