#include "counter_sink.h"

#include <fstream>
#include <mutex>
#include <stdexcept>

namespace {
std::mutex sinkMutex;
const char *kCounterOutputPath = "counter_results.txt";
}

void handleCounterValue(const std::string &value) {
    std::lock_guard<std::mutex> guard(sinkMutex);
    std::ofstream out(kCounterOutputPath, std::ios::app);
    if (!out) {
        throw std::runtime_error("Failed to open counter output file");
    }
    out << value << '\n';
}
