#include "JunkLogic.h"
#include <windows.h>
#include <cmath>
#include <random>
#include <algorithm>

namespace evasion {

void JunkLogic::GenerateEntropy() {
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(0, 255);

    std::vector<uint8_t> junk(1024);
    for(int i = 0; i < 100; ++i) {
        std::generate(junk.begin(), junk.end(), [&]() { return (uint8_t)dis(gen); });
        // Use the data so it's not optimized away
        volatile uint8_t sum = 0;
        for(auto b : junk) sum += b;
    }
}

void JunkLogic::PerformComplexMath() {
    volatile double val = 1.0;
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_real_distribution<> dis(1.1, 2.0);

    for (int i = 0; i < 1000; ++i) {
        val = std::sin(val) * std::cos(val) * std::sqrt(std::abs(val)) * dis(gen);
        if (val > 10000.0) val = 1.0;
    }
}

void JunkLogic::ScrambleMemory() {
    const size_t sz = 4096;
    void* ptr = VirtualAlloc(NULL, sz, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (ptr) {
        memset(ptr, 0xAA, sz);
        volatile uint8_t* b = (volatile uint8_t*)ptr;
        for(size_t i = 0; i < sz; ++i) b[i] = (uint8_t)(i % 256);
        VirtualFree(ptr, 0, MEM_RELEASE);
    }
}

} // namespace evasion
