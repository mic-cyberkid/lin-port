#include "JunkLogic.h"
#ifdef _WIN32
#include <windows.h>
#else
#include <sys/mman.h>
#include <unistd.h>
#include <cstring>
#endif
#include <cmath>
#include <random>
#include <algorithm>
#include <vector>
namespace evasion {
void JunkLogic::GenerateEntropy() {
    std::random_device rd; std::mt19937 gen(rd()); std::uniform_int_distribution<> dis(0, 255);
    std::vector<uint8_t> junk(1024);
    for(int i = 0; i < 100; ++i) {
        std::generate(junk.begin(), junk.end(), [&]() { return (uint8_t)dis(gen); });
        volatile uint8_t sum = 0; for(auto b : junk) sum = sum + b;
    }
}
void JunkLogic::PerformComplexMath() {
    volatile double val = 1.0; std::random_device rd; std::mt19937 gen(rd()); std::uniform_real_distribution<> dis(1.1, 2.0);
    for (int i = 0; i < 1000; ++i) { val = std::sin(val) * std::cos(val) * std::sqrt(std::abs(val)) * dis(gen); if (val > 10000.0) val = 1.0; }
}
void JunkLogic::ScrambleMemory() {
    const size_t sz = 4096;
#ifdef _WIN32
    void* ptr = VirtualAlloc(NULL, sz, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (ptr) { memset(ptr, 0xAA, sz); volatile uint8_t* b = (volatile uint8_t*)ptr; for(size_t i = 0; i < sz; ++i) b[i] = (uint8_t)(i % 256); VirtualFree(ptr, 0, MEM_RELEASE); }
#else
    void* ptr = mmap(NULL, sz, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (ptr != MAP_FAILED) { memset(ptr, 0xAA, sz); volatile uint8_t* b = (volatile uint8_t*)ptr; for(size_t i = 0; i < sz; ++i) b[i] = (uint8_t)(i % 256); munmap(ptr, sz); }
#endif
}
}
