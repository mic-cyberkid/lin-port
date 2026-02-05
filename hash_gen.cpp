#include <iostream>
#include <cstdint>
uint32_t HashApi(const char* str) {
    uint32_t hash = 5381;
    int c;
    while ((c = *str++))
        hash = ((hash << 5) + hash) + c;
    return hash;
}
int main() {
    std::cout << "NtResumeThread: 0x" << std::hex << HashApi("NtResumeThread") << std::endl;
    std::cout << "NtQueueApcThreadEx: 0x" << std::hex << HashApi("NtQueueApcThreadEx") << std::endl;
    return 0;
}
