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
    std::cout << "NtSuspendThread: 0x" << std::hex << HashApi("NtSuspendThread") << std::endl;
    std::cout << "NtGetContextThread: 0x" << std::hex << HashApi("NtGetContextThread") << std::endl;
    std::cout << "NtSetContextThread: 0x" << std::hex << HashApi("NtSetContextThread") << std::endl;
    return 0;
}
