#include <cstdint>
#include <cstddef>
#include <vector>

namespace evasion {
    // We'll use a moderate size to avoid compilation issues but enough to change the profile
    #define BLOAT_SIZE (512 * 1024)
    static uint8_t g_bloat_buffer[BLOAT_SIZE];

    void InitializeBloat() {
        for (size_t i = 0; i < BLOAT_SIZE; i++) {
            g_bloat_buffer[i] = (uint8_t)(i ^ 0x5A ^ (i >> 8));
        }
    }

    uint8_t GetBloatByte(size_t index) {
        return g_bloat_buffer[index % BLOAT_SIZE];
    }
}
