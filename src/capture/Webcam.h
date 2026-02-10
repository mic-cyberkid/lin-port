#pragma once
#include <vector>
#ifdef _WIN32
#include <windows.h>
#else
#include <cstdint>
typedef uint8_t BYTE;
#endif
namespace capture {
    std::vector<BYTE> CaptureWebcamImage();
}
