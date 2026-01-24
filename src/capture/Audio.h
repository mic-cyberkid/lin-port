#pragma once
#include <vector>
#include <windows.h>

namespace capture {
    std::vector<BYTE> RecordAudio(int seconds);
}
