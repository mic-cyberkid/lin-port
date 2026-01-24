#pragma once
#include <vector>
#include <windows.h>
#include <string>
#include "../external/nlohmann/json.hpp"

namespace capture {
    nlohmann::json ListWebcamDevices();
    std::vector<BYTE> CaptureWebcamJPEG(int deviceIndex = 0, const std::string& nameHint = "");
}
