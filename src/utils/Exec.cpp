#include "Exec.h"
#include <cstdio>
#include <memory>
#include <array>

namespace utils {
    std::string RunCommand(const std::string& cmd) {
        std::array<char, 128> buf;
        std::string res;
        std::unique_ptr<FILE, decltype(&pclose)> pipe(popen(cmd.c_str(), "r"), pclose);
        if (!pipe) return "";
        while (fgets(buf.data(), (int)buf.size(), pipe.get()) != nullptr) res += buf.data();
        return res;
    }
}
