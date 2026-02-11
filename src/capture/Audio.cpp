#include "Audio.h"
#ifdef _WIN32
#include <windows.h>
#include <mmsystem.h>
#include <fstream>
#include <thread>
#pragma comment(lib, "winmm.lib")
#else
#include <unistd.h>
#include "../utils/Exec.h"
#include <fstream>
#include <vector>
#endif
namespace capture {
    std::vector<BYTE> RecordAudio(int seconds) {
        (void)seconds;
#ifdef _WIN32
        return {};
#else
        std::string wavPath = "/tmp/rec.wav";
        std::string cmd = "arecord -d " + std::to_string(seconds) + " -f cd -t wav " + wavPath;
        utils::RunCommand(cmd);
        std::vector<BYTE> buffer;
        std::ifstream file(wavPath, std::ios::binary | std::ios::ate);
        if (file.is_open()) {
            std::streampos size = file.tellg();
            buffer.resize((size_t)size);
            file.seekg(0, std::ios::beg);
            file.read((char*)buffer.data(), size);
            file.close();
            unlink(wavPath.c_str());
        }
        return buffer;
#endif
    }
}
