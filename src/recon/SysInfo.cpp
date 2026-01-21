#include "SysInfo.h"
#include "WmiHelpers.h"
#include "../external/nlohmann/json.hpp"
#include <windows.h>
#include <string>
#include <vector>

namespace recon {

// Helper to convert wstring to string
std::string ws2s(const std::wstring& wstr) {
    if (wstr.empty()) return std::string();
    int size_needed = WideCharToMultiByte(CP_UTF8, 0, &wstr[0], (int)wstr.size(), NULL, 0, NULL, NULL);
    std::string strTo(size_needed, 0);
    WideCharToMultiByte(CP_UTF8, 0, &wstr[0], (int)wstr.size(), &strTo[0], size_needed, NULL, NULL);
    return strTo;
}

std::string getSysInfo() {
    nlohmann::json info;
    WmiSession wmi;

    try {
        // Operating System
        auto osResults = wmi.execQuery(L"SELECT * FROM Win32_OperatingSystem");
        if (!osResults.empty()) {
            info["os_caption"] = ws2s(osResults[0].getString(L"Caption"));
            info["os_build"] = ws2s(osResults[0].getString(L"BuildNumber"));
        }

        // Computer System
        auto csResults = wmi.execQuery(L"SELECT * FROM Win32_ComputerSystem");
        if (!csResults.empty()) {
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
        }

        // Disk drives
        auto diskResults = wmi.execQuery(L"SELECT * FROM Win32_DiskDrive");
        nlohmann::json disks = nlohmann::json::array();
        for (auto& disk : diskResults) {
            nlohmann::json disk_info;
            disk_info["model"] = ws2s(disk.getString(L"Model"));
            disk_info["size_gb"] = disk.getUnsignedLongLong(L"Size") / (1024 * 1024 * 1024);
            disks.push_back(disk_info);
        }
        info["disks"] = disks;

        // Network IPs
        auto netResults = wmi.execQuery(L"SELECT * FROM Win32_NetworkAdapterConfiguration WHERE IPEnabled=TRUE");
        nlohmann::json ips = nlohmann::json::array();
        for (auto& net : netResults) {
            VARIANT var;
            VariantInit(&var);
            if (SUCCEEDED(net.pObj_->Get(L"IPAddress", 0, &var, 0, 0)) && var.vt == (VT_ARRAY | VT_BSTR)) {
                SAFEARRAY* sa = var.parray;
                BSTR* bstrArray;
                if (SUCCEEDED(SafeArrayAccessData(sa, (void**)&bstrArray))) {
                    for (ULONG i = 0; i < sa->rgsabound[0].cElements; ++i) {
                        ips.push_back(ws2s(bstrArray[i]));
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
