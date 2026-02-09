#include "ADEnum.h"
#include "../utils/Shared.h"
#include <windows.h>
#include <lm.h>
#include <dsgetdc.h>
#include <vector>
#include <sstream>

#pragma comment(lib, "netapi32.lib")

namespace lateral {

namespace {
    std::wstring GetDC() {
        LPWSTR dcName = NULL;
        if (NetGetDCName(NULL, NULL, (LPBYTE*)&dcName) == NERR_Success) {
            std::wstring res(dcName);
            NetApiBufferFree(dcName);
            return res;
        }
        return L"";
    }
}

std::string ADEnum::GetDomainInfo() {
    LPWSTR name = NULL;
    NETSETUP_JOIN_STATUS status;
    std::stringstream ss;

    if (NetGetJoinInformation(NULL, &name, &status) == NERR_Success) {
        ss << "Domain/Workgroup: " << utils::ws2s(name) << "\n";
        ss << "Status: ";
        switch (status) {
            case NetSetupUnknownStatus: ss << "Unknown"; break;
            case NetSetupUnjoined: ss << "Unjoined"; break;
            case NetSetupWorkgroupName: ss << "Workgroup"; break;
            case NetSetupDomainName: ss << "Domain"; break;
        }
        ss << "\n";
        NetApiBufferFree(name);
    }

    std::wstring dc = GetDC();
    if (!dc.empty()) {
        ss << "Domain Controller: " << utils::ws2s(dc) << "\n";
    }

    return ss.str();
}

std::string ADEnum::EnumerateComputers() {
    std::stringstream ss;
    PNET_DISPLAY_MACHINE pBuff = NULL;
    DWORD res, count = 0;

    ss << "DOMAIN_COMPUTERS:\n";
    do {
        res = NetQueryDisplayInformation(NULL, 2, count, 100, 16384, &count, (PVOID*)&pBuff);
        if (res == ERROR_SUCCESS || res == ERROR_MORE_DATA) {
            PNET_DISPLAY_MACHINE p = pBuff;
            for (DWORD i = 0; i < count; i++) {
                ss << utils::ws2s(p->usrim2_name) << " | " << utils::ws2s(p->usrim2_comment) << "\n";
                p++;
            }
            NetApiBufferFree(pBuff);
        }
    } while (res == ERROR_MORE_DATA);

    return ss.str();
}

std::string ADEnum::EnumerateUsers() {
    std::stringstream ss;
    PNET_DISPLAY_USER pBuff = NULL;
    DWORD res, count = 0;

    ss << "DOMAIN_USERS:\n";
    do {
        res = NetQueryDisplayInformation(NULL, 1, count, 100, 16384, &count, (PVOID*)&pBuff);
        if (res == ERROR_SUCCESS || res == ERROR_MORE_DATA) {
            PNET_DISPLAY_USER p = pBuff;
            for (DWORD i = 0; i < count; i++) {
                ss << utils::ws2s(p->usrim1_name) << " | " << utils::ws2s(p->usrim1_full_name) << "\n";
                p++;
            }
            NetApiBufferFree(pBuff);
        }
    } while (res == ERROR_MORE_DATA);

    return ss.str();
}

std::string ADEnum::EnumerateGroups() {
    std::stringstream ss;
    PNET_DISPLAY_GROUP pBuff = NULL;
    DWORD res, count = 0;

    ss << "DOMAIN_GROUPS:\n";
    do {
        res = NetQueryDisplayInformation(NULL, 3, count, 100, 16384, &count, (PVOID*)&pBuff);
        if (res == ERROR_SUCCESS || res == ERROR_MORE_DATA) {
            PNET_DISPLAY_GROUP p = pBuff;
            for (DWORD i = 0; i < count; i++) {
                ss << utils::ws2s(p->grpi3_name) << " | " << utils::ws2s(p->grpi3_comment) << "\n";
                p++;
            }
            NetApiBufferFree(pBuff);
        }
    } while (res == ERROR_MORE_DATA);

    return ss.str();
}

std::string ADEnum::EnumerateDomainAdmins() {
    std::stringstream ss;
    ss << "DOMAIN_ADMINS:\n";

    // "Domain Admins" name might be localized?
    // Usually we use Well-Known SIDs but NetGroupGetUsers uses name.
    // For now use hardcoded "Domain Admins".

    LPCWSTR groupName = L"Domain Admins";
    LPLOCALGROUP_MEMBERS_INFO_1 pBuff = NULL;
    DWORD entriesRead = 0;
    DWORD totalEntries = 0;
    DWORD_PTR resumeHandle = 0;

    // Try NetGroupGetUsers first (Global groups)
    PBYTE pGlobalBuff = NULL;
    if (NetGroupGetUsers(NULL, groupName, 0, &pGlobalBuff, MAX_PREFERRED_LENGTH, &entriesRead, &totalEntries, &resumeHandle) == NERR_Success) {
        PGROUP_USERS_INFO_0 p = (PGROUP_USERS_INFO_0)pGlobalBuff;
        for (DWORD i = 0; i < entriesRead; i++) {
            ss << utils::ws2s(p->grui0_name) << " (Global)\n";
            p++;
        }
        NetApiBufferFree(pGlobalBuff);
    }

    return ss.str();
}

} // namespace lateral
