#include "DeepRecon.h"
#include "../external/nlohmann/json.hpp"
#include <windows.h>
#include <iphlpapi.h>
#include <comdef.h>
#include <WbemIdl.h>
#include <vector>
#include <iostream>
#include <iomanip>
#include <lm.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <lmshare.h>


#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "wbemuuid.lib")
#pragma comment(lib, "netapi32.lib")
#pragma comment(lib, "psapi.lib")


namespace recon {

    namespace {
        // Helper to convert wstring to string
        std::string ws2s(const std::wstring& wstr) {
            if (wstr.empty()) return std::string();
            int size_needed = WideCharToMultiByte(CP_UTF8, 0, &wstr[0], (int)wstr.size(), NULL, 0, NULL, NULL);
            std::string strTo(size_needed, 0);
            WideCharToMultiByte(CP_UTF8, 0, &wstr[0], (int)wstr.size(), &strTo[0], size_needed, NULL, NULL);
            return strTo;
        }

        // Helper to query WMI and return JSON array of objects
        nlohmann::json QueryWMI(const std::wstring& nspace, const std::wstring& query, const std::vector<std::wstring>& properties) {
            nlohmann::json results = nlohmann::json::array();
            
            IWbemLocator* pLoc = NULL;
            HRESULT hr = CoCreateInstance(CLSID_WbemLocator, 0, CLSCTX_INPROC_SERVER, IID_IWbemLocator, (LPVOID*)&pLoc);
            if (FAILED(hr)) return results;

            IWbemServices* pSvc = NULL;
            hr = pLoc->ConnectServer(_bstr_t(nspace.c_str()), NULL, NULL, 0, NULL, 0, 0, &pSvc);
            if (FAILED(hr)) {
                pLoc->Release();
                return results;
            }

            hr = CoSetProxyBlanket(pSvc, RPC_C_AUTHN_WINNT, RPC_C_AUTHZ_NONE, NULL, RPC_C_AUTHN_LEVEL_CALL, RPC_C_IMP_LEVEL_IMPERSONATE, NULL, EOAC_NONE);
            if (FAILED(hr)) {
                pSvc->Release();
                pLoc->Release();
                return results;
            }

            IEnumWbemClassObject* pEnumerator = NULL;
            hr = pSvc->ExecQuery(_bstr_t(L"WQL"), _bstr_t(query.c_str()), WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY, NULL, &pEnumerator);
            if (FAILED(hr)) {
                pSvc->Release();
                pLoc->Release();
                return results;
            }

            IWbemClassObject* pclsObj = NULL;
            ULONG uReturn = 0;

            while (pEnumerator) {
                hr = pEnumerator->Next(WBEM_INFINITE, 1, &pclsObj, &uReturn);
                if (0 == uReturn) break;

                nlohmann::json item;
                for (const auto& prop : properties) {
                    VARIANT vtProp;
                    hr = pclsObj->Get(prop.c_str(), 0, &vtProp, 0, 0);
                    if (SUCCEEDED(hr)) {
                        std::string key_s = ws2s(prop);

                        if (vtProp.vt == VT_BSTR) {
                            item[key_s] = ws2s(vtProp.bstrVal);
                        } else if (vtProp.vt == VT_I4) {
                            item[key_s] = vtProp.lVal;
                        } else if (vtProp.vt == VT_BOOL) {
                            item[key_s] = (bool)vtProp.boolVal;
                        } else if (vtProp.vt == VT_UI4) {
                            item[key_s] = vtProp.ulVal;
                        }
                        VariantClear(&vtProp);
                    }
                }
                results.push_back(item);
                pclsObj->Release();
            }

            pEnumerator->Release();
            pSvc->Release();
            pLoc->Release();
            return results;
        }

        nlohmann::json GetArpTable() {
            nlohmann::json arpList = nlohmann::json::array();
            ULONG outBufLen = sizeof(MIB_IPNETTABLE);
            PMIB_IPNETTABLE pIpNetTable = (MIB_IPNETTABLE*)malloc(outBufLen);
            
            if (pIpNetTable && GetIpNetTable(pIpNetTable, &outBufLen, FALSE) == ERROR_INSUFFICIENT_BUFFER) {
                free(pIpNetTable);
                pIpNetTable = (MIB_IPNETTABLE*)malloc(outBufLen);
            }

            if (pIpNetTable && GetIpNetTable(pIpNetTable, &outBufLen, FALSE) == NO_ERROR) {
                for (DWORD i = 0; i < pIpNetTable->dwNumEntries; i++) {
                    if (pIpNetTable->table[i].dwType != 2) { // Skip invalid
                        nlohmann::json entry;
                        struct in_addr ipAddr;
                        ipAddr.s_addr = pIpNetTable->table[i].dwAddr;
                        entry["ip"] = inet_ntoa(ipAddr);
                        
                        std::stringstream ss;
                        for (DWORD j = 0; j < pIpNetTable->table[i].dwPhysAddrLen; j++) {
                            ss << std::hex << std::setw(2) << std::setfill('0') << (int)pIpNetTable->table[i].bPhysAddr[j];
                            if (j < pIpNetTable->table[i].dwPhysAddrLen - 1) ss << "-";
                        }
                        entry["mac"] = ss.str();
                        entry["type"] = (pIpNetTable->table[i].dwType == 3) ? "Dynamic" : "Static";
                        arpList.push_back(entry);
                    }
                }
            }
            if (pIpNetTable) {
                free(pIpNetTable);
            }
            return arpList;
        }

        nlohmann::json GetLoggedUsers() {
            nlohmann::json users = nlohmann::json::array();
            LPWKSTA_USER_INFO_1 pBuf = NULL;
            DWORD entries = 0, total = 0;
            NET_API_STATUS nStatus = NetWkstaUserEnum(NULL, 1, (LPBYTE*)&pBuf, MAX_PREFERRED_LENGTH, &entries, &total, NULL);
            if (nStatus == NERR_Success) {
                for (DWORD i = 0; i < entries; i++) {
                    nlohmann::json user;
                    user["username"] = ws2s(pBuf[i].wkui1_username);
                    user["domain"] = ws2s(pBuf[i].wkui1_logon_domain);
                    user["logon_server"] = ws2s(pBuf[i].wkui1_logon_server);
                    users.push_back(user);
                }
                NetApiBufferFree(pBuf);
            }
            return users;
        }

        nlohmann::json GetProcesses() {
            nlohmann::json procs = nlohmann::json::array();
            HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
            if (hSnap != INVALID_HANDLE_VALUE) {
                PROCESSENTRY32 pe; pe.dwSize = sizeof(pe);
                if (Process32First(hSnap, &pe)) {
                    size_t count = 0;
                    do {
                        nlohmann::json proc;
                        proc["pid"] = pe.th32ProcessID;
                        proc["name"] = pe.szExeFile;
                        HANDLE hProc = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pe.th32ProcessID);
                        if (hProc) {
                            HMODULE hMods[1024]; DWORD needed;
                            if (EnumProcessModules(hProc, hMods, sizeof(hMods), &needed)) {
                                nlohmann::json mods = nlohmann::json::array();
                                for (unsigned i = 0; i < (needed / sizeof(HMODULE)); i++) {
                                    char modName[MAX_PATH];
                                    if (GetModuleFileNameExA(hProc, hMods[i], modName, sizeof(modName))) {
                                        mods.push_back(modName);
                                    }
                                }
                                proc["modules"] = mods;
                            }
                            CloseHandle(hProc);
                        }
                        procs.push_back(proc);
                        if (++count >= 50) break;  // Limit to evade scans
                    } while (Process32Next(hSnap, &pe));
                }
                CloseHandle(hSnap);
            }
            return procs;
        }

        nlohmann::json GetShares() {
            nlohmann::json shares = nlohmann::json::array();
            PSHARE_INFO_502 BufPtr = NULL; DWORD entries = 0, total = 0;
            NET_API_STATUS status = NetShareEnum(NULL, 502, (LPBYTE*)&BufPtr, MAX_PREFERRED_LENGTH, &entries, &total, NULL);
            if (status == NERR_Success) {
                 for (DWORD i = 0; i < entries; i++) {
                    if (BufPtr[i].shi502_type == STYPE_DISKTREE) { // Only disk shares
                        nlohmann::json share;
                        share["name"] = ws2s(BufPtr[i].shi502_netname);
                        share["path"] = ws2s(BufPtr[i].shi502_path);
                        shares.push_back(share);
                    }
                }
                NetApiBufferFree(BufPtr);
            }
            return shares;
        }
    }

    std::string GetDeepRecon() {
        nlohmann::json reconData;
        
        // 1. Domain Info
        reconData["domain_info"] = QueryWMI(L"ROOT\\CIMV2", L"SELECT DNSHostName, Domain, PartOfDomain, DomainRole, Workgroup FROM Win32_ComputerSystem", 
            {L"DNSHostName", L"Domain", L"PartOfDomain", L"DomainRole", L"Workgroup"});

        // 2. Security Products
        reconData["security_products"] = QueryWMI(L"ROOT\\SecurityCenter2", L"SELECT displayName, productState, pathToSignedProductExe FROM AntiVirusProduct", 
            {L"displayName", L"productState", L"pathToSignedProductExe"});
        
        if (reconData["security_products"].empty()) {
             // Try older namespace
             reconData["security_products"] = QueryWMI(L"ROOT\\SecurityCenter", L"SELECT displayName, productState, pathToSignedProductExe FROM AntiVirusProduct", 
                {L"displayName", L"productState", L"pathToSignedProductExe"});
        }

        // 3. ARP Table
        reconData["arp_table"] = GetArpTable();

        // 4. Logged-in Users
        reconData["logged_users"] = GetLoggedUsers();

        // 5. Processes
        reconData["processes"] = GetProcesses();

        // 6. Shares
        reconData["shares"] = GetShares();

        return reconData.dump(4);
    }

}
