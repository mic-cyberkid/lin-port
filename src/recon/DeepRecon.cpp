#include "DeepRecon.h"
#include "../external/nlohmann/json.hpp"
#include <windows.h>
#include <iphlpapi.h>
#include <comdef.h>
#include <WbemIdl.h>
#include <vector>
#include <iostream>
#include <iomanip>

#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "wbemuuid.lib")

namespace recon {

    namespace {
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
                        std::wstring key_ws = prop;
                        std::string key_s;
                        for(wchar_t wc : key_ws) key_s += (char)wc;

                        if (vtProp.vt == VT_BSTR) {
                            std::wstring ws(vtProp.bstrVal);
                            std::string s;
                            for(wchar_t wc : ws) s += (char)wc;
                            item[key_s] = s;
                        } else if (vtProp.vt == VT_I4) {
                            item[key_s] = vtProp.lVal;
                        } else if (vtProp.vt == VT_BOOL) {
                            item[key_s] = (bool)vtProp.boolVal;
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

        std::string GetArpTable() {
            nlohmann::json arpList = nlohmann::json::array();
            ULONG outBufLen = sizeof(MIB_IPNETTABLE);
            PMIB_IPNETTABLE pIpNetTable = (MIB_IPNETTABLE*)malloc(outBufLen);
            
            if (GetIpNetTable(pIpNetTable, &outBufLen, FALSE) == ERROR_INSUFFICIENT_BUFFER) {
                free(pIpNetTable);
                pIpNetTable = (MIB_IPNETTABLE*)malloc(outBufLen);
            }

            if (GetIpNetTable(pIpNetTable, &outBufLen, FALSE) == NO_ERROR) {
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
            free(pIpNetTable);
            return arpList.dump();
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
        reconData["arp_table"] = nlohmann::json::parse(GetArpTable());

        return reconData.dump(4);
    }

}
