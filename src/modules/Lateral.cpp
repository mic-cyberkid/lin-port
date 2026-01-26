#include "Lateral.h"
#include <comdef.h>
#include <WbemIdl.h>

#pragma comment(lib, "wbemuuid.lib")

namespace Lateral {

    bool WmiRemoteExec(const std::wstring& target, const std::wstring& cmd) {
        IWbemLocator* pLoc = NULL;
        HRESULT hr = CoCreateInstance(CLSID_WbemLocator, NULL, CLSCTX_INPROC_SERVER, IID_IWbemLocator, (void**)&pLoc);
        if (FAILED(hr)) {
            return false;
        }

        IWbemServices* pSvc = NULL;
        std::wstring serverPath = L"\\\\" + target + L"\\root\\cimv2";
        hr = pLoc->ConnectServer(_bstr_t(serverPath.c_str()), NULL, NULL, NULL, 0, NULL, NULL, &pSvc);
        if (FAILED(hr)) {
            pLoc->Release();
            return false;
        }

        hr = CoSetProxyBlanket(pSvc, RPC_C_AUTHN_WINNT, RPC_C_AUTHZ_NONE, NULL, RPC_C_AUTHN_LEVEL_CALL, RPC_C_IMP_LEVEL_IMPERSONATE, NULL, EOAC_NONE);
        if (FAILED(hr)) {
            pSvc->Release();
            pLoc->Release();
            return false;
        }

        IWbemClassObject* pClass = NULL;
        hr = pSvc->GetObject(_bstr_t(L"Win32_Process"), 0, NULL, &pClass, NULL);
        if (FAILED(hr)) {
            pSvc->Release();
            pLoc->Release();
            return false;
        }

        IWbemClassObject* pInParams = NULL;
        hr = pClass->GetMethod(_bstr_t(L"Create"), 0, &pInParams, NULL);
        if (FAILED(hr)) {
            pClass->Release();
            pSvc->Release();
            pLoc->Release();
            return false;
        }

        VARIANT varCmd;
        varCmd.vt = VT_BSTR;
        varCmd.bstrVal = SysAllocString(cmd.c_str());
        pInParams->Put(L"CommandLine", 0, &varCmd, 0);

        IWbemClassObject* pOutParams = NULL;
        hr = pSvc->ExecMethod(_bstr_t(L"Win32_Process"), _bstr_t(L"Create"), 0, NULL, pInParams, &pOutParams, NULL);

        VariantClear(&varCmd);
        if (pOutParams) pOutParams->Release();
        pInParams->Release();
        pClass->Release();
        pSvc->Release();
        pLoc->Release();

        return SUCCEEDED(hr);
    }

}
