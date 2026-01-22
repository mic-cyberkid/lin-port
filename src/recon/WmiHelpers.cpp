#include "WmiHelpers.h"
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
    if (pSvc_) {
        pSvc_->Release();
    }
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
