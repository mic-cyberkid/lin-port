#include "DotNetExecutor.h"
#include <mscoree.h>
#include <metahost.h>
#include <comutil.h>
#include <iostream>
#include <sstream>

#pragma comment(lib, "mscoree.lib")

// Important: Need to import mscorlib for smart pointers
#import "libid:BED7F4EA-1A96-11D2-8F08-00A0C9A6186D" \
    rename("SizeOf", "SizeOf_") \
    rename("ReportEvent", "ReportEvent_") \
    rename("or", "or_") \
    rename("and", "and_") \
    rename("not", "not_")

using namespace mscorlib;

namespace execution {

DotNetExecutor::DotNetExecutor() {
    StartCLR();
}

DotNetExecutor::~DotNetExecutor() {
    StopCLR();
}

bool DotNetExecutor::StartCLR() {
    HRESULT hr = CLRCreateInstance(CLSID_CLRMetaHost, IID_PPV_ARGS(&m_pMetaHost));
    if (FAILED(hr)) return false;

    // We prefer v4.0 if available
    hr = m_pMetaHost->GetRuntime(L"v4.0.30319", IID_PPV_ARGS(&m_pRuntimeInfo));
    if (FAILED(hr)) {
        // Fallback to v2.0
        hr = m_pMetaHost->GetRuntime(L"v2.0.50727", IID_PPV_ARGS(&m_pRuntimeInfo));
        if (FAILED(hr)) return false;
    }

    BOOL loadable;
    hr = m_pRuntimeInfo->IsLoadable(&loadable);
    if (FAILED(hr) || !loadable) return false;

    hr = m_pRuntimeInfo->GetInterface(CLSID_CorRuntimeHost, IID_PPV_ARGS(&m_pRuntimeHost));
    if (FAILED(hr)) return false;

    hr = m_pRuntimeHost->Start();
    if (FAILED(hr)) return false;

    m_clrStarted = true;
    return true;
}

void DotNetExecutor::StopCLR() {
    if (m_pRuntimeHost) m_pRuntimeHost->Release();
    if (m_pRuntimeInfo) m_pRuntimeInfo->Release();
    if (m_pMetaHost) m_pMetaHost->Release();
}

std::string DotNetExecutor::Execute(const std::vector<uint8_t>& assemblyBytes, const std::vector<std::wstring>& args) {
    if (!m_clrStarted) return "Error: CLR not started.";

    IUnknownPtr pAppDomainThunk = nullptr;
    _AppDomainPtr pDefaultAppDomain = nullptr;

    HRESULT hr = m_pRuntimeHost->GetDefaultDomain(&pAppDomainThunk);
    if (FAILED(hr)) return "Error: Failed to get default AppDomain.";

    hr = pAppDomainThunk->QueryInterface(IID_PPV_ARGS(&pDefaultAppDomain));
    if (FAILED(hr)) return "Error: Failed to query _AppDomain.";

    // Load assembly from memory
    SAFEARRAYBOUND rgsabound[1];
    rgsabound[0].cElements = (ULONG)assemblyBytes.size();
    rgsabound[0].lLbound = 0;
    SAFEARRAY* pSafeArray = SafeArrayCreate(VT_UI1, 1, rgsabound);

    void* pData = nullptr;
    SafeArrayAccessData(pSafeArray, &pData);
    memcpy(pData, assemblyBytes.data(), assemblyBytes.size());
    SafeArrayUnaccessData(pSafeArray);

    _Assembly* pAssembly = nullptr;
    hr = pDefaultAppDomain->raw_Load_3(pSafeArray, &pAssembly);
    if (FAILED(hr)) {
        SafeArrayDestroy(pSafeArray);
        return "Error: Failed to load assembly into AppDomain.";
    }
    _MethodInfoPtr pEntryPoint = nullptr;
    hr = pAssembly->get_EntryPoint(&pEntryPoint);
    if (FAILED(hr)) {
        SafeArrayDestroy(pSafeArray);
        return "Error: Failed to find entry point.";
    }

    // Set up arguments
    SAFEARRAY* pArgs = SafeArrayCreateVector(VT_VARIANT, 0, 1);
    VARIANT vArgs;
    vArgs.vt = VT_ARRAY | VT_BSTR;
    
    SAFEARRAY* pArgsStrings = SafeArrayCreateVector(VT_BSTR, 0, (ULONG)args.size());
    for (LONG i = 0; i < (LONG)args.size(); i++) {
        BSTR bstr = SysAllocString(args[i].c_str());
        SafeArrayPutElement(pArgsStrings, &i, bstr);
    }
    vArgs.parray = pArgsStrings;

    LONG idx = 0;
    SafeArrayPutElement(pArgs, &idx, &vArgs);

    // Call Main
    VARIANT vRet;
    VARIANT vObj;
    VariantInit(&vRet);
    VariantInit(&vObj);
    vObj.vt = VT_NULL;

    // Note: To capture output, we'd need to redirect Console.SetOut in C# or use a pipe.
    // For now, this executes the code.
    hr = pEntryPoint->raw_Invoke_3(vObj, pArgs, &vRet);
    
    SafeArrayDestroy(pArgs);
    SafeArrayDestroy(pSafeArray);

    if (FAILED(hr)) return "Error: Assembly execution failed.";
    
    return "Assembly executed successfully.";
}

} // namespace execution
