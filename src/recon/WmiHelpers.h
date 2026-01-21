#pragma once

#include <string>
#include <vector>
#include <comdef.h>
#include <wbemidl.h>

namespace recon {

// A wrapper for a single WMI result object
class WmiResult {
public:
    WmiResult(IWbemClassObject* obj);
    ~WmiResult();

    std::wstring getString(const wchar_t* propName);
    int getInt(const wchar_t* propName);
    unsigned long long getUnsignedLongLong(const wchar_t* propName);

    IWbemClassObject* pObj_;
};

// Manages a WMI session and queries
class WmiSession {
public:
    WmiSession();
    ~WmiSession();

    std::vector<WmiResult> execQuery(const std::wstring& query);

private:
    IWbemServices* pSvc_ = nullptr;
    bool comSecurityInitialized_ = false;
};

} // namespace recon
