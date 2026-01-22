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

    // Rule of Five for proper COM pointer management
    WmiResult(const WmiResult& other);
    WmiResult& operator=(const WmiResult& other);
    WmiResult(WmiResult&& other) noexcept;
    WmiResult& operator=(WmiResult&& other) noexcept;

    std::wstring getString(const wchar_t* propName);
    int getInt(const wchar_t* propName);
    unsigned long long getUnsignedLongLong(const wchar_t* propName);

    IWbemClassObject* getRaw() const { return pObj_; }

private:
    IWbemClassObject* pObj_ = nullptr;
};

// Manages a WMI session and queries
class WmiSession {
public:
    WmiSession();
    WmiSession(const std::wstring& nameSpace);
    ~WmiSession();

    std::vector<WmiResult> execQuery(const std::wstring& query);

private:
    IWbemServices* pSvc_ = nullptr;
    bool comSecurityInitialized_ = false;
};

} // namespace recon
