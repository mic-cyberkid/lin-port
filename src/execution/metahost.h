#ifndef __METAHOST_H__
#define __METAHOST_H__

#include <windows.h>
#include <unknwn.h>

typedef PVOID HADDR;

// Forward declarations
interface ICLRRuntimeInfo;

DEFINE_GUID(CLSID_CLRMetaHost, 0x9280188d, 0xe8e, 0x4867, 0xb3, 0xc, 0x7f, 0xa8, 0x38, 0x84, 0xe8, 0xde);
DEFINE_GUID(IID_ICLRMetaHost, 0xD332DB9E, 0xB9E3, 0x4151, 0x9E, 0x01, 0x7A, 0x4F, 0x77, 0x11, 0xE4, 0x56);
DEFINE_GUID(IID_ICLRRuntimeInfo, 0xBD39D1D2, 0xBA2F, 0x486a, 0x89, 0xB0, 0xB4, 0xB0, 0xCB, 0x46, 0x68, 0x91);

interface ICLRRuntimeInfo : public IUnknown
{
    virtual HRESULT STDMETHODCALLTYPE GetRuntimeDirectory(LPWSTR pwzBuffer, DWORD *pcchBuffer) = 0;
    virtual HRESULT STDMETHODCALLTYPE IsLoaded(HANDLE hProcess, BOOL *pbLoaded) = 0;
    virtual HRESULT STDMETHODCALLTYPE GetInterface(REFCLSID rclsid, REFIID riid, LPVOID *ppUnk) = 0;
    virtual HRESULT STDMETHODCALLTYPE IsLoadable(BOOL *pbLoadable) = 0;
    virtual HRESULT STDMETHODCALLTYPE SetDefaultStartupFlags(DWORD dwStartupFlags, LPCWSTR pwzHostConfigFile) = 0;
    virtual HRESULT STDMETHODCALLTYPE GetDefaultStartupFlags(DWORD *pdwStartupFlags, LPWSTR pwzHostConfigFile, DWORD *pcchHostConfigFile) = 0;
    virtual HRESULT STDMETHODCALLTYPE BindAsLegacyV2Runtime(void) = 0;
    virtual HRESULT STDMETHODCALLTYPE IsStarted(BOOL *pbStarted, DWORD *pdwStartupFlags) = 0;
};

interface ICLRMetaHost : public IUnknown
{
    virtual HRESULT STDMETHODCALLTYPE GetRuntime(LPCWSTR pwzVersion, REFIID riid, LPVOID *ppRuntime) = 0;
    virtual HRESULT STDMETHODCALLTYPE GetVersionFromFile(LPCWSTR pwzFilePath, LPWSTR pwzBuffer, DWORD *pcchBuffer) = 0;
    virtual HRESULT STDMETHODCALLTYPE EnumerateInstalledRuntimes(IUnknown **ppEnumerator) = 0;
    virtual HRESULT STDMETHODCALLTYPE EnumerateLoadedRuntimes(HANDLE hProcess, IUnknown **ppEnumerator) = 0;
    virtual HRESULT STDMETHODCALLTYPE RequestRuntimeLoadedNotification(PVOID pCallbackFunction) = 0;
    virtual HRESULT STDMETHODCALLTYPE QueryLegacyV2RuntimeBinding(REFIID riid, LPVOID *ppUnk) = 0;
    virtual HRESULT STDMETHODCALLTYPE ExitProcess(INT32 iExitCode) = 0;
};

// ICorRuntimeHost should be in mscoree.h

extern "C" HRESULT WINAPI CLRCreateInstance(REFCLSID clsid, REFIID riid, LPVOID *ppInterface);

#endif
