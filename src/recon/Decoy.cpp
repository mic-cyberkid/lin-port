#include "Decoy.h"
#include <windows.h>
#include <shlwapi.h>
#include <shellapi.h>
#include <fstream>
#include <vector>
#include "../utils/Logger.h"

#pragma comment(lib, "Shlwapi.lib")
#pragma comment(lib, "Shell32.lib")

namespace recon {

void Decoy::Launch() {
    std::wstring decoyPath = GetTempPathForDecoy();
    
    if (CreateDummyDocument(decoyPath)) {
        LOG_INFO("Decoy document created: " + std::string(decoyPath.begin(), decoyPath.end()));
        
        // Open the document with the default handler
        HINSTANCE result = ShellExecuteW(NULL, L"open", decoyPath.c_str(), NULL, NULL, SW_SHOWNORMAL);
        
        if ((INT_PTR)result <= 32) {
            LOG_ERROR("Failed to launch decoy document.");
        } else {
            LOG_INFO("Decoy document launched successfully.");
        }
    } else {
        LOG_ERROR("Failed to create decoy document.");
    }
}

std::wstring Decoy::GetTempPathForDecoy() {
    wchar_t tempPath[MAX_PATH];
    GetTempPathW(MAX_PATH, tempPath);
    
    // We'll name it something innocuous
    return std::wstring(tempPath) + L"Invoice_Report_2024.txt";
}

bool Decoy::CreateDummyDocument(const std::wstring& path) {
    std::wofstream file(path);
    if (!file.is_open()) return false;
    
    file << L"--- CONFIDENTIAL INVOICE REPORT ---" << std::endl;
    file << L"Date: January 22, 2026" << std::endl;
    file << L"Description: Quarterly security audit and software migration services." << std::endl;
    file << L"Amount Due: $15,400.00" << std::endl;
    file << L"Status: PENDING" << std::endl;
    file << L"-----------------------------------" << std::endl;
    file << L"Please contact the billing department if you have any questions." << std::endl;
    
    file.close();
    return true;
}

} // namespace recon
