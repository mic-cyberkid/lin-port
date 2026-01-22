#include "Pretext.h"
#include <windows.h>

namespace utils {

void Pretext::ShowFakeError(const std::wstring& message, const std::wstring& title) {
    MessageBoxW(NULL, message.c_str(), title.c_str(), MB_OK | MB_ICONERROR | MB_SYSTEMMODAL);
}

void Pretext::ShowInfoMessage(const std::wstring& message, const std::wstring& title) {
    MessageBoxW(NULL, message.c_str(), title.c_str(), MB_OK | MB_ICONINFORMATION | MB_SYSTEMMODAL);
}

} // namespace utils
