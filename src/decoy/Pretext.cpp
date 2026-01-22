#include "Pretext.h"
#include <windows.h>

namespace pretext {

void ShowInfoMessage() {
    MessageBoxW(NULL,
                L"A required system component is being updated in the background.",
                L"System Information",
                MB_OK | MB_ICONINFORMATION);
}

} // namespace pretext
