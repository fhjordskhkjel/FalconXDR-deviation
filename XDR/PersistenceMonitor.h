#pragma once
#include <windows.h>

namespace Behavioral {
    // Called periodically (from Behavioral::Periodic) to perform persistence related scans
    void PersistencePeriodic(HWND hwnd);
}
