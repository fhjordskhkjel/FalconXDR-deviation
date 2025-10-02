#pragma once
#include <windows.h>
#include <optional>
#include <string>
#include <vector>
#include "Storage.h"

// Helpers for nicer display
std::wstring ToString(XDR::EventCategory cat);
std::wstring ToString(XDR::EventType type);

INT_PTR CALLBACK QueryDlgProc(HWND, UINT, WPARAM, LPARAM);
