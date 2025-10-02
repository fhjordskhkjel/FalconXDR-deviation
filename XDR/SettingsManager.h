#pragma once
#include <windows.h>
#include <filesystem>
#include "BehavioralAnalyzer.h"

namespace XDR {
namespace Settings {

// UI settings
struct UISettings {
    bool darkTheme = true;
    int splitPos = 600;
    int winX = CW_USEDEFAULT;
    int winY = 0;
    int winW = 1400;
    int winH = 800;
};

std::filesystem::path GetSettingsPath();
void LoadSettings(UISettings& ui, Behavioral::Settings& behavior);
void SaveSettings(const UISettings& ui, const Behavioral::Settings& behavior);

} // namespace Settings
} // namespace XDR
