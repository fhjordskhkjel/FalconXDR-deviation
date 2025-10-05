#include "SettingsManager.h"
#include <fstream>
#include <string>

namespace XDR {
namespace Settings {

std::filesystem::path GetSettingsPath() {
    wchar_t mod[MAX_PATH];
    GetModuleFileNameW(nullptr, mod, MAX_PATH);
    std::filesystem::path p(mod);
    return p.parent_path() / L"xdr_ui.cfg";
}

void LoadSettings(UISettings& ui, Behavioral::Settings& behavior) {
    std::error_code ec;
    auto p = GetSettingsPath();
    if (!std::filesystem::exists(p, ec)) return;
    
    std::wifstream f(p);
    if (!f) return;
    
    std::wstring k, v;
    while (f >> k >> v) {
        if (k == L"theme") {
            ui.darkTheme = (v == L"Dark");
        }
        else if (k == L"split") {
            try { ui.splitPos = std::stoi(v); }
            catch (...) {}
        }
        else if (k == L"winx") {
            try { ui.winX = std::stoi(v); }
            catch (...) {}
        }
        else if (k == L"winy") {
            try { ui.winY = std::stoi(v); }
            catch (...) {}
        }
        else if (k == L"winw") {
            try { ui.winW = std::stoi(v); }
            catch (...) {}
        }
        else if (k == L"winh") {
            try { ui.winH = std::stoi(v); }
            catch (...) {}
        }
        else if (k == L"enableUnsigned") {
            behavior.enableUnsignedModuleAlert = (v == L"1");
        }
        else if (k == L"enableApiHooks") {
            behavior.enableApiHookScan = (v == L"1");
        }
        else if (k == L"enableExecReg") {
            behavior.enableExecRegionClassifier = (v == L"1");
        }
        else if (k == L"enableInjectHeur") {
            behavior.enableInjectionHeuristic = (v == L"1");
        }
        else if (k == L"enableThreadScan") {
            behavior.enableThreadScan = (v == L"1");
        }
        else if (k == L"enableProtTrans") {
            behavior.enableProtTransitions = (v == L"1");
        }
        else if (k == L"enableYaraReg") {
            behavior.enableYaraRegionScan = (v == L"1");
        }
        else if (k == L"enableCodeCaves") {
            behavior.enableCodeCaveDetection = (v == L"1");
        }
        else if (k == L"enableIATHooks") {
            // alias of ApiHook scan toggle
            behavior.enableApiHookScan = (v == L"1");
        }
        else if (k == L"enableCodeCaveBps") {
            behavior.enableCodeCaveBreakpointDetect = (v == L"1");
        }
    }
}

void SaveSettings(const UISettings& ui, const Behavioral::Settings& behavior) {
    std::wofstream f(GetSettingsPath());
    if (!f) return;
    
    f << L"theme " << (ui.darkTheme ? L"Dark" : L"Light") << L"\n";
    f << L"split " << ui.splitPos << L"\n";
    f << L"winx " << ui.winX << L"\n";
    f << L"winy " << ui.winY << L"\n";
    f << L"winw " << ui.winW << L"\n";
    f << L"winh " << ui.winH << L"\n";
    f << L"enableUnsigned " << (behavior.enableUnsignedModuleAlert ? 1 : 0) << L"\n";
    f << L"enableApiHooks " << (behavior.enableApiHookScan ? 1 : 0) << L"\n";
    f << L"enableExecReg " << (behavior.enableExecRegionClassifier ? 1 : 0) << L"\n";
    f << L"enableInjectHeur " << (behavior.enableInjectionHeuristic ? 1 : 0) << L"\n";
    f << L"enableThreadScan " << (behavior.enableThreadScan ? 1 : 0) << L"\n";
    f << L"enableProtTrans " << (behavior.enableProtTransitions ? 1 : 0) << L"\n";
    f << L"enableYaraReg " << (behavior.enableYaraRegionScan ? 1 : 0) << L"\n";
    f << L"enableCodeCaves " << (behavior.enableCodeCaveDetection ? 1 : 0) << L"\n";
    f << L"enableIATHooks " << (behavior.enableApiHookScan ? 1 : 0) << L"\n";
    f << L"enableCodeCaveBps " << (behavior.enableCodeCaveBreakpointDetect ? 1 : 0) << L"\n";
}

} // namespace Settings
} // namespace XDR
