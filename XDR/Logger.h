#pragma once
#include <string>
#include <string_view>

class Logger {
public:
    static void Init();
    static void Write(std::wstring_view line);
};
