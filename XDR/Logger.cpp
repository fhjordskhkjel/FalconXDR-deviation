#include "Logger.h"
#include <mutex>
#include <filesystem>
#include <format>
#include <chrono>
#include <ctime>
#include <cstdio>
#include <windows.h>

class LoggerImpl {
public:
    static LoggerImpl& Instance(){ static LoggerImpl inst; return inst; }
    void Init(){ std::lock_guard lk(m_); if(f_) return; wchar_t path[MAX_PATH]{}; GetModuleFileNameW(nullptr,path,MAX_PATH); std::filesystem::path p(path); p=p.parent_path()/L"xdr_events.log"; path_=p; open(); writeInternal(header()); }
    void Write(std::wstring_view line){ std::lock_guard lk(m_); if(!f_) return; writeInternal(line); rotate(); }
private:
    std::mutex m_;
    std::filesystem::path path_;
    FILE* f_{};
    void writeInternal(std::wstring_view line){ std::wstring out(line); out.append(L"\r\n"); fwrite(out.c_str(),sizeof(wchar_t),out.size(),f_); fflush(f_); }
    void open(){ _wfopen_s(&f_, path_.c_str(), L"ab+"); }
    static std::wstring now(){ using namespace std::chrono; auto n=system_clock::now(); auto ms=duration_cast<milliseconds>(n.time_since_epoch())%1000; std::time_t tt=system_clock::to_time_t(n); std::tm tm{}; localtime_s(&tm,&tt); return std::format(L"{:04}-{:02}-{:02} {:02}:{:02}:{:02}.{:03}",tm.tm_year+1900,tm.tm_mon+1,tm.tm_mday,tm.tm_hour,tm.tm_min,tm.tm_sec,ms.count()); }
    std::wstring header(){ return std::format(L"=== FalconXDR Session Started: {} ===", now()); }
    void rotate(){ constexpr uintmax_t MAX_BYTES=10ull*1024*1024; std::error_code ec; if(std::filesystem::exists(path_,ec)){ auto sz=std::filesystem::file_size(path_,ec); if(!ec && sz>=MAX_BYTES){ fclose(f_); f_=nullptr; auto rotated=path_; rotated+=L".bak"; std::filesystem::remove(rotated,ec); std::filesystem::rename(path_,rotated,ec); open(); } } }
};

void Logger::Init(){ LoggerImpl::Instance().Init(); }
void Logger::Write(std::wstring_view l){ LoggerImpl::Instance().Write(l); }
