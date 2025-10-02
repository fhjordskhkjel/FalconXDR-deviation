#include "Storage.h"
#include <windows.h>
#include <mutex>
#include <cstdio>
#include <filesystem>
#include <string>
#include <codecvt>
#include <vector>
#include <chrono>

// We will dynamically load SQLite (sqlite3.dll) if present next to exe.
// This avoids adding build dependencies right now.
// Minimal subset of SQLite C API declarations.
extern "C" {
    typedef struct sqlite3 sqlite3;
    typedef struct sqlite3_stmt sqlite3_stmt;
    typedef int (*sqlite3_open_v2_t)(const char*, sqlite3**, int, const char*);
    typedef int (*sqlite3_close_t)(sqlite3*);
    typedef int (*sqlite3_exec_t)(sqlite3*, const char*, int(*)(void*,int,char**,char**), void*, char**);
    typedef int (*sqlite3_prepare_v2_t)(sqlite3*, const char*, int, sqlite3_stmt**, const char**);
    typedef int (*sqlite3_step_t)(sqlite3_stmt*);
    typedef int (*sqlite3_finalize_t)(sqlite3_stmt*);
    typedef int (*sqlite3_bind_text16_t)(sqlite3_stmt*, int, const void*, int, void(*)(void*));
    typedef int (*sqlite3_bind_int_t)(sqlite3_stmt*, int, int);
    typedef int (*sqlite3_bind_int64_t)(sqlite3_stmt*, int, long long);
    typedef const unsigned char* (*sqlite3_column_text16_t)(sqlite3_stmt*, int);
    typedef int (*sqlite3_column_int_t)(sqlite3_stmt*, int);
    typedef long long (*sqlite3_column_int64_t)(sqlite3_stmt*, int);
    typedef long long (*sqlite3_last_insert_rowid_t)(sqlite3*);
}

#ifndef SQLITE_OK
#define SQLITE_OK 0
#define SQLITE_ROW 100
#define SQLITE_DONE 101
#define SQLITE_OPEN_READWRITE 0x00000002
#define SQLITE_OPEN_CREATE    0x00000004
#endif

namespace {
    std::mutex g_mutex;
    bool g_sqliteAvailable = false;
    HMODULE g_sqliteMod = nullptr;
    sqlite3* g_db = nullptr;

    sqlite3_open_v2_t     p_open  = nullptr;
    sqlite3_close_t       p_close = nullptr;
    sqlite3_exec_t        p_exec  = nullptr;
    sqlite3_prepare_v2_t  p_prep  = nullptr;
    sqlite3_step_t        p_step  = nullptr;
    sqlite3_finalize_t    p_final = nullptr;
    sqlite3_bind_text16_t p_bind_text16 = nullptr;
    sqlite3_bind_int_t    p_bind_int    = nullptr;
    sqlite3_bind_int64_t  p_bind_int64  = nullptr;
    sqlite3_column_text16_t p_col_text16 = nullptr;
    sqlite3_column_int_t    p_col_int = nullptr;
    sqlite3_column_int64_t  p_col_int64 = nullptr;
    sqlite3_last_insert_rowid_t p_last_rowid = nullptr;

    FILE* g_fallbackLog = nullptr;

    std::wstring g_backendDesc = L"Uninitialized";

    std::wstring ToW(const std::string& s) {
        if (s.empty()) return L"";
        int len = MultiByteToWideChar(CP_UTF8,0,s.c_str(),(int)s.size(),nullptr,0);
        std::wstring out(len, L'\0');
        MultiByteToWideChar(CP_UTF8,0,s.c_str(),(int)s.size(),out.data(),len);
        return out;
    }

    std::string Narrow(const std::wstring& ws) {
        if (ws.empty()) return {};
        int len = WideCharToMultiByte(CP_UTF8,0,ws.c_str(),(int)ws.size(),nullptr,0,nullptr,nullptr);
        std::string out(len,'\0');
        WideCharToMultiByte(CP_UTF8,0,ws.c_str(),(int)ws.size(),out.data(),len,nullptr,nullptr);
        return out;
    }

    void OpenFallback(const std::filesystem::path& baseDir) {
        auto p = baseDir / L"xdr_events_fallback.log";
        _wfopen_s(&g_fallbackLog, p.c_str(), L"ab+");
        g_backendDesc = L"PlainLog:" + p.wstring();
    }

    void EnsureSchema() {
        const char* ddl =
            "CREATE TABLE IF NOT EXISTS events (" \
            "id INTEGER PRIMARY KEY AUTOINCREMENT," \
            "ts INTEGER NOT NULL," \
            "category INTEGER NOT NULL," \
            "type INTEGER NOT NULL," \
            "pid INTEGER," \
            "image TEXT," \
            "details TEXT" \
            ");";
        char* err = nullptr;
        if (p_exec(g_db, ddl, nullptr, nullptr, &err) != SQLITE_OK) {
            if (err) LocalFree(err);
        }
        const char* idx = "CREATE INDEX IF NOT EXISTS idx_events_ct ON events(category,type,ts);";
        p_exec(g_db, idx, nullptr, nullptr, nullptr);
    }
}

#include "Storage.h"
using namespace XDR;
using namespace XDR::Storage;

void XDR::Storage::Init()
{
    std::lock_guard lk(g_mutex);
    if (g_db || g_fallbackLog) return;

    wchar_t modulePath[MAX_PATH]{};
    GetModuleFileNameW(nullptr, modulePath, MAX_PATH);
    std::filesystem::path base(modulePath);
    base = base.parent_path();
    auto sqlitePath = base / L"sqlite3.dll";

    if (std::filesystem::exists(sqlitePath)) {
        g_sqliteMod = LoadLibraryW(sqlitePath.c_str());
        if (g_sqliteMod) {
            p_open  = (sqlite3_open_v2_t)GetProcAddress(g_sqliteMod, "sqlite3_open_v2");
            p_close = (sqlite3_close_t)GetProcAddress(g_sqliteMod, "sqlite3_close");
            p_exec  = (sqlite3_exec_t)GetProcAddress(g_sqliteMod, "sqlite3_exec");
            p_prep  = (sqlite3_prepare_v2_t)GetProcAddress(g_sqliteMod, "sqlite3_prepare_v2");
            p_step  = (sqlite3_step_t)GetProcAddress(g_sqliteMod, "sqlite3_step");
            p_final = (sqlite3_finalize_t)GetProcAddress(g_sqliteMod, "sqlite3_finalize");
            p_bind_text16 = (sqlite3_bind_text16_t)GetProcAddress(g_sqliteMod, "sqlite3_bind_text16");
            p_bind_int    = (sqlite3_bind_int_t)GetProcAddress(g_sqliteMod, "sqlite3_bind_int");
            p_bind_int64  = (sqlite3_bind_int64_t)GetProcAddress(g_sqliteMod, "sqlite3_bind_int64");
            p_col_text16  = (sqlite3_column_text16_t)GetProcAddress(g_sqliteMod, "sqlite3_column_text16");
            p_col_int     = (sqlite3_column_int_t)GetProcAddress(g_sqliteMod, "sqlite3_column_int");
            p_col_int64   = (sqlite3_column_int64_t)GetProcAddress(g_sqliteMod, "sqlite3_column_int64");
            p_last_rowid  = (sqlite3_last_insert_rowid_t)GetProcAddress(g_sqliteMod, "sqlite3_last_insert_rowid");
            if (p_open && p_close && p_exec && p_prep && p_step && p_final && p_bind_text16 && p_bind_int && p_bind_int64 && p_col_text16 && p_col_int && p_col_int64 && p_last_rowid) {
                std::filesystem::path dbPath = base / L"xdr_events.db";
                if (p_open(Narrow(dbPath.wstring()).c_str(), &g_db, SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE, nullptr) == SQLITE_OK) {
                    g_sqliteAvailable = true;
                    g_backendDesc = L"SQLite:" + dbPath.wstring();
                    EnsureSchema();
                }
            }
        }
    }
    if (!g_sqliteAvailable) {
        OpenFallback(base);
    }
}

void XDR::Storage::Shutdown()
{
    std::lock_guard lk(g_mutex);
    if (g_db && p_close) { p_close(g_db); g_db = nullptr; }
    if (g_sqliteMod) { FreeLibrary(g_sqliteMod); g_sqliteMod = nullptr; }
    if (g_fallbackLog) { fclose(g_fallbackLog); g_fallbackLog = nullptr; }
}

bool XDR::Storage::UsingSQLite() { return g_sqliteAvailable; }

std::wstring XDR::Storage::BackendDescription() { return g_backendDesc; }

void XDR::Storage::Insert(const Event& ev)
{
    std::lock_guard lk(g_mutex);
    long long ts = std::chrono::duration_cast<std::chrono::seconds>(ev.ts.time_since_epoch()).count();
    if (g_sqliteAvailable && g_db) {
        const char* sql = "INSERT INTO events(ts,category,type,pid,image,details) VALUES(?,?,?,?,?,?);";
        sqlite3_stmt* stmt = nullptr;
        if (p_prep(g_db, sql, -1, &stmt, nullptr) == SQLITE_OK) {
            p_bind_int64(stmt, 1, ts);
            p_bind_int(stmt, 2, (int)ev.category);
            p_bind_int(stmt, 3, (int)ev.type);
            p_bind_int(stmt, 4, (int)ev.pid);
            p_bind_text16(stmt, 5, ev.image.c_str(), -1, nullptr);
            p_bind_text16(stmt, 6, ev.details.c_str(), -1, nullptr);
            p_step(stmt);
            p_final(stmt);
        }
    } else if (g_fallbackLog) {
        // simple line oriented fallback (UTF-16)
        std::wstring line = L"ts=" + std::to_wstring(ts) + L" cat=" + std::to_wstring((int)ev.category) +
            L" type=" + std::to_wstring((int)ev.type) + L" pid=" + std::to_wstring(ev.pid) +
            L" image=" + ev.image + L" details=" + ev.details + L"\r\n";
        fwrite(line.c_str(), sizeof(wchar_t), line.size(), g_fallbackLog);
        fflush(g_fallbackLog);
    }
}

std::vector<XDR::Event> XDR::Storage::QueryRecent(std::size_t limit)
{
    std::vector<Event> result;
    std::lock_guard lk(g_mutex);
    if (!g_sqliteAvailable || !g_db || limit == 0) return result;
    std::string sql = "SELECT id,ts,category,type,pid,image,details FROM events ORDER BY id DESC LIMIT " + std::to_string(limit) + ";";
    sqlite3_stmt* stmt = nullptr;
    if (p_prep(g_db, sql.c_str(), (int)sql.size(), &stmt, nullptr) == SQLITE_OK) {
        while (p_step(stmt) == SQLITE_ROW) {
            Event ev; ev.id = (uint64_t)p_col_int64(stmt,0); long long ts = p_col_int64(stmt, 1);
            ev.ts = std::chrono::system_clock::time_point(std::chrono::seconds(ts));
            ev.category = (EventCategory)p_col_int(stmt,2);
            ev.type     = (EventType)p_col_int(stmt,3);
            ev.pid      = (uint32_t)p_col_int(stmt,4);
            if (const unsigned char* txt = p_col_text16(stmt,5)) ev.image = (wchar_t*)txt;
            if (const unsigned char* txt2 = p_col_text16(stmt,6)) ev.details = (wchar_t*)txt2;
            result.push_back(std::move(ev));
        }
        p_final(stmt);
    }
    return result;
}

std::vector<XDR::Event> XDR::Storage::QueryRecentFiltered(std::optional<EventCategory> category, std::wstring_view contains, std::size_t limit)
{
    std::vector<Event> result;
    std::lock_guard lk(g_mutex);
    if (!g_sqliteAvailable || !g_db || limit == 0) return result;

    std::string sql = "SELECT id,ts,category,type,pid,image,details FROM events WHERE 1=1";
    if (category.has_value()) {
        sql += " AND category=" + std::to_string((int)category.value());
    }
    bool doLike = !contains.empty();
    if (doLike) {
        sql += " AND (image LIKE ?1 OR details LIKE ?1)";
    }
    sql += " ORDER BY id DESC LIMIT " + std::to_string(limit) + ";";

    sqlite3_stmt* stmt = nullptr;
    if (p_prep(g_db, sql.c_str(), (int)sql.size(), &stmt, nullptr) == SQLITE_OK) {
        if (doLike) {
            // Build pattern %text%
            std::wstring pattern = L"%" + std::wstring(contains) + L"%";
            p_bind_text16(stmt, 1, pattern.c_str(), -1, nullptr);
        }
        while (p_step(stmt) == SQLITE_ROW) {
            Event ev; ev.id = (uint64_t)p_col_int64(stmt,0); long long ts = p_col_int64(stmt, 1);
            ev.ts = std::chrono::system_clock::time_point(std::chrono::seconds(ts));
            ev.category = (EventCategory)p_col_int(stmt,2);
            ev.type     = (EventType)p_col_int(stmt,3);
            ev.pid      = (uint32_t)p_col_int(stmt,4);
            if (const unsigned char* txt = p_col_text16(stmt,5)) ev.image = (wchar_t*)txt;
            if (const unsigned char* txt2 = p_col_text16(stmt,6)) ev.details = (wchar_t*)txt2;
            result.push_back(std::move(ev));
        }
        p_final(stmt);
    }
    return result;
}

std::vector<XDR::Event> XDR::Storage::QuerySinceFiltered(uint64_t lastId, std::optional<EventCategory> category, std::wstring_view contains, std::size_t limit)
{
    std::vector<Event> result;
    std::lock_guard lk(g_mutex);
    if (!g_sqliteAvailable || !g_db || limit == 0) return result;

    std::string sql = "SELECT id,ts,category,type,pid,image,details FROM events WHERE id > ?1"; // fixed ?0 -> ?1
    if (category.has_value()) sql += " AND category=" + std::to_string((int)category.value());
    bool doLike = !contains.empty();
    if (doLike) sql += " AND (image LIKE ?2 OR details LIKE ?2)"; // shift param index when LIKE used
    sql += " ORDER BY id ASC LIMIT " + std::to_string(limit) + ";"; // ascending for streaming

    sqlite3_stmt* stmt = nullptr;
    if (p_prep(g_db, sql.c_str(), (int)sql.size(), &stmt, nullptr) == SQLITE_OK) {
        p_bind_int64(stmt, 1, (long long)lastId);
        if (doLike) {
            std::wstring pattern = L"%" + std::wstring(contains) + L"%";
            p_bind_text16(stmt, 2, pattern.c_str(), -1, nullptr);
        }
        while (p_step(stmt) == SQLITE_ROW) {
            Event ev; ev.id = (uint64_t)p_col_int64(stmt,0); long long ts = p_col_int64(stmt,1);
            ev.ts = std::chrono::system_clock::time_point(std::chrono::seconds(ts));
            ev.category = (EventCategory)p_col_int(stmt,2);
            ev.type     = (EventType)p_col_int(stmt,3);
            ev.pid      = (uint32_t)p_col_int(stmt,4);
            if (const unsigned char* txt = p_col_text16(stmt,5)) ev.image = (wchar_t*)txt;
            if (const unsigned char* txt2 = p_col_text16(stmt,6)) ev.details = (wchar_t*)txt2;
            result.push_back(std::move(ev));
        }
        p_final(stmt);
    }
    return result;
}

std::vector<XDR::Event> XDR::Storage::QueryRecentAdvanced(std::optional<EventCategory> category, std::wstring_view contains, std::optional<uint32_t> pid, std::size_t limit)
{
    std::vector<Event> result;
    std::lock_guard lk(g_mutex);
    if (!g_sqliteAvailable || !g_db || limit == 0) return result;

    std::string sql = "SELECT id,ts,category,type,pid,image,details FROM events WHERE 1=1";
    if (category) sql += " AND category=" + std::to_string((int)category.value());
    if (pid) sql += " AND pid=" + std::to_string(pid.value());
    bool doLike = !contains.empty();
    if (doLike) sql += " AND (image LIKE ?1 OR details LIKE ?1)";
    sql += " ORDER BY id DESC LIMIT " + std::to_string(limit) + ";";
    sqlite3_stmt* stmt = nullptr;
    if (p_prep(g_db, sql.c_str(), (int)sql.size(), &stmt, nullptr) == SQLITE_OK) {
        if (doLike) {
            std::wstring pattern = L"%" + std::wstring(contains) + L"%";
            p_bind_text16(stmt, 1, pattern.c_str(), -1, nullptr);
        }
        while (p_step(stmt) == SQLITE_ROW) {
            Event ev; ev.id = (uint64_t)p_col_int64(stmt,0); long long ts = p_col_int64(stmt,1);
            ev.ts = std::chrono::system_clock::time_point(std::chrono::seconds(ts));
            ev.category = (EventCategory)p_col_int(stmt,2);
            ev.type     = (EventType)p_col_int(stmt,3);
            ev.pid      = (uint32_t)p_col_int(stmt,4);
            if (const unsigned char* txt = p_col_text16(stmt,5)) ev.image = (wchar_t*)txt;
            if (const unsigned char* txt2 = p_col_text16(stmt,6)) ev.details = (wchar_t*)txt2;
            result.push_back(std::move(ev));
        }
        p_final(stmt);
    }
    return result;
}

std::vector<XDR::Event> XDR::Storage::QuerySinceAdvanced(uint64_t lastId, std::optional<EventCategory> category, std::wstring_view contains, std::optional<uint32_t> pid, std::size_t limit)
{
    std::vector<Event> result;
    std::lock_guard lk(g_mutex);
    if (!g_sqliteAvailable || !g_db || limit == 0) return result;

    std::string sql = "SELECT id,ts,category,type,pid,image,details FROM events WHERE id > ?1"; // fixed ?0 -> ?1
    if (category) sql += " AND category=" + std::to_string((int)category.value());
    if (pid) sql += " AND pid=" + std::to_string(pid.value());
    bool doLike = !contains.empty();
    if (doLike) sql += " AND (image LIKE ?2 OR details LIKE ?2)"; // shift index
    sql += " ORDER BY id ASC LIMIT " + std::to_string(limit) + ";";
    sqlite3_stmt* stmt = nullptr;
    if (p_prep(g_db, sql.c_str(), (int)sql.size(), &stmt, nullptr) == SQLITE_OK) {
        p_bind_int64(stmt, 1, (long long)lastId);
        if (doLike) {
            std::wstring pattern = L"%" + std::wstring(contains) + L"%";
            p_bind_text16(stmt, 2, pattern.c_str(), -1, nullptr);
        }
        while (p_step(stmt) == SQLITE_ROW) {
            Event ev; ev.id = (uint64_t)p_col_int64(stmt,0); long long ts = p_col_int64(stmt,1);
            ev.ts = std::chrono::system_clock::time_point(std::chrono::seconds(ts));
            ev.category = (EventCategory)p_col_int(stmt,2);
            ev.type     = (EventType)p_col_int(stmt,3);
            ev.pid      = (uint32_t)p_col_int(stmt,4);
            if (const unsigned char* txt = p_col_text16(stmt,5)) ev.image = (wchar_t*)txt;
            if (const unsigned char* txt2 = p_col_text16(stmt,6)) ev.details = (wchar_t*)txt2;
            result.push_back(std::move(ev));
        }
        p_final(stmt);
    }
    return result;
}

std::vector<XDR::Event> XDR::Storage::QueryRecentAdvancedTokens(std::optional<EventCategory> category, std::wstring_view contains, std::optional<uint32_t> pid, const std::vector<std::wstring>& tokens, std::size_t limit)
{
    std::vector<Event> result; std::lock_guard lk(g_mutex);
    if(!g_sqliteAvailable || !g_db || limit==0) return result;
    std::string sql = "SELECT id,ts,category,type,pid,image,details FROM events WHERE 1=1";
    if(category) sql += " AND category=" + std::to_string((int)category.value());
    if(pid) sql += " AND pid=" + std::to_string(pid.value());
    bool doLikeMain = !contains.empty();
    int bindIndex = 1;
    if(doLikeMain){ sql += " AND (image LIKE ?" + std::to_string(bindIndex) + " OR details LIKE ?" + std::to_string(bindIndex) + ")"; bindIndex++; }
    // Each token -> AND details LIKE ?X
    for(size_t i=0;i<tokens.size();++i){ sql += " AND details LIKE ?" + std::to_string(bindIndex); bindIndex++; }
    sql += " ORDER BY id DESC LIMIT " + std::to_string(limit) + ";";
    sqlite3_stmt* stmt=nullptr; if(p_prep(g_db,sql.c_str(),(int)sql.size(),&stmt,nullptr)==SQLITE_OK){ int bi=1; if(doLikeMain){ std::wstring pat=L"%"+std::wstring(contains)+L"%"; p_bind_text16(stmt, bi++, pat.c_str(), -1, nullptr); }
        for(auto &t: tokens){ std::wstring pat=L"%"+t+L"%"; p_bind_text16(stmt, bi++, pat.c_str(), -1, nullptr); }
        while(p_step(stmt)==SQLITE_ROW){ Event ev; ev.id=(uint64_t)p_col_int64(stmt,0); long long ts=p_col_int64(stmt,1); ev.ts=std::chrono::system_clock::time_point(std::chrono::seconds(ts)); ev.category=(EventCategory)p_col_int(stmt,2); ev.type=(EventType)p_col_int(stmt,3); ev.pid=(uint32_t)p_col_int(stmt,4); if(const unsigned char* txt=p_col_text16(stmt,5)) ev.image=(wchar_t*)txt; if(const unsigned char* txt2=p_col_text16(stmt,6)) ev.details=(wchar_t*)txt2; result.push_back(std::move(ev)); }
        p_final(stmt);
    }
    return result;
}

std::vector<XDR::Event> XDR::Storage::QuerySinceAdvancedTokens(uint64_t lastId, std::optional<EventCategory> category, std::wstring_view contains, std::optional<uint32_t> pid, const std::vector<std::wstring>& tokens, std::size_t limit)
{
    std::vector<Event> result; std::lock_guard lk(g_mutex);
    if(!g_sqliteAvailable || !g_db || limit==0) return result;
    std::string sql = "SELECT id,ts,category,type,pid,image,details FROM events WHERE id > ?1"; // param 1 fixed for lastId
    if(category) sql += " AND category=" + std::to_string((int)category.value());
    if(pid) sql += " AND pid=" + std::to_string(pid.value());
    bool doLikeMain = !contains.empty();
    int bindIndexBase = 2; // next parameter index after lastId
    if(doLikeMain){ sql += " AND (image LIKE ?2 OR details LIKE ?2)"; bindIndexBase = 3; }
    int curIndex = bindIndexBase;
    for(size_t i=0;i<tokens.size();++i){ sql += " AND details LIKE ?" + std::to_string(curIndex); curIndex++; }
    sql += " ORDER BY id ASC LIMIT " + std::to_string(limit) + ";";
    sqlite3_stmt* stmt=nullptr; if(p_prep(g_db,sql.c_str(),(int)sql.size(),&stmt,nullptr)==SQLITE_OK){ p_bind_int64(stmt,1,(long long)lastId); int bi=2; if(doLikeMain){ std::wstring pat=L"%"+std::wstring(contains)+L"%"; p_bind_text16(stmt,2,pat.c_str(),-1,nullptr); bi=3; } for(size_t i=0;i<tokens.size();++i){ std::wstring pat=L"%"+tokens[i]+L"%"; p_bind_text16(stmt,bi++,pat.c_str(),-1,nullptr);} while(p_step(stmt)==SQLITE_ROW){ Event ev; ev.id=(uint64_t)p_col_int64(stmt,0); long long ts=p_col_int64(stmt,1); ev.ts=std::chrono::system_clock::time_point(std::chrono::seconds(ts)); ev.category=(EventCategory)p_col_int(stmt,2); ev.type=(EventType)p_col_int(stmt,3); ev.pid=(uint32_t)p_col_int(stmt,4); if(const unsigned char* txt=p_col_text16(stmt,5)) ev.image=(wchar_t*)txt; if(const unsigned char* txt2=p_col_text16(stmt,6)) ev.details=(wchar_t*)txt2; result.push_back(std::move(ev)); } p_final(stmt);} return result;
}
