#include "YaraSupport.h"
#include <windows.h>
#include <mutex>
#include <fstream>
#include <filesystem>

namespace {
    struct YaraCtx { HMODULE dll{}; bool ready=false; void* rules{}; void* compiler{}; bool attempted=false; std::mutex m; };
    static YaraCtx g_ctx;
    using yr_initialize_t = int (*)();
    using yr_finalize_t = int (*)();
    using yr_compiler_create_t = int (*)(void**);
    using yr_compiler_destroy_t = void (*)(void*);
    using yr_compiler_add_string_t = int (*)(void*, const char*, const char*);
    using yr_compiler_get_rules_t = int (*)(void*, void**);
    using yr_rules_destroy_t = void (*)(void*);
    using yr_rules_scan_mem_t = int (*)(void*, const uint8_t*, size_t, int, int (*)(int, void*, void*), void*, int);
    static yr_initialize_t p_init=nullptr; static yr_finalize_t p_fini=nullptr; static yr_compiler_create_t p_comp_create=nullptr; static yr_compiler_destroy_t p_comp_destroy=nullptr; static yr_compiler_add_string_t p_comp_add_string=nullptr; static yr_compiler_get_rules_t p_comp_get_rules=nullptr; static yr_rules_destroy_t p_rules_destroy=nullptr; static yr_rules_scan_mem_t p_rules_scan_mem=nullptr;
    struct MatchCtx { std::vector<std::wstring>* out; };
    static int Callback(int msg, void*, void* user){ if(msg==1){ auto* mc=reinterpret_cast<MatchCtx*>(user); mc->out->push_back(L"Match"); } return 0; }
}

namespace YaraSupport {
    void EnsureInit(){ std::lock_guard lg(g_ctx.m); if(g_ctx.ready||g_ctx.attempted) return; g_ctx.attempted=true; g_ctx.dll=LoadLibraryW(L"yara.dll"); if(!g_ctx.dll) return; auto gp=[&](const char* n){ return GetProcAddress(g_ctx.dll,n); }; p_init=(yr_initialize_t)gp("yr_initialize"); p_fini=(yr_finalize_t)gp("yr_finalize"); p_comp_create=(yr_compiler_create_t)gp("yr_compiler_create"); p_comp_destroy=(yr_compiler_destroy_t)gp("yr_compiler_destroy"); p_comp_add_string=(yr_compiler_add_string_t)gp("yr_compiler_add_string"); p_comp_get_rules=(yr_compiler_get_rules_t)gp("yr_compiler_get_rules"); p_rules_destroy=(yr_rules_destroy_t)gp("yr_rules_destroy"); p_rules_scan_mem=(yr_rules_scan_mem_t)gp("yr_rules_scan_mem"); if(!(p_init&&p_fini&&p_comp_create&&p_comp_destroy&&p_comp_add_string&&p_comp_get_rules&&p_rules_destroy&&p_rules_scan_mem)){ FreeLibrary(g_ctx.dll); g_ctx.dll=nullptr; return; } if(p_init()!=0) return; if(p_comp_create(&g_ctx.compiler)!=0) return; const char* rule="rule AlwaysMatch { condition: true }"; if(p_comp_add_string(g_ctx.compiler,rule,nullptr)!=0) return; if(p_comp_get_rules(g_ctx.compiler,&g_ctx.rules)!=0) return; g_ctx.ready=true; }
    bool Initialized(){ std::lock_guard lg(g_ctx.m); return g_ctx.ready; }
    bool ScanBuffer(const uint8_t* data, size_t size, std::vector<std::wstring>& matches){ EnsureInit(); std::lock_guard lg(g_ctx.m); if(!g_ctx.ready) return false; MatchCtx mc{&matches}; return p_rules_scan_mem(g_ctx.rules,data,size,0,Callback,&mc,2000)==0 && !matches.empty(); }
}
