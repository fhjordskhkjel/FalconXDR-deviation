#include "ShellcodeDetection.h"
#include <vector>
#include <string>
#include <sstream>
#include <algorithm>
#include <cmath>

namespace ShellcodeDetection {

static double Entropy(const uint8_t* d,size_t n){ if(n==0) return 0.0; uint32_t f[256]{}; for(size_t i=0;i<n;i++) ++f[d[i]]; double e=0; for(int i=0;i<256;i++){ if(f[i]){ double p=(double)f[i]/n; e -= p*std::log2(p); } } return e; }
static double InstructionDensity(const uint8_t* d,size_t n){ if(n==0) return 0.0; size_t inst=0; for(size_t i=0;i<n;i++){ switch(d[i]){ case 0x55:case 0x53:case 0x57:case 0x56:case 0x48:case 0x8B:case 0x89:case 0xE8:case 0xE9:case 0xFF:case 0x41:case 0x40:case 0xB8:case 0xB9:case 0xBA:case 0xEB: ++inst; default: break; } } return (double)inst/n; }

static bool MemFind(const uint8_t* d,size_t n,const uint8_t* pat,size_t m){ if(m==0||n<m) return false; for(size_t i=0;i<=n-m;i++){ if(std::equal(pat,pat+m,d+i)) return true; } return false; }

ShellcodeIndicators Analyze(const uint8_t* data, size_t size){
    ShellcodeIndicators ind{};
    if(!data || size<16) { ind.entropy=Entropy(data,size); ind.instructionDensity=InstructionDensity(data,size); return ind; }

    // Heuristic byte patterns
    // "GetProcAddress" ASCII/Unicode sequences
    const uint8_t getprocA[] = { 'G','e','t','P','r','o','c','A','d','d','r','e','s','s' };
    const uint8_t getprocW[] = { 'G',0,'e',0,'t',0,'P',0,'r',0,'o',0,'c',0,'A',0,'d',0,'d',0,'r',0,'e',0,'s',0,'s',0 };
    ind.hasGetProcAddress = MemFind(data,size,getprocA,sizeof(getprocA)) || MemFind(data,size,getprocW,sizeof(getprocW));

    // PEB walk: fs/gs segment + pointer chasing of PEB->Ldr, search for "PEB" or loader strings
    const uint8_t ldrStrA[] = { 'L','d','r' };
    const uint8_t kernel32A[] = { 'k','e','r','n','e','l','3','2','.','d','l','l' };
    ind.hasPEB_Walk = MemFind(data,size,ldrStrA,sizeof(ldrStrA)) && MemFind(data,size,kernel32A,sizeof(kernel32A));

    // Stack pivot: look for "xchg eax, esp" (0x94) or "mov esp, reg" (C7? / 0x89 e.g., 0x89 E4)
    for(size_t i=0;i+1<size;i++){
        uint8_t b0=data[i], b1=data[i+1];
        if(b0==0x94 /*xchg eax,esp*/ || (b0==0x89 && (b1&0xF8)==0xE0) /*mov r/m32,esp*/){ ind.hasStackPivot=true; break; }
    }

    // NOP sled: 16 consecutive 0x90
    int nopRun=0; for(size_t i=0;i<size;i++){ if(data[i]==0x90){ if(++nopRun>=16){ ind.hasNopSled=true; break; } } else nopRun=0; }

    // Egg hunter: common tag search loops e.g., 0x66 0x81 0x3C 0x33 'w','00' etc. Simplified pattern
    const uint8_t egg1[] = { 0x66,0x81,0x3C,0x33 };
    ind.hasEggHunter = MemFind(data,size,egg1,sizeof(egg1));

    // Suspicious API sequence text references
    const uint8_t vaA[] = { 'V','i','r','t','u','a','l','A','l','l','o','c' };
    const uint8_t wpmA[] = { 'W','r','i','t','e','P','r','o','c','e','s','s','M','e','m','o','r','y' };
    const uint8_t crtA[] = { 'C','r','e','a','t','e','R','e','m','o','t','e','T','h','r','e','a','d' };
    ind.suspiciousAPISequence = MemFind(data,size,vaA,sizeof(vaA)) && MemFind(data,size,wpmA,sizeof(wpmA)) && MemFind(data,size,crtA,sizeof(crtA));

    ind.entropy = Entropy(data,size);
    ind.instructionDensity = InstructionDensity(data,size);
    return ind;
}

std::wstring ToDetails(const ShellcodeIndicators& ind){
    std::wstringstream ss;
    ss << L"getproc=" << (ind.hasGetProcAddress?1:0)
       << L" peb_walk=" << (ind.hasPEB_Walk?1:0)
       << L" stack_pivot=" << (ind.hasStackPivot?1:0)
       << L" nop_sled=" << (ind.hasNopSled?1:0)
       << L" egg_hunter=" << (ind.hasEggHunter?1:0)
       << L" api_seq=" << (ind.suspiciousAPISequence?1:0)
       << L" ent=" << ind.entropy
       << L" dens=" << ind.instructionDensity;
    return ss.str();
}

}
