//
// Created by DiaLight on 13.09.2024.
//

#include "bug_hunter.h"
#include "dk2_globals.h"
#include "StackLimits.h"
#include "LoadedModules.h"
#include "win32_gui_layout.h"
#include "patches/game_version_patch.h"
#include <Windows.h>
#include <TlHelp32.h>
#include <cstdio>
#include <cstdint>
#include <vector>
#include <sstream>
#include <iostream>
#include <iomanip>
#include <ranges>
#include <queue>
#include <thread>
#include <fstream>
#include <filesystem>
#include <ShlObj_core.h>
#include <codecvt>

#include "console.h"
#include "flame_config.h"
#include "sha1.hpp"
#include "tools/bug_hunter/MyFpoFun.h"
#include "tools/bug_hunter/StackWalker.h"
#include "tools/bug_hunter/StackWalkerState.h"

namespace fs = std::filesystem;

#define fmtHex32(val) std::hex << std::setw(8) << std::setfill('0') << std::uppercase << (val) << std::dec
#define fmtHex16(val) std::hex << std::setw(4) << std::setfill('0') << std::uppercase << (val) << std::dec
#define fmtHex8(val) std::hex << std::setw(2) << std::setfill('0') << std::uppercase << ((DWORD) val) << std::dec
#define fmtHex32W(val) std::hex << std::setw(8) << std::setfill(L'0') << std::uppercase << (val) << std::dec
#define fmtHex(val) std::hex << std::uppercase << (val) << std::dec

struct MyCodeViewInfo {

    enum class CodeViewMagic : unsigned int {
        pdb70 = 'SDSR', // RSDS
        pdb20 = '01BN', // NB10
    };

    struct DebugInfoPdb20 {
        CodeViewMagic magic;
        unsigned int offset;
        unsigned int signature;
        unsigned int age;
        char pdbName[1];
    };

    struct DebugInfoPdb70 {
        CodeViewMagic magic;
        GUID guid;
        unsigned int age;
        char pdbName[1];
    };

    union DebugInfo {
        CodeViewMagic magic;
        DebugInfoPdb20 pdb20;
        DebugInfoPdb70 pdb70;
    };

    HMODULE base;
    DebugInfo *codeView = nullptr;
    explicit MyCodeViewInfo(HMODULE hModule) : base(hModule) {}

    bool find() {
        auto *pHeader = (PIMAGE_DOS_HEADER) base;
        if (pHeader->e_magic != IMAGE_DOS_SIGNATURE) return false;
        auto *header = (PIMAGE_NT_HEADERS) ((BYTE *) base + ((PIMAGE_DOS_HEADER) base)->e_lfanew);
        if (header->Signature != IMAGE_NT_SIGNATURE) return false;
        if (header->OptionalHeader.NumberOfRvaAndSizes == 0) return false;
        DWORD debugRva = header->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG].VirtualAddress;
        if (debugRva == 0) return false;
        DWORD debugSize = header->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG].Size;
        PIMAGE_DEBUG_DIRECTORY debug = (PIMAGE_DEBUG_DIRECTORY) ((BYTE *) base + debugRva);
        PIMAGE_DEBUG_DIRECTORY debugEnd = (PIMAGE_DEBUG_DIRECTORY) ((BYTE *) debug + debugSize);
        DWORD codeViewRva = 0;
        DWORD codeViewSize = 0;
        for(; debug < debugEnd; debug++) {
            if (debug->Type != IMAGE_DEBUG_TYPE_CODEVIEW) continue;
            codeViewRva = debug->AddressOfRawData;
            codeViewSize = debug->SizeOfData;
            break;
        }
        if(codeViewRva == 0) return false;
        DebugInfo *codeView = (DebugInfo *) ((BYTE *) base + codeViewRva);
        if(codeView->magic != CodeViewMagic::pdb70) return false;
        this->codeView = codeView;
        return true;
    }
};
struct MyVersionInfo {
    struct LANGANDCODEPAGE {
        WORD wLanguage;
        WORD wCodePage;
    };

    HMODULE hModule;
    LPVOID versionInfo = NULL;
    UINT cbVersionInfo = 0;
    LANGANDCODEPAGE *lpTranslate = NULL;
    UINT cbTranslate = 0;

    explicit MyVersionInfo(HMODULE hModule) : hModule(hModule) {}
    ~MyVersionInfo() {
        if(versionInfo) free(versionInfo);
    }

    bool open() {
        wchar_t filePath[MAX_PATH];
        GetModuleFileNameW(hModule, filePath, MAX_PATH);
        DWORD dwHandle;
        DWORD vSize = GetFileVersionInfoSizeW(filePath, &dwHandle);
        if (vSize == 0) return false;
        cbVersionInfo = vSize + 1;
        versionInfo = malloc(vSize + 1);
        if (!GetFileVersionInfoExW(FILE_VER_GET_NEUTRAL, filePath, dwHandle, vSize, versionInfo)) return false;
        if (!VerQueryValueW(versionInfo, L"\\VarFileInfo\\Translation", (LPVOID*) &lpTranslate, &cbTranslate)) return false;
        return true;
    }

#define LANGID_US_ENGLISH 0x0409
    std::string queryValue(const char *csEntry) const {
        for(unsigned int i = 0; i < (cbTranslate / sizeof(LANGANDCODEPAGE)); i++) {
            if(lpTranslate[i].wLanguage != LANGID_US_ENGLISH) continue;
            char subblock[256];
            sprintf_s(subblock, "\\StringFileInfo\\%04x%04x\\%s", lpTranslate[i].wLanguage, lpTranslate[i].wCodePage, csEntry);
            char *description = NULL;
            UINT dwBytes;
            if(VerQueryValue(versionInfo, subblock, (LPVOID*) &description, &dwBytes)) {
                return (char *) description;
            }
        }
        return "";
    }
};

uint32_t decodeVarint(uint8_t *&p) {
    uint32_t ret = 0;
    int i = 0;
    while (true) {
        uint8_t b = *p++;
        ret |= (b & 0x7F) << (7 * i++);
        if(!(b & 0x80)) break;
    }
    return ret;
}
int32_t decodeSignedVarint(uint8_t *&p) {
    uint32_t v = decodeVarint(p);
    if(v & 1) return -(v >> 1);
    return v >> 1;
}

EXTERN_C __declspec(dllexport) void *_dkii_fpomap_start = nullptr;
EXTERN_C __declspec(dllexport) void *_dkii_text_start = nullptr;
EXTERN_C __declspec(dllexport) void *_dkii_text_end = nullptr;

EXTERN_C __declspec(dllexport) void *_flame_base = nullptr;
EXTERN_C __declspec(dllexport) void *_flame_fpomap_start = nullptr;
EXTERN_C __declspec(dllexport) void *_flame_text_start = nullptr;
EXTERN_C __declspec(dllexport) void *_flame_text_end = nullptr;

std::shared_ptr<LoadedModule> bughunter::weanetr;
std::shared_ptr<LoadedModule> bughunter::qmixer;


std::vector<MyFpoFun>::iterator bughunter::find_gt(std::vector<MyFpoFun> &fpos, DWORD rva) {
    return std::upper_bound(fpos.begin(), fpos.end(), rva, [](DWORD rva, MyFpoFun &bl) {
        return rva < bl.rva;
    });
}

std::vector<MyFpoFun>::iterator bughunter::find_le(std::vector<MyFpoFun> &fpos, DWORD rva) {
    auto it = find_gt(fpos, rva);
    if (it == fpos.begin()) return fpos.end();
    return it - 1;
}

uintptr_t bughunter::dkii_base = 0;
uintptr_t bughunter::dkii_entry = 0;
uintptr_t bughunter::dkii_fpomap_start = 0;
uintptr_t bughunter::dkii_text_start = 0;
uintptr_t bughunter::dkii_text_end = 0;
std::vector<MyFpoFun> bughunter::dkii_fpomap;

bool bughunter::isDkiiCode(DWORD ptr) noexcept {
    return dkii_text_start <= ptr && ptr < dkii_text_end;
}

uintptr_t bughunter::flame_base = 0;
uintptr_t bughunter::flame_fpomap_start = 0;
uintptr_t bughunter::flame_text_start = 0;
uintptr_t bughunter::flame_text_end = 0;
std::vector<MyFpoFun> bughunter::flame_fpomap;

bool bughunter::isFlameCode(DWORD ptr) noexcept {
    return flame_text_start <= ptr && ptr < flame_text_end;
}

bool ichar_equals(char a, char b) {
    return std::tolower(static_cast<unsigned char>(a)) ==
           std::tolower(static_cast<unsigned char>(b));
}
bool iequals(const std::string& a, const std::string& b) {
    return std::equal(a.begin(), a.end(), b.begin(), b.end(), ichar_equals);
}

void resolveLocs() {
    bughunter::dkii_base = (uintptr_t) GetModuleHandleA(NULL);
    {
        auto *pHeader = (PIMAGE_DOS_HEADER) bughunter::dkii_base;
        if (pHeader->e_magic == IMAGE_DOS_SIGNATURE) {
            auto *header = (PIMAGE_NT_HEADERS) ((BYTE *) bughunter::dkii_base + ((PIMAGE_DOS_HEADER) bughunter::dkii_base)->e_lfanew);
            bughunter::dkii_entry = bughunter::dkii_base + header->OptionalHeader.AddressOfEntryPoint;
        }
    }

    bughunter::dkii_fpomap_start = (uintptr_t) _dkii_fpomap_start;
    bughunter::dkii_text_start = (uintptr_t) _dkii_text_start;
    bughunter::dkii_text_end = (uintptr_t) _dkii_text_end;

    bughunter::flame_base = (uintptr_t) _flame_base;
    bughunter::flame_fpomap_start = (uintptr_t) _flame_fpomap_start;
    bughunter::flame_text_start = (uintptr_t) _flame_text_start;
    bughunter::flame_text_end = (uintptr_t) _flame_text_end;

    LoadedModules modules;
    modules.update();
    for(auto &mod : modules) {
        if(iequals(mod->name, "weanetr.dll")) bughunter::weanetr = mod;
        if(iequals(mod->name, "QMIXER.dll")) bughunter::qmixer = mod;
    }
}

void parseFpomap(uintptr_t fpomap_start, std::vector<MyFpoFun> &fpomap) {
    fpomap.clear();
    auto *p = (uint8_t *) fpomap_start;
    size_t fposCount = decodeVarint(p);
//    printf("fposCount = %d\n", fposCount);
    DWORD rva = 0;
    for (int i = 0; i < fposCount; ++i) {
        rva += decodeVarint(p);
        size_t sz = decodeVarint(p);
        const char *name = (const char *) p;
        p += strlen(name) + 1;
        auto &fpoFun = fpomap.emplace_back();
        fpoFun.rva = rva;
        fpoFun.rva_end = fpoFun.rva + sz;
        fpoFun.name = name;
//        printf("%08X-%08X %s\n", va, va + sz, name);
        size_t spdsCount = decodeVarint(p);
        for (int j = 0; j < spdsCount; ++j) {
            size_t offs = decodeVarint(p);
            int32_t spd = decodeSignedVarint(p);
            uint32_t ty = decodeVarint(p);
            uint32_t kind = decodeVarint(p);

            auto &mySpd = fpoFun.spds.emplace_back();
            mySpd.offs = offs;
            mySpd.spd = spd;
            mySpd.ty = ty;
            mySpd.kind = kind;
        }
    }
}

struct AppThread {
    DWORD tid = 0;
    HANDLE hThread = NULL;
    bool suspended = false;

    AppThread() = default;
    AppThread(DWORD tid, HANDLE hThread) : tid(tid), hThread(hThread) {}
    AppThread(const AppThread& Right) noexcept = delete;
    AppThread(AppThread&& R) noexcept : tid(R.tid), hThread(R.hThread) {
        R.tid = 0;
        R.hThread = NULL;
    }
    AppThread& operator=(const AppThread& Right) noexcept = delete;
    AppThread& operator=(AppThread&& R) noexcept {
        if(this == &R) return *this;
        reset();
        tid = R.tid;
        hThread = R.hThread;
        R.tid = 0;
        R.hThread = NULL;
        return *this;
    }
    ~AppThread() {
        reset();
    }

    void reset() {
        if (!hThread) return;
        CloseHandle(hThread);
        hThread = NULL;
    }

    void suspend() {
        if(suspended) return;
        SuspendThread(hThread);
        suspended = true;
    }
    void resume() {
        if(!suspended) return;
        ResumeThread(hThread);
        suspended = false;
    }
    void terminate() const {
        __try{
            TerminateThread(hThread, 0);
        } __except(0xC000071C) {}
    }

};

std::vector<AppThread> collectAppThreadsExceptCurrent() {
    std::vector<AppThread> states;
    HANDLE h = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (h == INVALID_HANDLE_VALUE) return {};
    DWORD curPid = GetCurrentProcessId();
    DWORD curTid = GetCurrentThreadId();
    THREADENTRY32 te;
    te.dwSize = sizeof(te);
    for(bool b = Thread32First(h, &te); b; b = Thread32Next(h, &te)) {
        if (te.th32OwnerProcessID != curPid) continue;
        if (te.th32ThreadID == curTid) continue;
        if(HANDLE hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, te.th32ThreadID)) {
            states.emplace_back(te.th32ThreadID, hThread);
        }
    }
    CloseHandle(h);
    return states;
}


std::string wide_string_to_string(const wchar_t *wide_string) {
    if (wide_string == NULL || wide_string[0] == L'\0') return "";

    size_t wlen = wcslen(wide_string);
    const auto size_needed = WideCharToMultiByte(CP_UTF8, 0, wide_string, wlen, nullptr, 0, nullptr, nullptr);
    if (size_needed <= 0) {
        std::string ret(wlen, 0);
        for (int i = 0; i < wlen; ++i) ret[i] = wide_string[i];
        return ret;
    }

    std::string result(size_needed, 0);
    WideCharToMultiByte(CP_UTF8, 0, wide_string, wlen, result.data(), size_needed, nullptr, nullptr);
    return result;
}
template<typename charT>
struct my_equal {
    my_equal( const std::locale& loc ) : loc_(loc) {}
    bool operator()(charT ch1, charT ch2) {
        return std::toupper(ch1, loc_) == std::toupper(ch2, loc_);
    }
private:
    const std::locale& loc_;
};

// find substring (case insensitive)
template<typename T>
int ci_find_substr( const T& str1, const T& str2, const std::locale& loc = std::locale() ) {
    typename T::const_iterator it = std::search(
            str1.begin(), str1.end(), str2.begin(), str2.end(),
            my_equal<typename T::value_type>(loc) );
    if ( it != str1.end() ) return it - str1.begin();
    else return -1; // not found
}

void formatHeader(std::stringstream &ss, FILETIME &timestamp) {
    ss << "timestamp: " << fmtHex32(timestamp.dwHighDateTime) << fmtHex32(timestamp.dwLowDateTime);
    {
        SYSTEMTIME stime;
        FileTimeToSystemTime(&timestamp, &stime);

        char timeStr[64];
        snprintf(timeStr, sizeof(timeStr), "%d.%02d.%02d %02d:%02d:%02d %d UTC",
                 stime.wYear, stime.wMonth, stime.wDay,
                 stime.wHour, stime.wMinute, stime.wSecond, stime.wMilliseconds);
        ss << " (" << timeStr << ")" << std::endl;
    }
    std::string version = "<unknown>";
    if(auto *ver = patch::game_version_patch::getFileVersion()) version = ver;
    std::replace(version.begin(), version.end(), '\n', ' ');
    ss << "version: " << version << std::endl;
    std::string commandLine = wide_string_to_string(GetCommandLineW());
    int pos = ci_find_substr<std::string>(commandLine, ".exe");
    if(pos != -1) commandLine = commandLine.substr(pos);
    ss << "command line: " << commandLine << std::endl;
}

void formatModules(std::stringstream &ss, LoadedModules &modules) {
    ss << "modules:" << std::endl;
    for(auto &mod : modules) {
        ss << fmtHex32(mod->base) << "-" << fmtHex32(mod->end) << " ";
        ss << std::left << std::setw(16) << std::setfill(' ') << mod->name;
        bool hasId = false;
        MyVersionInfo ver((HMODULE) mod->base);
        if(ver.open()) {
            std::string version = ver.queryValue("FileVersion");
            if(version.empty()) {
                version = ver.queryValue("ProductVersion");
            }
            std::string prodictName = ver.queryValue("ProductName");
            if(prodictName == "Microsoft® Windows® Operating System") {
                prodictName = "";
            }
            auto desc = ver.queryValue("FileDescription");
            if(!desc.empty()) ss << " desc=\"" << desc << "\"";
            if(!prodictName.empty()) ss << " product_name=\"" << prodictName << "\"";
            if(!version.empty()) {
                ss << " ver=\"" << version << "\"";
                hasId = true;  // here we can identify dll
            }
        }
        if(!hasId) {
            // try find pdb guid or calc sha1 hashsum
            MyCodeViewInfo cvi((HMODULE) mod->base);
            if(cvi.find()) {
                GUID &guid = cvi.codeView->pdb70.guid;
                DWORD age = cvi.codeView->pdb70.age;
                ss << " codeview=\"";
                ss << fmtHex32(guid.Data1);
                ss << fmtHex16(guid.Data2);
                ss << fmtHex16(guid.Data3);
                for (int i = 0; i < 8; ++i) ss << fmtHex8(guid.Data4[i]);
                ss << fmtHex(age);
                ss << "\"";
                hasId = true;  // here we can identify dll
            }
        }
        if(!hasId) {
            // try calc sha1 hashsum
            wchar_t dllPath[MAX_PATH];
            DWORD len = GetModuleFileNameW((HMODULE) mod->base, dllPath, MAX_PATH);
            std::string buffer;
            {

                std::ifstream file(dllPath, std::ios::binary | std::ios::ate);
                std::streamsize size = file.tellg();
                file.seekg(0, std::ios::beg);
                buffer.resize(size);
                if (!file.read(buffer.data(), size)) buffer.clear();
            }
            if(!buffer.empty()) {
                SHA1 checksum;
                checksum.update(buffer);
                std::string hash = checksum.final();
                ss << " sha1=\"";
                ss << hash;
                ss << "\"";
                hasId = true;
            }
        }
        ss << std::endl;
    }
}

void formatConfig(std::stringstream &ss) {
    ss << "config:\n";
    ss << flame_config::shortDump();
}

void buildFileName(FILETIME &timestamp, const char *namePart, char *reportFile, size_t bufCount) {
    char curDir[MAX_PATH];
    GetCurrentDirectoryA(MAX_PATH, curDir);
    strcat(curDir, "\\flame\\");
    strcat(curDir, namePart);

    if (!CreateDirectory(curDir, NULL) && GetLastError() != ERROR_ALREADY_EXISTS) {
        initConsole();
        std::cerr << "unable to create " << curDir << " directory" << std::endl;
        std::cout << '\n' << "Press a key to continue...";
        std::cin.get();
        exit(-1);
        return;
    }

    SYSTEMTIME stime;
    FileTimeToSystemTime(&timestamp, &stime);
    snprintf(reportFile, bufCount, "%s\\Flame-%s-%02d%02d%02d.txt", curDir, namePart,
             stime.wYear % 100, stime.wMonth, stime.wDay);
    for (int suffix = 1; fs::exists(reportFile); suffix++) {
        snprintf(reportFile, bufCount, "%s\\Flame-%s-%02d%02d%02d[%d].txt", curDir, namePart,
                 stime.wYear % 100, stime.wMonth, stime.wDay, suffix);
    }
}

bool isGameFrame(StackFrame &frame) {
    if(frame.libBase == bughunter::dkii_base) return true;
    if(bughunter::weanetr && frame.libBase == bughunter::weanetr->base) return true;
    if(bughunter::qmixer && frame.libBase == bughunter::qmixer->base) return true;
    return false;
}

LPTOP_LEVEL_EXCEPTION_FILTER g_prev = nullptr;
LONG WINAPI TopLevelExceptionFilter(_In_ struct _EXCEPTION_POINTERS *ExceptionInfo) {
    std::vector<AppThread> states = collectAppThreadsExceptCurrent();

    // suspend all collected threads
    for(auto &ts : states) ts.suspend();

    std::stringstream ss;
    FILETIME timespamp;
    GetSystemTimeAsFileTime(&timespamp);
    formatHeader(ss, timespamp);

    ss << std::endl;
    ss << "caught exception " << fmtHex32(ExceptionInfo->ExceptionRecord->ExceptionCode) << " at " << fmtHex32(ExceptionInfo->ExceptionRecord->ExceptionAddress) << std::endl;
    ss << "tid: " << GetCurrentThreadId() << "(0x" << fmtHex(GetCurrentThreadId()) << ")" << std::endl;
    ss << "exe base: " << fmtHex32(bughunter::dkii_base) << std::endl;
    auto &R = *ExceptionInfo->ContextRecord;
    ss << "eax=" << fmtHex32(R.Eax) << " ebx=" << fmtHex32(R.Ebx) << " ecx=" << fmtHex32(R.Ecx) << " edx=" << fmtHex32(R.Edx) << std::endl;
    ss << "esi=" << fmtHex32(R.Esi) << " edi=" << fmtHex32(R.Edi) << " esp=" << fmtHex32(R.Esp) << " ebp=" << fmtHex32(R.Ebp) << std::endl;
    ss << "eip=" << fmtHex32(R.Eip) << " efl=" << fmtHex32(R.EFlags) << std::endl;

    LoadedModules modules;
    modules.update();
    {  // current thread info
        WalkerError err;

        StackLimits limits;
        limits.resolve();

        std::deque<StackFrame> frames;
        StackWalker sw(modules, limits, R, err);
//        onlyImportantFrames(sw.begin(), frames, err);
        for(auto &frame : sw) frames.push_back(frame);

        ss << std::endl;
        ss << "thread " << GetCurrentThreadId() << " stack=" << fmtHex32(limits.low) << "-" << fmtHex32(limits.high) << std::endl;
        for(auto &fr : frames) {
            ss << fr << std::endl;
        }
        if(err) {
            ss << "[StackWalker ERROR]: " << err.str() << std::endl;
        }
    }
    for(auto &ts : states) {
        WalkerError err;
        StackLimits limits;
        if(!limits.resolve(ts.hThread)) {
            DWORD lastError = GetLastError();
            ss << std::endl;
            ss << "thread " << ts.tid << " [error]: GetThreadStackLimits failed " << fmtHex32(lastError) << std::endl;
            continue;
        }

        CONTEXT ctx;
        ZeroMemory(&ctx, sizeof(ctx));
        ctx.ContextFlags = CONTEXT_FULL;
        if(!GetThreadContext(ts.hThread, &ctx)) {
            DWORD lastError = GetLastError();
            ss << "thread " << ts.tid << " stack=" << fmtHex32(limits.low) << "-" << fmtHex32(limits.high) << std::endl;
            ss << "[StackWalker ERROR]: GetThreadContext failed " << fmtHex32(lastError) << std::endl;
            continue;
        }

        std::deque<StackFrame> frames;
        StackWalker sw(modules, limits, ctx, err);
        for(auto &frame : sw) frames.push_back(frame);

        bool hasGameFrame = false;
        for(auto &frame : frames) {
            if(!isGameFrame(frame)) continue;
            hasGameFrame = true;
            break;
        }
        if(!hasGameFrame) continue;

        ss << std::endl;
        ss << "thread " << ts.tid << " stack=" << fmtHex32(limits.low) << "-" << fmtHex32(limits.high) << std::endl;
        for(auto &fr : frames) {
            ss << fr << std::endl;
        }
        if(err) {
            ss << "[StackWalker ERROR]: " << err.str() << std::endl;
        }
    }

    // resume all suspended threads
    for(auto &ts : states) ts.resume();

    ss << std::endl;
    formatModules(ss, modules);
    ss << std::endl;
    formatConfig(ss);

    std::string text = ss.str();

    char reportFile[MAX_PATH];
    buildFileName(timespamp, "CrashInfo", reportFile, MAX_PATH);
    {
        std::ofstream os(reportFile);
        os << text;
    }
    std::cerr << text << std::endl;

    SetEnvironmentVariableA("FLAME_CRASH_FILE", reportFile);

    char exeFile[MAX_PATH];
    GetModuleFileNameA(NULL, exeFile, MAX_PATH);
    ShellExecuteA(NULL, "open", exeFile, "-display_crash_message", NULL, SW_SHOWDEFAULT);

    for(auto &ts : states) ts.resume();
    return g_prev(ExceptionInfo);
}

struct PausedThread {
    HANDLE hThread;
    explicit PausedThread(HANDLE hThread) : hThread(hThread) {
        SuspendThread(hThread);
    }
    ~PausedThread() {
        ResumeThread(hThread);
    }
};

void traceThread(HANDLE hThread, std::vector<StackFrame> &frames, WalkerError &err, LoadedModules *modules = NULL) {
    CONTEXT ctx;
    ZeroMemory(&ctx, sizeof(ctx));
    ctx.ContextFlags = CONTEXT_FULL;

    StackLimits limits;
    if(!limits.resolve(hThread)) {
        DWORD lastError = GetLastError();
        std::stringstream ss;
        ss << "GetThreadStackLimits failed " << fmtHex32(lastError) << std::endl;
        StackWalkerState::setError(err, ss.str());
        return;
    }
    PausedThread pauseGuard(hThread);
    if(!GetThreadContext(hThread, &ctx)) {
        DWORD lastError = GetLastError();
        std::stringstream ss;
        ss << "GetThreadContext failed " << fmtHex32(lastError) << std::endl;
        StackWalkerState::setError(err, ss.str());
        return;
    }
    LoadedModules localModules;
    if(!modules) {
        localModules.update();
        modules = &localModules;
    }
    StackWalker sw(*modules, limits, ctx, err);
    for(auto &frame : sw) frames.push_back(frame);
}

void dumpCurrentStack(int numFrames) {
    std::vector<StackFrame> frames;
    WalkerError err;
    traceCurrentStack(frames, err);
    for(auto &fr : frames) {
        std::cout << fr << std::endl;
        if(numFrames-- == 0) break;
    }
    if(err) {
        std::cout << "[StackWalker ERROR]: " << err.str() << std::endl;
    }
}
void traceCurrentStack(std::vector<StackFrame> &frames, WalkerError &err) {
    CONTEXT ctx;
    ZeroMemory(&ctx, sizeof(ctx));
    ctx.ContextFlags = CONTEXT_FULL;
    RtlCaptureContext(&ctx);

    StackLimits limits;
    limits.resolve();

    LoadedModules modules;
    modules.update();

    StackWalker sw(modules, limits, ctx, err);
    for(auto &frame : sw) frames.push_back(frame);
}

void displayCrashMessage() {
    gui::initDPI();
    std::stringstream ss;
    ss << "The Dungeon Keeper 2 process has crashed" << std::endl;
    ss << "But! Flame has collected crash info in the text file" << std::endl;

    char exeDir[MAX_PATH];
    GetCurrentDirectoryA(MAX_PATH, exeDir);
    char crashFile[MAX_PATH];
    if(GetEnvironmentVariableA("FLAME_CRASH_FILE", crashFile, MAX_PATH) != 0) {
        ss << "CrashInfo location:" << std::endl;
        ss << crashFile << std::endl;
    } else {
        crashFile[0] = '\0';
        ss << "CrashInfos location:" << std::endl;
        ss << exeDir << "\\flame\\CrashInfo\\Flame-CrashInfo-*.txt" << std::endl;
    }
    ss << std::endl;
    ss << "ok - open directory and exit" << std::endl;
    ss << "cancel - exit" << std::endl;
    std::string text = ss.str();
    int res = MessageBoxA(NULL, text.c_str(), "Flame bug hunter", MB_OKCANCEL | MB_ICONERROR);
    if(res == IDOK) {
        // try open directory and select file
        if(crashFile[0]) {
            ITEMIDLIST *pidl = ILCreateFromPath(crashFile);
            if(pidl) {
                SHOpenFolderAndSelectItems(pidl, 0, NULL, 0);
                ILFree(pidl);
                return;
            }
        }
        ShellExecuteA(NULL, "open", exeDir, NULL, NULL, SW_SHOWDEFAULT);
    }
}

void bug_hunter::displayCrash() {
    if(wcsstr(GetCommandLineW(), L" -display_crash_message") != NULL) {
        displayCrashMessage();
        ExitProcess(0);
    }
}
void bug_hunter::init() {
    resolveLocs();
    parseFpomap(bughunter::dkii_fpomap_start, bughunter::dkii_fpomap);
    parseFpomap(bughunter::flame_fpomap_start, bughunter::flame_fpomap);
    g_prev = SetUnhandledExceptionFilter(TopLevelExceptionFilter);
}

void bug_hunter::collectStackInfo() {
    std::stringstream ss;
    FILETIME timespamp;
    GetSystemTimeAsFileTime(&timespamp);
    formatHeader(ss, timespamp);

    LoadedModules modules;
    modules.update();

    std::vector<AppThread> states = collectAppThreadsExceptCurrent();
    for(auto &ts : states) {
        WalkerError err;
        std::vector<StackFrame> frames;
        traceThread(ts.hThread, frames, err, &modules);

        ss << std::endl;

        StackLimits limits;
        if (!limits.resolve(ts.hThread)) {
            DWORD lastError = GetLastError();
            ss << std::endl;
            ss << "thread " << ts.tid << " [error]: GetThreadStackLimits failed " << fmtHex32(lastError) << std::endl;
            continue;
        }
        ss << "thread " << ts.tid << " stack=" << fmtHex32(limits.low) << "-" << fmtHex32(limits.high) << std::endl;
        for(auto &fr : frames) {
            ss << fr << std::endl;
        }
        if(err) {
            ss << "[StackWalker ERROR]: " << err.str() << std::endl;
        }
    }

    ss << std::endl;
    formatModules(ss, modules);
    ss << std::endl;
    formatConfig(ss);

    std::string text = ss.str();

    char reportFile[MAX_PATH];
    buildFileName(timespamp, "StackInfo", reportFile, MAX_PATH);
    {
        std::ofstream os(reportFile);
        os << text;
    }
}

