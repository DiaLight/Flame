//
// Created by DiaLight on 9/3/2025.
//

#include <Windows.h>
#include <algorithm>
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <map>
#include <memory>
#include <span>
#include <string>
#include <vector>

#include "compressapi.h"
#include "dependency_injection.h"

#include "Symbol.h"
#include "VaReloc.h"
#include "logging.h"


struct DecompressorDeleter {
    static void operator()(const DECOMPRESSOR_HANDLE handle) {
        CloseDecompressor(handle);
    }
};

std::vector<std::byte> decompress(
    const DWORD algorithm, const std::span<const std::byte> compressed) {
    std::unique_ptr<std::remove_pointer_t<DECOMPRESSOR_HANDLE>, DecompressorDeleter> decompressor {};
    if(!CreateDecompressor(algorithm, nullptr, std::out_ptr(decompressor))) {
        log_err("failed to CreateDecompressor");
        return {};
    }
    SIZE_T bufferSize {};
    if(!Decompress(
        decompressor.get(),
        compressed.data(),
        compressed.size(),
        nullptr,
        0,
        &bufferSize)) {
        DWORD lastError = GetLastError();
        if(lastError != ERROR_INSUFFICIENT_BUFFER) {
            log_err("failed to Decompress. lastError: %08X", lastError);
            return {};
        }
    }
    std::vector<std::byte> buffer;
    buffer.resize(bufferSize);
    SIZE_T actualSize {};
    if(!Decompress(
        decompressor.get(),
        compressed.data(),
        compressed.size(),
        buffer.data(),
        bufferSize,
        &actualSize)) {
        return {};
    }
    buffer.resize(actualSize);
    buffer.shrink_to_fit();
    return buffer;
}

#define IDR_RCDATA1 101

std::map<std::string, std::vector<std::byte>> unpackResources(HMODULE mod) {
    std::vector<std::byte> packedResources;
    HRSRC myResource = ::FindResource(mod, MAKEINTRESOURCE(IDR_RCDATA1), RT_RCDATA);
    if(HGLOBAL myResourceData = ::LoadResource(mod, myResource)) {
        DWORD size = SizeofResource(mod, myResource);
        if(void *data = ::LockResource(myResourceData)) {
//            log_inf("compressed %d", size);
            packedResources = decompress(COMPRESS_ALGORITHM_LZMS, std::span{(std::byte *) data, size});
//            log_inf("decompressed %d", packedResources.size());
            UnlockResource(data);
        }
        FreeResource(myResourceData);
    }
    if(packedResources.empty()) {
        log_err("Failed to decompress Flame resources");
        return {};
    }
    std::map<std::string, std::vector<std::byte>> resources;
    {
        auto *p = (std::byte *) packedResources.data();
        auto *e = p + packedResources.size();
        while(p < e) {
            uint16_t keySize = *(uint16_t *) p; p += sizeof(uint16_t);
            std::string key((const char *) p, keySize);
            p += keySize;
            uint32_t valSize = *(uint32_t *) p; p += sizeof(uint32_t);
            std::vector<std::byte> val;
            val.resize(valSize);
            memcpy(val.data(), p, valSize);
            p += valSize;
            resources.emplace(std::make_pair(key, std::move(val)));
        }
    }
    return std::move(resources);
}

std::vector<std::byte> pop(std::map<std::string, std::vector<std::byte>> &resources, const std::string &key) {
    if(const auto &it = resources.find(key); it != resources.end()) {
        return std::move(it->second);
    }
    log_err("[-] key %s is not found in resources", key.c_str());
    return {};
}

std::string popString(std::map<std::string, std::vector<std::byte>> &resources, const std::string &key) {
    std::vector<std::byte> map = pop(resources, key);
    if(map.empty()) return {};
    std::string s;
    s.assign((char *) map.data(), map.size());  // copy
    return std::move(s);
}

template<typename T>
bool parseResource(std::map<std::string, std::vector<std::byte>> &resources, const std::string &key,
                   void (*parse)(std::istream &is, std::vector<T> &vec), std::vector<T> &vec) {
    std::string s = popString(resources, key);
    if(s.empty()) {
        log_err("[-] Failed to read %s", key.c_str());
        return false;
    }
    std::istringstream is(s);
    parse(is, vec);
    if(!is.eof() || is.fail()) {
        log_err("[-] Failed to parse %s. eof=%d, fail=%d", key.c_str(), is.eof(), is.fail());
        return false;
    }
    if(vec.empty()) {
        log_err("[-] Parsed empty vec %s. eof=%d, fail=%d", key.c_str(), is.eof(), is.fail());
        return false;
    }
    return true;
}

struct Resources {

    std::vector<Symbol> dkiiSyms;
    std::vector<VaReloc> dkiiRelocs;
    std::vector<std::byte> dkiiFpo;
    std::vector<std::byte> flameFpo;
    std::string version;

    bool load(HMODULE mod) {
        std::map<std::string, std::vector<std::byte>> resources = unpackResources(mod);
//        for(auto &e : resources) {
//            log_info("%s %d", e.first.c_str(), e.second.size());
//        }
        if(!parseResource(resources, "symmap", parseSymbols, dkiiSyms)) return false;
        if(!parseResource(resources, "refmap", parseRelocs, dkiiRelocs)) return false;
        dkiiFpo = pop(resources, "dkii_fpo");
        if(dkiiFpo.empty()) {
            log_err("[-] Failed to read dkii_fpo");
            return false;
        }
        flameFpo = pop(resources, "flame_fpo");
        if(flameFpo.empty()) {
            log_err("[-] Failed to read flame_fpo");
            return false;
        }

        version = popString(resources, "version");
        if(version.empty()) {
            log_err("[-] Failed to read version");
            return false;
        }
        return true;
    }

} g_resources;

void *findText(HMODULE mod, size_t &size) {
    auto *nt = (IMAGE_NT_HEADERS *) (((IMAGE_DOS_HEADER *) mod)->e_lfanew + (std::byte *) mod);
    for (auto *sec = IMAGE_FIRST_SECTION(nt), *end = sec + nt->FileHeader.NumberOfSections; sec < end; ++sec) {
        if(strncmp((char *) sec->Name, ".text", 8) == 0) {
            size = sec->Misc.VirtualSize;
            return sec->VirtualAddress + (std::byte *) mod;
        }
    }
    return nullptr;
}
bool collectImportsExports(HMODULE flame, std::map<std::string, void *> &flameImports, std::map<std::string, void *> &flameExports) {
    auto *nt = (IMAGE_NT_HEADERS *) (((IMAGE_DOS_HEADER *) flame)->e_lfanew + (std::byte *) flame);
    auto *exp = (IMAGE_EXPORT_DIRECTORY *)(nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress + (std::byte *) flame);
    auto *names = (DWORD *) (exp->AddressOfNames + (std::byte *) flame);
    auto *ordinals = (WORD *) (exp->AddressOfNameOrdinals + (std::byte *) flame);
    auto *funs = (DWORD *) (exp->AddressOfFunctions + (std::byte *) flame);
    for(
        auto *imp = (IMAGE_IMPORT_DESCRIPTOR *)(nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress + (std::byte *) flame);
        imp->FirstThunk;
        imp++
    ) {
        auto *name = (char *) (imp->Name + (std::byte *) flame);
        if(strcmp(name, "DKII.dll") != 0) continue;
        for(
            auto *thunk = (IMAGE_THUNK_DATA *) (imp->FirstThunk + (std::byte *) flame),
                 *othunk = (IMAGE_THUNK_DATA *) (imp->OriginalFirstThunk + (std::byte *) flame);
            thunk->u1.AddressOfData;
            thunk++, othunk++
        ) {
            if(othunk->u1.AddressOfData & IMAGE_ORDINAL_FLAG) {
                log_err("[-] Flame has ordinal import");
                return false;
            }
            auto *byName = (IMAGE_IMPORT_BY_NAME *) (othunk->u1.AddressOfData + (std::byte *) flame);
            auto *ptr = &thunk->u1.Function;
            flameImports.insert(std::make_pair(byName->Name, ptr));
        }
    }
    for (int i = 0; i < exp->NumberOfNames; ++i) {
        auto *name = (char *) (names[i] + (std::byte *) flame);
        void *fun = (funs[ordinals[i]] + (std::byte *) flame);
        flameExports.insert(std::make_pair(name, fun));
    }
    if(flameImports.empty()) {
        log_err("[-] Flame has no imports");
        return false;
    }
    if(flameExports.empty()) {
        log_err("[-] Flame has no exports");
        return false;
    }
    return true;
}

bool connectFlameAndDkii(
    const std::vector<Symbol> &dkiiSyms,
    const std::vector<VaReloc> &dkiiRelocs,
    const std::map<std::string, void *> &flameImports,
    const std::map<std::string, void *> &flameExports
) {
    for(auto &s : dkiiSyms) {
        if(s.replace) {
            if(const auto &it = flameExports.find(s.name); it != flameExports.end()) {
                auto *fptr = it->second;
//                log_inf("%p %s", fptr, s.name.c_str());
                std::vector<const VaReloc*> refs;
                for (const auto& r : dkiiRelocs) {
                    if(r.ty == VaReloc::RT_NOT_VA32) continue;
                    if(r.to != s.va) continue;
                    refs.push_back(&r);
                    DWORD p;
                    VirtualProtect((LPVOID) r.from, 4, PAGE_EXECUTE_READWRITE, &p);
                    switch(r.ty) {
                    case VaReloc::RT_VA32: *(uint32_t *) r.from = (uint32_t) fptr; break;
                    case VaReloc::RT_REL32: *(uint32_t *) r.from = (uint32_t) fptr - (r.from + 4); break;
                    }
                    VirtualProtect((LPVOID) r.from, 4, p, &p);
                }
                if(refs.empty()) {
                    log_err("[-] nothing to replace for symbol %s in DKII", s.name.c_str());
                }
            } else {
                log_err("[-] replace sym %s is not found in Flame", s.name.c_str());
                return false;
            }
        } else {  // !s.replace
            if(const auto &it = flameImports.find(s.name); it != flameImports.end()) {
                auto *fptr = it->second;
                DWORD p;
                VirtualProtect((LPVOID) fptr, 4, PAGE_EXECUTE_READWRITE, &p);
                *(uint32_t *) fptr = (uint32_t) s.va;
                VirtualProtect((LPVOID) fptr, 4, p, &p);
            }
        }
    }
    return true;
}

bool patchMain(HMODULE flame) {
    HMODULE dkii = GetModuleHandleA(NULL);
    if(dkii == NULL) {
        DWORD lastError = GetLastError();
        log_err("[-] Failed to find dkii %08X", lastError);
        return false;
    }

    HMODULE dkiiStub = LoadLibraryA("DKII.dll");
    if(dkiiStub == NULL) {
        DWORD lastError = GetLastError();
        log_err("[-] Failed to load dkii stub %08X", lastError);
        return false;
    }

    std::map<std::string, void *> flameImports;
    std::map<std::string, void *> flameExports;
    if(!collectImportsExports(flame, flameImports, flameExports)) return false;

    if(!connectFlameAndDkii(g_resources.dkiiSyms, g_resources.dkiiRelocs, flameImports, flameExports)) return false;

    if(auto it = flameExports.find("_dkii_fpomap_start"); it != flameExports.end()) {
        *(void **) it->second = g_resources.dkiiFpo.data();
    } else {
        log_err("[-] Failed to patch _dkii_fpomap_start");
        return false;
    }

    if(auto it = flameExports.find("_flame_fpomap_start"); it != flameExports.end()) {
        *(void **) it->second = g_resources.flameFpo.data();
    } else {
        log_err("[-] Failed to patch _flame_fpomap_start");
        return false;
    }

    if(auto it = flameExports.find("Flame_version"); it != flameExports.end()) {
        auto pos = g_resources.version.find("build");
        if(pos != -1) {
            g_resources.version = " V" + g_resources.version.substr(0, pos - 1) + "\n " + g_resources.version.substr(pos);
        }
        DWORD p;
        VirtualProtect((LPVOID) it->second, 64, PAGE_EXECUTE_READWRITE, &p);
        strncpy_s((char *) it->second, 64, g_resources.version.data(), 63);
        VirtualProtect((LPVOID) it->second, 64, p, &p);
    } else {
        log_err("[-] Failed to patch Flame_version");
        return false;
    }

    size_t size;
    if(auto *text = findText(dkii, size)) {
        if(auto it = flameExports.find("_dkii_text_start"); it != flameExports.end()) {
            *(void **) it->second = text;
        } else {
            log_err("[-] Failed to patch _dkii_text_start");
            return false;
        }
        if(auto it = flameExports.find("_dkii_text_end"); it != flameExports.end()) {
            *(void **) it->second = (std::byte *) text + size;
        } else {
            log_err("[-] Failed to patch _dkii_text_end");
            return false;
        }
    } else {
        log_err("[-] Failed to find dkii .text");
        return false;
    }
    if(auto it = flameExports.find("_flame_base"); it != flameExports.end()) {
        *(void **) it->second = flame;
    } else {
        log_err("[-] Failed to patch _flame_base");
        return false;
    }
    if(auto *text = findText(flame, size)) {
        if(auto it = flameExports.find("_flame_text_start"); it != flameExports.end()) {
            *(void **) it->second = text;
        } else {
            log_err("[-] Failed to patch _flame_text_start");
            return false;
        }
        if(auto it = flameExports.find("_flame_text_end"); it != flameExports.end()) {
            *(void **) it->second = (std::byte *) text + size;
        } else {
            log_err("[-] Failed to patch _flame_text_end");
            return false;
        }
    } else {
        log_err("[-] Failed to find flame .text");
        return false;
    }
    return true;
}

typedef bool (*CallbackProc)(HMODULE base);
HMODULE HookedLoadLibraryA(_In_ LPCSTR lpLibFileName, CallbackProc onMapped) {
    #ifndef _NTMMAPI_H
    typedef enum _SECTION_INHERIT {
        ViewShare = 1,
        ViewUnmap = 2
    } SECTION_INHERIT;
    #endif
    typedef NTSTATUS (WINAPI *NtMapViewOfSectionProc)(
        _In_         HANDLE           SectionHandle,
        _In_         HANDLE           ProcessHandle,
        _Inout_      PVOID            *BaseAddress,
        _In_         ULONG_PTR        ZeroBits,
        _In_         SIZE_T           CommitSize,
        _Inout_opt_  PLARGE_INTEGER   SectionOffset,
        _Inout_      PSIZE_T          ViewSize,
        _In_         SECTION_INHERIT  InheritDisposition,
        _In_         ULONG            AllocationType,
        _In_         ULONG            Win32Protect
    );

    auto pNtMapViewOfSection = (NtMapViewOfSectionProc) GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtMapViewOfSection");
    if(!pNtMapViewOfSection) {
        log_err("[-] Failed to find NtMapViewOfSection entry");
        return nullptr;
    }

    // B8 ?? ?? ?? ??    mov eax, <imm32>
    if(*(uint8_t *) pNtMapViewOfSection != 0xB8) {
        log_err("[-] Failed to find iat entry");
        return nullptr;
    }

    static struct {
        NtMapViewOfSectionProc pNtMapViewOfSection;
        uint8_t savedCode[5];
        CallbackProc onMapped;
        bool hookResult;

        void save() {
            memcpy(savedCode, pNtMapViewOfSection, 5);
        }
        void patch(NtMapViewOfSectionProc fun) const {
            DWORD p;
            VirtualProtect((LPVOID) pNtMapViewOfSection, 5, PAGE_EXECUTE_READWRITE, &p);
            auto *pos = (uint8_t *) pNtMapViewOfSection;
            *pos++ = 0xE9;  // jmp <rel32>
            *(uint32_t *) pos = (uint8_t *) fun - (pos + 4);  // rel32 = dst - src
            VirtualProtect((LPVOID) pNtMapViewOfSection, 5, p, &p);
        }
        void restore() {
            DWORD p;
            VirtualProtect((LPVOID) pNtMapViewOfSection, 5, PAGE_EXECUTE_READWRITE, &p);
            memcpy(pNtMapViewOfSection, savedCode, 5);
            VirtualProtect((LPVOID) pNtMapViewOfSection, 5, p, &p);
        }
    } hookedFun {
        .pNtMapViewOfSection = pNtMapViewOfSection,
        .onMapped = onMapped,
    };
    hookedFun.save();

    NtMapViewOfSectionProc NtMapViewOfSectionReplace = [](
        auto SectionHandle, auto ProcessHandle, auto *BaseAddress,
        auto ZeroBits, auto CommitSize, auto SectionOffset,
        auto ViewSize, auto InheritDisposition, auto AllocationType,
        auto Win32Protect
    ) -> NTSTATUS {
        // restore code
        hookedFun.restore();
        NTSTATUS status = hookedFun.pNtMapViewOfSection(SectionHandle, ProcessHandle, BaseAddress, ZeroBits, CommitSize, SectionOffset, ViewSize, InheritDisposition, AllocationType, Win32Protect);
        if(SUCCEEDED(status)) hookedFun.hookResult = hookedFun.onMapped((HMODULE) *BaseAddress);
        return status;
    };
    hookedFun.patch(NtMapViewOfSectionReplace);
    HMODULE mod = LoadLibraryA(lpLibFileName);
    hookedFun.restore();
    if(!hookedFun.hookResult) return nullptr;
    return mod;
}

typedef BOOL (WINAPI *DllEntryPointProc)(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpReserved);
struct entryHook_t {
    DllEntryPointProc pDllEntryPoint;
    bool called;
    CallbackProc onEntry;
    bool hookResult;

    bool hook(HMODULE mod, CallbackProc onEntry);
} g_entryHook {.called = false, .hookResult = false};

BOOL DllEntryPointReplace(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpReserved) {
    if(!g_entryHook.called) {
        g_entryHook.called = true;
        g_entryHook.hookResult = g_entryHook.onEntry(hinstDLL);
    }
    return g_entryHook.pDllEntryPoint(hinstDLL, fdwReason, lpReserved);
};

bool entryHook_t::hook(HMODULE mod, CallbackProc onEntry) {
    this->onEntry = onEntry;
    auto *nt = (IMAGE_NT_HEADERS *) (((IMAGE_DOS_HEADER *) mod)->e_lfanew + (std::byte *) mod);
    auto *entryPoint = nt->OptionalHeader.AddressOfEntryPoint + (uint8_t *) mod;
    // follow jump if any
    {
        // E9 ?? ?? ?? ??    jmp <rel32>
        auto *pos = (uint8_t *) entryPoint;
        if(*pos++ == 0xE9) entryPoint = (*(uint32_t *) pos) + (pos + 4);
    }
    pDllEntryPoint = (DllEntryPointProc) entryPoint;
    {
        // at 32bit system RVA == 32bit value, void_p == 32bit value. And! ntdll does not check where AddressOfEntryPoint point
        DWORD p;
        VirtualProtect((LPVOID) &nt->OptionalHeader.AddressOfEntryPoint, 4, PAGE_EXECUTE_READWRITE, &p);
        nt->OptionalHeader.AddressOfEntryPoint = (uint8_t *) DllEntryPointReplace - (uint8_t *) mod;
        VirtualProtect((LPVOID) &nt->OptionalHeader.AddressOfEntryPoint, 4, p, &p);
    }
    return true;
}


bool flameLoaderMain(HMODULE loader) {
    if(!g_resources.load(loader)) {
        log_err("[-] Failed to load resources");
        return false;
    }
    log_inf("Flame resources loaded v%s", g_resources.version.c_str());

    // I need to patch Flame.dll before dll entry call. Only way I see for now is to hook NtMapViewOfSection while calling LoadLibraryA
    SetDllDirectoryA("flame");
    HMODULE flame = HookedLoadLibraryA("Flame.dll", [](auto flame) -> bool {
        // Ok, I have a mapped dll and the entry point still hasn't been called
        // I still cant replace links because ntdll hasn't done the relocations yet
        // Relocate process will erase my links if I replace them now
        // I need to patch entry point and continue at the entry point begin
        return g_entryHook.hook(flame, [](auto flame) -> bool {
            // Finally! Relocations already applied and entry is not called in both PEs
            // we can now link Flame.dll and DKII-DX.exe together
            return patchMain(flame);
        });
    });
    SetDllDirectoryA(NULL);

    if(flame == NULL) {
        DWORD lastError = GetLastError();
        log_err("[-] Failed to load flame dll. lastError: %08X", lastError);
        return false;
    }
    if(!g_entryHook.hookResult) {
        log_err("[-] Entry hook failed");
    }
    return true;
}


BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved) {
    switch(fdwReason) {
    case DLL_PROCESS_ATTACH:
        if (!CreateDirectory("flame", NULL) && GetLastError() != ERROR_ALREADY_EXISTS) {
            MessageBoxA(NULL, "Failed to create flame directory", "Flame loader error", MB_OK);
            return false;
        }
        loader::log::init();
        initDependency();
        if(!flameLoaderMain(hinstDLL)) {
            fflush(stdout);
            MessageBoxA(NULL, "Load Flame failed", "Flame loader error", MB_OK);
            return FALSE;
        }
        log_inf("Flame loader succeeded");
        return TRUE;
        break;
    case DLL_THREAD_ATTACH:
        // Do thread-specific initialization.
        break;
    case DLL_THREAD_DETACH:
        // Do thread-specific cleanup.
        break;
    case DLL_PROCESS_DETACH:
        if (lpvReserved != nullptr) {
            break; // do not do cleanup if process termination scenario
        }
        // Perform any necessary cleanup.
        break;
    }
    return TRUE;
}
