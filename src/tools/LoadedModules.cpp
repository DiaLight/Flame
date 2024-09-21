//
// Created by DiaLight on 21.09.2024.
//

#include "LoadedModules.h"
#include <ImageHlp.h>


LoadedModule::LoadedModule(PCSTR ModuleName, ULONG ModuleBase, ULONG ModuleSize) {
    const char *name = strrchr(ModuleName, '/');
    if (name == nullptr) name = strrchr(ModuleName, '\\');
    if (name == nullptr) name = ModuleName;
    else name = name + 1;
    this->name.append(name);
    this->base = ModuleBase;
    this->size = ModuleSize;
}

bool LoadedModule::contains(ULONG_PTR addr) const {
    return base <= addr && addr < (base + size);
}

std::vector<std::shared_ptr<ModuleExport>>::iterator LoadedModule::_find_gt(ULONG_PTR addr) {
    return std::upper_bound(exports.begin(), exports.end(), addr,[](ULONG_PTR addr, std::shared_ptr<ModuleExport> &bl) {  // <
        return addr < bl->addr;
    });
}

std::vector<std::shared_ptr<ModuleExport>>::iterator LoadedModule::_find_le(ULONG_PTR addr) {
    auto it = _find_gt(addr);
    if (it == exports.begin()) return exports.end();
    return it - 1;
}

ModuleExport *LoadedModule::find_export_le(ULONG_PTR addr) {
    if (!_findExports()) return nullptr;
    auto it = _find_le(addr);
    if (it == exports.end()) return nullptr;
    return &**it;
}

bool LoadedModule::_visitExport(ULONG_PTR funAddr, const char *name) {
    auto value = std::make_shared<ModuleExport>(funAddr, name);
    auto it = _find_gt(funAddr);
    if (it != this->exports.begin() && (*(it - 1))->addr == funAddr) {
        *(it - 1) = value;
        return false;
    }
    if (it == this->exports.end()) {
        this->exports.push_back(value);
        return true;
    }
    this->exports.insert(it, value);
    return true;
}

bool LoadedModule::_findExports() {
    if (!exports.empty()) return true;
    auto *pHeader = (PIMAGE_DOS_HEADER) base;
    if (pHeader->e_magic != IMAGE_DOS_SIGNATURE) return false;
    auto *header = (PIMAGE_NT_HEADERS) ((BYTE *) base + ((PIMAGE_DOS_HEADER) base)->e_lfanew);
    if (header->Signature != IMAGE_NT_SIGNATURE) return false;
    if (header->OptionalHeader.NumberOfRvaAndSizes == 0) return false;
    PIMAGE_EXPORT_DIRECTORY exports = (PIMAGE_EXPORT_DIRECTORY) ((BYTE *) base + header->
            OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
    if (exports->AddressOfNames == 0) return false;
    DWORD *names = (DWORD *) ((int) base + exports->AddressOfNames);
    SHORT *nameOrdinals = (SHORT *) ((BYTE *) base + exports->AddressOfNameOrdinals);
    DWORD *functions = (DWORD *) ((BYTE *) base + exports->AddressOfFunctions);
    for (int i = 0; i < exports->NumberOfNames; i++) {
        const char *name = (const char *) ((BYTE *) base + names[i]);
        ULONG_PTR funAddr = (ULONG_PTR) ((BYTE *) base + functions[nameOrdinals[i]]);
        _visitExport(funAddr, name);
    }
//    std::sort(this->exports.begin(), this->exports.end(), [](ModuleExport &lhs, ModuleExport &rhs) {
//      return lhs.addr < rhs.addr;
//    });
    return true;
}

bool LoadedModules::_visitModule(PCSTR ModuleName, ULONG ModuleBase, ULONG ModuleSize) {
    auto it = _find_gt(ModuleBase);
    if (it != this->modules.begin() && (*(it - 1))->base == ModuleBase) {
//        *(it - 1) = value;
        return false;
    }
    if (it == this->modules.end()) {
        auto value = std::make_shared<LoadedModule>(ModuleName, ModuleBase, ModuleSize);
        this->modules.push_back(value);
        return true;
    }
    auto value = std::make_shared<LoadedModule>(ModuleName, ModuleBase, ModuleSize);
    this->modules.insert(it, value);
    return true;
}

void LoadedModules::update() {
    EnumerateLoadedModules(GetCurrentProcess(), enumerateModulesCallback, this);
}


std::vector<std::shared_ptr<LoadedModule>>::iterator LoadedModules::_find_gt(ULONG_PTR addr) {
    return std::upper_bound(modules.begin(), modules.end(), addr,
                            [](ULONG_PTR addr, std::shared_ptr<LoadedModule> &bl) {  // <
                                return addr < bl->base;
                            });
}

std::vector<std::shared_ptr<LoadedModule>>::iterator LoadedModules::_find_ge(ULONG_PTR addr) {
    return std::lower_bound(modules.begin(), modules.end(), addr,
                            [](std::shared_ptr<LoadedModule> &bl, ULONG_PTR addr) {  // <=
                                return bl->base < addr;
                            });
}

LoadedModule *LoadedModules::find(ULONG_PTR addr) {
    auto it = _find_ge(addr);
    if (it != modules.end()) {
        if ((*it)->contains(addr)) return &**it;
    }
    for (auto &mod: modules) {
        if (mod->contains(addr)) return &*mod;
    }
    return nullptr;
}

BOOL LoadedModules::enumerateModulesCallback(PCSTR ModuleName, ULONG ModuleBase, ULONG ModuleSize, PVOID UserContext) {
    auto *_this = (LoadedModules *) UserContext;
    _this->_visitModule(ModuleName, ModuleBase, ModuleSize);
    return TRUE;
}
