//
// Created by DiaLight on 21.09.2024.
//

#ifndef FLAME_LOADEDMODULES_H
#define FLAME_LOADEDMODULES_H

#include <Windows.h>
#include <string>
#include <vector>
#include <memory>

struct ModuleExport {
    ULONG_PTR addr;
    std::string name;

    ModuleExport(ULONG_PTR addr, const char *name) {
        this->addr = addr;
        this->name.append(name);
    }
};

struct CodeRange {
    ULONG_PTR base;
    ULONG_PTR end;
    std::string name;

    [[nodiscard]] bool contains(ULONG_PTR addr) const;

};

struct LoadedModule {
    std::string name;
    ULONG_PTR base;
    ULONG_PTR end;
    std::vector<std::shared_ptr<ModuleExport>> exports;
    std::vector<CodeRange> codeSections;

    LoadedModule(PCSTR ModuleName, ULONG ModuleBase, ULONG ModuleSize);

    [[nodiscard]] bool contains(ULONG_PTR addr) const;
    [[nodiscard]] bool codeContains(ULONG_PTR addr) const;

    std::vector<std::shared_ptr<ModuleExport>>::iterator _find_gt(ULONG_PTR addr);
    std::vector<std::shared_ptr<ModuleExport>>::iterator _find_le(ULONG_PTR addr);
    ModuleExport *find_export_le(ULONG_PTR addr);

    bool _visitExport(ULONG_PTR funAddr, const char *name);
    bool _findExports();
};

class LoadedModules {
    using iterator = std::vector<std::shared_ptr<LoadedModule>>::iterator;
    std::vector<std::shared_ptr<LoadedModule>> modules;
public:

    bool _visitModule(PCSTR ModuleName, ULONG ModuleBase, ULONG ModuleSize);
    void update();

    std::vector<std::shared_ptr<LoadedModule>>::iterator _find_gt(ULONG_PTR addr);
    std::vector<std::shared_ptr<LoadedModule>>::iterator _find_ge(ULONG_PTR addr);
    std::vector<std::shared_ptr<LoadedModule>>::iterator _find_lt(ULONG_PTR addr);
    std::vector<std::shared_ptr<LoadedModule>>::iterator _find_le(ULONG_PTR addr);
    LoadedModule *find(ULONG_PTR addr);
    ULONG_PTR findBaseThreadInitThunk();

    iterator begin() { return modules.begin(); }
    iterator end() { return modules.end(); }

private:
    static BOOL CALLBACK enumerateModulesCallback(
            _In_ PCSTR ModuleName,
            _In_ ULONG ModuleBase,
            _In_ ULONG ModuleSize,
            _In_opt_ PVOID UserContext
    );

};


#endif //FLAME_LOADEDMODULES_H
