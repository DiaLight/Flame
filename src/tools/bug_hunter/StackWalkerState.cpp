//
// Created by DiaLight on 9/17/2025.
//

#include "StackWalkerState.h"
#include <sstream>
#include "MyFpoFun.h"
#include "tools/StackLimits.h"
#include "tools/bug_hunter.h"
#include <iostream>
#include <iomanip>

#define fmtHex32(val) std::hex << std::setw(8) << std::setfill('0') << std::uppercase << (val) << std::dec
#define fmtHex16(val) std::hex << std::setw(4) << std::setfill('0') << std::uppercase << (val) << std::dec
#define fmtHex8(val) std::hex << std::setw(2) << std::setfill('0') << std::uppercase << ((DWORD) val) << std::dec
#define fmtHex(val) std::hex << std::uppercase << (val) << std::dec


StackWalkerState::StackWalkerState(LoadedModules& modules, StackLimits& limits, CONTEXT& ctx, WalkerError& err) : modules(modules), limits(limits), ctx(ctx), err(err) {
    if(!err) {
        BaseThreadInitThunk = modules.findBaseThreadInitThunk();
    }
    isEbpValid = !bughunter::isDkiiCode(ctx.Eip);
}
bool StackWalkerState::isAnyCode(DWORD eip) {
    if(eip == 0) return false;
    if (auto *mod = modules.findByCodePtr(eip)) return true;
    return false;
}
bool StackWalkerState::stackEndCondition() const {
    if(BaseThreadInitThunk) {
        if(BaseThreadInitThunk < frame.eip && frame.eip < (BaseThreadInitThunk + 0x40)) return true;
    } else {
        if(frame.libName == "KERNEL32.DLL" && frame.symName == "BaseThreadInitThunk") return true;
    }
    if(frame.symAddr == bughunter::dkii_entry) return true;
    return false;
}

bool isDkiiFunctionStart(DWORD eip) {
    if(!bughunter::isDkiiCode(eip)) return false;
    DWORD rva = eip - bughunter::dkii_base;
    auto it = bughunter::find_le(bughunter::dkii_fpomap, rva);
    return it != bughunter::dkii_fpomap.end() && rva == it->rva;
}
bool isFlameFunctionStart(DWORD eip) {
    if(!bughunter::isFlameCode(eip)) return false;
    DWORD rva = eip - bughunter::flame_base;
    auto it = bughunter::find_le(bughunter::flame_fpomap, rva);
    return it != bughunter::flame_fpomap.end() && rva == it->rva;
}
bool isKnownFunctionStart(LoadedModule *mod, DWORD eip) {
    if(isDkiiFunctionStart(eip) || isFlameFunctionStart(eip)) return true;
    if(auto *exp = mod->find_export_le(eip)) if(exp->addr == eip) return true;
//    uint8_t prologue[] {0x55, 0x8B, 0xEC};
//    if(IsBadReadPtr((void *) eip, 5)) return false;
//    if(memcmp((void *) eip, prologue, sizeof(prologue)) == 0) return true;
//    if(memcmp((void *) (eip + 1), prologue, sizeof(prologue)) == 0) return true;
//    if(memcmp((void *) (eip + 2), prologue, sizeof(prologue)) == 0) return true;
    return false;
}

void StackWalkerState::tryStep() {
    std::vector<MyFpoFun>* fpos = nullptr;
    bool willEbpBeValid = true;
    bool isDkii = bughunter::isDkiiCode(ctx.Eip);
    bool isFlame = !isDkii && bughunter::isFlameCode(ctx.Eip);
    if(isDkii) {
        frame.libBase = bughunter::dkii_base;
        frame.libName = "DKII";
        fpos = &bughunter::dkii_fpomap;
        willEbpBeValid = false;
    } else if(isFlame) {
        frame.libBase = bughunter::flame_base;
        frame.libName = "Flame";
        fpos = &bughunter::flame_fpomap;
    } else if(bughunter::qmixer_base && bughunter::qmixer_base->codeContains(ctx.Eip)) {
        willEbpBeValid = false;
    }
//    std::cout << " ip=" << fmtHex32(ctx.Eip) << " sp=" << fmtHex32(ctx.Esp) << " bp=" << fmtHex32(ctx.Ebp) << std::endl;

    DWORD savedEbp = 0;
    DWORD* p = (DWORD*) ctx.Esp;
    if(fpos) {
        DWORD rva = ctx.Eip - frame.libBase;
        auto it = bughunter::find_le(*fpos, rva);
        if(it != fpos->end() && rva < it->rva_end) {
            MyFpoFun &fpo = *it;
            frame.symAddr = frame.libBase + fpo.rva;
            frame.symName = fpo.name;
            auto it2 = fpo.find_ge(rva - fpo.rva);
            if (it2 != fpo.spds.end()) {
                auto &spd = *it2;
                const char *ty = "";
                if(spd.ty == MST_Ida) {
                    ty = "ida";
                } else if(spd.ty == MST_Fpo) {
                    ty = "fpo";
                } else if(spd.ty == MST_Frm) {
                    ty = "frm";
                }
//                std::cout << " rva=" << fmtHex32(fpo.rva + spd.offs) << " spd=" << fmtHex(spd.spd) << " " << ty << " kind=" << fmtHex(spd.kind) << std::endl;
                if(spd.spd > 0) {
                }
                DWORD ebp = ctx.Esp + spd.spd - 16;
                if(ctx.Esp <= ebp && ebp < limits.high) {
                    p = (DWORD*) ebp;
                }
            }
        }
    } else {
        // identify module and symbol
        if(ctx.Eip) {
            if (auto *mod = modules.findByCodePtr(ctx.Eip)) {
                frame.libName = mod->name;
                frame.libBase = mod->base;
                if (auto *exp = mod->find_export_le(ctx.Eip)) {
                    frame.symName = exp->name;
                    frame.symAddr = exp->addr;
//                    printf("unwind lib %s:%s+%X\n", frame.libName.c_str(), frame.symName.c_str(), Eip - frame.symAddr);
                } else {
//                    printf("unwind lib %s+%X\n", frame.libName.c_str(), Eip - frame.libBase);
                }
            } else {
                std::stringstream ss;
                ss << "unwind lib unk eip=" << fmtHex32(ctx.Eip);
                err.set(ss.str());
                return;
            }
        }
    }
    if(!(ctx.Esp <= ctx.Ebp && ctx.Ebp < limits.high)) {
        isEbpValid = false;
    }
    if(isEbpValid) {
        p = (DWORD*) ctx.Ebp + 1;
    }
    DWORD frameBase = 0;
    for(; (DWORD) p <= (limits.high - 4); p++) {
        DWORD eipCand = p[0];
        if(willEbpBeValid) {
            DWORD ebpCand = p[-1];
            if((DWORD) p <= ebpCand && ebpCand <= (limits.high - 4)) {
                if(auto *mod = modules.findByCodePtr(eipCand)) {
                    if(isKnownFunctionStart(mod, eipCand)) continue;  // ignore fun ptr on stack
                    savedEbp = ebpCand;
                    frameBase = (DWORD) p;
                    break;
                }
            }
        } else {
            if(auto *mod = modules.findByCodePtr(eipCand)) {
                if(isKnownFunctionStart(mod, eipCand)) continue;  // ignore fun ptr on stack
                frameBase = (DWORD) p;
                break;
            }
        }
    }
    if(frameBase == 0) {
        std::stringstream ss;
        ss << "failed to resolve frameBase eip=" << fmtHex32(ctx.Eip) << " esp=" << fmtHex32(ctx.Esp) << " esp=" << fmtHex32(ctx.Ebp);
        err.set(ss.str());
        return;
    }
//    std::cout << " resolved frameBase=" << fmtHex32(frameBase) << " spd=" << fmtHex(frameBase - ctx.Esp) << std::endl;
    // save
    frame.eip = ctx.Eip;
    frame.esp = ctx.Esp;
    frame.ebp = frameBase;
    // step
    ctx.Ebp = savedEbp;
    ctx.Eip = *(DWORD *) frameBase;
    ctx.Esp = frameBase + 4;
    if(!(ctx.Esp <= ctx.Ebp && ctx.Ebp < limits.high)) {
        willEbpBeValid = false;
    }
    isEbpValid = willEbpBeValid;
}
void StackWalkerState::step() {
    if(err) return;
    if(stackEndCondition()) {
        // stack end
        ctx.Esp = limits.high;
        frame.reset();
        return;
    }
    frame.reset();
    if(!(limits.low <= ctx.Esp && ctx.Esp < (limits.high + 0x1000))) {
        std::stringstream ss;
        ss << "resolved invalid esp=" << fmtHex32(ctx.Esp);
        err.set(ss.str());
        return;
    }
    if(ctx.Esp >= limits.high) {
        std::stringstream ss;
        ss << "stack limit reached esp=" << fmtHex32(ctx.Esp);
        err.set(ss.str());
        return;
    }
    if(!isAnyCode(ctx.Eip)) {
        std::stringstream ss;
        ss << "resolved invalid eip=" << fmtHex32(ctx.Eip);
        err.set(ss.str());
        return;
    }
//    __try {
    tryStep();
//    } __except(EXCEPTION_EXECUTE_HANDLER) {
//        onException();
//    }
}
