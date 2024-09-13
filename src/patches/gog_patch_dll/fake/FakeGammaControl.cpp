//
// Created by DiaLight on 20.01.2023.
//
#include <fake/FakeGammaControl.h>
#include <gog_debug.h>

using namespace gog;

FakeGammaControl *FakeGammaControl::instance = nullptr;

HRESULT FakeGammaControl::QueryInterface(REFIID riid, LPVOID FAR *ppvObj) {
    gog_debug("Unused function called: FakeGammaControl::QueryInterface");
    return DDERR_GENERIC;
}

HRESULT FakeGammaControl::GetGammaRamp(DWORD, LPDDGAMMARAMP) {
    gog_debug("Unused function called: FakeGammaControl::GetGammaRamp");
    return DDERR_GENERIC;
}

HRESULT FakeGammaControl::SetGammaRamp(DWORD, LPDDGAMMARAMP) {
    return DD_OK;
}
