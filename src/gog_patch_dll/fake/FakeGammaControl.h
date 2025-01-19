//
// Created by DiaLight on 20.01.2023.
//

#ifndef EMBER_FAKEGAMMACONTROL_H
#define EMBER_FAKEGAMMACONTROL_H

#include <ddraw.h>
#include <fake/FakeUnknown.h>

namespace gog {

    class FakeGammaControl : public FakeUnknown<IDirectDrawGammaControl> {

    public:

        /*** IUnknown methods ***/
        STDMETHOD(QueryInterface) (THIS_ REFIID riid, LPVOID FAR * ppvObj) override;

        /*** IDirectDrawGammaControl methods ***/
        STDMETHOD(GetGammaRamp)(THIS_ DWORD, LPDDGAMMARAMP) override;
        STDMETHOD(SetGammaRamp)(THIS_ DWORD, LPDDGAMMARAMP) override;

        static FakeGammaControl *instance;

    };

}

#endif //EMBER_FAKEGAMMACONTROL_H
