//
// Created by DiaLight on 21.01.2023.
//

#ifndef EMBER_FAKEUNKNOWN_H
#define EMBER_FAKEUNKNOWN_H


#include <Unknwnbase.h>

namespace gog {

    template<class Base>
    class FakeUnknown : public Base {

    protected:
        ULONG refs;
    public:
        FakeUnknown() : refs(1) {};

        /*** IUnknown methods ***/
        STDMETHOD(QueryInterface) (THIS_ REFIID riid, LPVOID FAR * ppvObj) PURE;

        STDMETHOD_(ULONG,AddRef) (THIS) override {
            return ++refs;
        }
        STDMETHOD_(ULONG,Release) (THIS) override {
            if (refs == 0) return 0;
            return --refs;
        }

    };

}

#endif //EMBER_FAKEUNKNOWN_H
