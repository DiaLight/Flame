//
// Created by DiaLight on 5/5/2026.
//

#ifndef FLAME_OPENGL_PATCH_H
#define FLAME_OPENGL_PATCH_H

#include "dk2/MyWindow.h"
#include "dk2/CEngineDDSurface.h"
#include "dk2/MyD3D3Vertex.h"
#include "dk2/utils/Idx3us.h"
#include "dk2/RenderStageTex.h"

namespace patch::opengl_patch {

    extern bool enabled;
    extern bool oneWindowOnly;
    extern bool clearSurf;
    extern bool clearSurf2;
    extern bool noSoftwareScale;
    extern bool enableImgui;
    extern bool ignoreCameraMatrix[8];
    extern bool overrideGuiSize;

    dk2::Size2i calcGuiSize(int width, int height);

    void selectEngine(dk2::MyWindow* window);

    int *init(
            int *pstatus, uint32_t width, uint32_t height,
            uint32_t displayBitness, int initFlags, LPPALETTEENTRY entries_
    );
    void cleanup();

    bool handleInput(HWND hWnd, UINT Msg, WPARAM wParam, LPARAM lParam);

    void setFillColor(int r, int g, int b);

    void createViewport();
    void setViewport(uint32_t a1_x, uint32_t a2_y, uint32_t a3_width, uint32_t a4_height);
    void getViewportDesc(LPDIRECTDRAWSURFACE handle, DDSURFACEDESC &desc);

    void setGammaRamp(DDGAMMARAMP &gammaRamp);
    void configureRenderState();

    // texture
    void createOglTexture(dk2::MyDdSurfaceEx &out_surf, size_t width, size_t height, bool videoMemory);
    void createOglTexture(dk2::MyDdSurfaceEx &out_surf, dk2::MySurface &in_surf, bool videoMemory);

    LPDIRECTDRAWSURFACE addRef(LPDIRECTDRAWSURFACE &surf, bool _addRef);
    inline LPDIRECTDRAWSURFACE addRef(LPDIRECTDRAWSURFACE4 &surf, bool _addRef) { return addRef(*(LPDIRECTDRAWSURFACE *) &surf, _addRef); }
    inline LPDIRECTDRAWSURFACE addRef(dk2::MyDdSurface &surf, bool _addRef) { return addRef(surf.dd_surface, _addRef); }
    void releaseOglTexture(LPDIRECTDRAWSURFACE &surf);
    inline void releaseOglTexture(LPDIRECTDRAWSURFACE4 &surf) { return releaseOglTexture(*(LPDIRECTDRAWSURFACE *) &surf); }
    inline void releaseOglTexture(dk2::MyDdSurface &surf) { return releaseOglTexture(surf.dd_surface); }

    LPVOID lock(dk2::MyDdSurface &surf);
    inline LPVOID lock(dk2::MyDdSurfaceEx &surf) { return lock(surf.dd_surf); }
    void unlock(dk2::MyDdSurfaceEx &surf);
    void texSetSrcColorKey(dk2::MyDdSurfaceEx &dst, DWORD color);
    bool fillWithColor(LPDIRECTDRAWSURFACE surf, LPRECT dstRect, dk2::Bgraf a4_color);
    inline bool fillWithColor(dk2::MyDdSurfaceEx &out_surf, LPRECT dstRect, dk2::Bgraf a4_color) { return fillWithColor(out_surf.dd_surf.dd_surface, dstRect, a4_color); }

    void createOglTexture(dk2::CEngineDDSurface &out_surf, DDSURFACEDESC2 &in_desc, bool videoMemory);
    LPVOID lock(dk2::CEngineDDSurface &surf);
    void unlock(dk2::CEngineDDSurface &surf, LPVOID buf);
    void destroy(dk2::CEngineDDSurface &surf);

    bool getDesc(dk2::MyDdSurfaceEx &surf, DDSURFACEDESC &desc);
    bool bltTexture(dk2::MyDdSurfaceEx &dst, RECT *dstRect, dk2::MyDdSurfaceEx &src, RECT *srcRect);
    bool copyTex(dk2::CEngineDDSurface &dst, dk2::CEngineDDSurface &src);
    bool copyBgra32ToTex(uint8_t *data, size_t width, size_t height, size_t pitch,
                         dk2::CEngineSurfaceBase &dst, size_t dstX, size_t dstY);
    bool bindTex(size_t stage, LPDIRECTDRAWSURFACE surf);
    inline bool bindTex(size_t stage, LPDIRECTDRAWSURFACE4 surf) { return bindTex(stage, (LPDIRECTDRAWSURFACE) surf); }
    inline bool bindTex(size_t stage, dk2::CEngineDDSurface &surf) { return bindTex(stage, surf.ddSurf); }

    void dumpTex(LPDIRECTDRAWSURFACE surf, const char *title, int scale = 4, int timeout = -1);
    inline void dumpTex(LPDIRECTDRAWSURFACE4 surf, const char *title, int scale = 4, int timeout = -1) { return dumpTex((LPDIRECTDRAWSURFACE) surf, title, scale, timeout); }
    inline void dumpTex(dk2::MyDdSurfaceEx &surf, const char *title, int scale = 4, int timeout = -1) { return dumpTex(surf.dd_surf.dd_surface, title, scale, timeout); }
    inline void dumpTex(dk2::CEngineDDSurface &surf, const char *title, int scale = 4, int timeout = -1) { return dumpTex(surf.ddSurf, title, scale, timeout); }

    // render
    void beginScene();
    void updateTexRenderState(uint32_t flags);
    void drawCall(
            uint32_t renderStateFlags,
            dk2::RenderStageTex *const *textures, size_t texturesCount,
            const dk2::MyD3D3Vertex *vertices, size_t vertexSize, size_t verticesCount,
            const dk2::Idx3us *indices, size_t trianglesCount
    );

    void endScene();
    void flip();

}


#endif //FLAME_OPENGL_PATCH_H
