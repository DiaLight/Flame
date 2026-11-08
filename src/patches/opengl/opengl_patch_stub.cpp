//
// Created by DiaLight on 11/8/2026.
//
#include "opengl_patch.h"


bool patch::opengl_patch::enabled = false;
bool patch::opengl_patch::oneWindowOnly = false;
bool patch::opengl_patch::clearSurf = false;
bool patch::opengl_patch::clearSurf2 = false;
bool patch::opengl_patch::noSoftwareScale = false;
bool patch::opengl_patch::enableImgui = false;
bool patch::opengl_patch::ignoreCameraMatrix[8] {false};
bool patch::opengl_patch::overrideGuiSize = false;


dk2::Size2i patch::opengl_patch::calcGuiSize(int width, int height) {return {};}

void patch::opengl_patch::selectEngine(dk2::MyWindow* window) {}

int *patch::opengl_patch::init(
        int *pstatus, uint32_t width, uint32_t height,
        uint32_t displayBitness, int initFlags, LPPALETTEENTRY entries_
) {return pstatus;}
void patch::opengl_patch::cleanup() {}

bool patch::opengl_patch::handleInput(HWND hWnd, UINT Msg, WPARAM wParam, LPARAM lParam) {return false;}

void patch::opengl_patch::setFillColor(int r, int g, int b) {}

void patch::opengl_patch::createViewport() {}
void patch::opengl_patch::setViewport(uint32_t a1_x, uint32_t a2_y, uint32_t a3_width, uint32_t a4_height) {}
void patch::opengl_patch::getViewportDesc(LPDIRECTDRAWSURFACE handle, DDSURFACEDESC &desc) {}

void patch::opengl_patch::setGammaRamp(DDGAMMARAMP &gammaRamp) {}
void patch::opengl_patch::configureRenderState() {}

// texture
void patch::opengl_patch::createOglTexture(dk2::MyDdSurfaceEx &out_surf, size_t width, size_t height, bool videoMemory) {}
void patch::opengl_patch::createOglTexture(dk2::MyDdSurfaceEx &out_surf, dk2::MySurface &in_surf, bool videoMemory) {}

LPDIRECTDRAWSURFACE patch::opengl_patch::addRef(LPDIRECTDRAWSURFACE &surf, bool _addRef) {return NULL;}
void patch::opengl_patch::releaseOglTexture(LPDIRECTDRAWSURFACE &surf) {}

LPVOID patch::opengl_patch::lock(dk2::MyDdSurface &surf) {return NULL;}
void patch::opengl_patch::unlock(dk2::MyDdSurfaceEx &surf) {}
void patch::opengl_patch::texSetSrcColorKey(dk2::MyDdSurfaceEx &dst, DWORD color) {}
bool patch::opengl_patch::fillWithColor(LPDIRECTDRAWSURFACE surf, LPRECT dstRect, dk2::Bgraf a4_color) {return false;}

void patch::opengl_patch::createOglTexture(dk2::CEngineDDSurface &out_surf, DDSURFACEDESC2 &in_desc, bool videoMemory) {}
LPVOID patch::opengl_patch::lock(dk2::CEngineDDSurface &surf) {return NULL;}
void patch::opengl_patch::unlock(dk2::CEngineDDSurface &surf, LPVOID buf) {}
void patch::opengl_patch::destroy(dk2::CEngineDDSurface &surf) {}

bool patch::opengl_patch::getDesc(dk2::MyDdSurfaceEx &surf, DDSURFACEDESC &desc) {return false;}
bool patch::opengl_patch::bltTexture(dk2::MyDdSurfaceEx &dst, RECT *dstRect, dk2::MyDdSurfaceEx &src, RECT *srcRect) {return false;}
bool patch::opengl_patch::copyTex(dk2::CEngineDDSurface &dst, dk2::CEngineDDSurface &src) {return false;}
bool patch::opengl_patch::copyBgra32ToTex(uint8_t *data, size_t width, size_t height, size_t pitch,
                     dk2::CEngineSurfaceBase &dst, size_t dstX, size_t dstY) {return false;}
bool patch::opengl_patch::bindTex(size_t stage, LPDIRECTDRAWSURFACE surf) {return false;}

void patch::opengl_patch::dumpTex(LPDIRECTDRAWSURFACE surf, const char *title, int scale, int timeout) {}

// render
void patch::opengl_patch::beginScene() {}
void patch::opengl_patch::updateTexRenderState(uint32_t flags) {}
void patch::opengl_patch::drawCall(
        uint32_t renderStateFlags,
        dk2::RenderStageTex *const *textures, size_t texturesCount,
        const dk2::MyD3D3Vertex *vertices, size_t vertexSize, size_t verticesCount,
        const dk2::Idx3us *indices, size_t trianglesCount
) {}

void patch::opengl_patch::endScene() {}
void patch::opengl_patch::flip() {}
