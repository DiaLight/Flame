//
// Created by DiaLight on 5/5/2026.
//

#include "opengl_patch.h"
#include "dk2_globals.h"
#include "opengl_internal.h"
#include "dk2/engine/game_engine.h"
#include "dk2_functions.h"
#include "tools/png_support.h"
#include "tools/visual_debug.h"
#include "patches/logging.h"
#include "imgui.h"
#include "imgui_impl_opengl3.h"
#include "imgui_impl_win32.h"
#include <exception>
#include <iostream>
#include <GL/glu.h>

//bool patch::opengl_patch::enabled = false;
bool patch::opengl_patch::enabled = true;
bool patch::opengl_patch::oneWindowOnly = patch::opengl_patch::enabled;
bool patch::opengl_patch::clearSurf = false;
bool patch::opengl_patch::clearSurf2 = true;
bool patch::opengl_patch::noSoftwareScale = patch::opengl_patch::enabled;  // dont do it software way. let opengl handle this for you in a draw call
bool patch::opengl_patch::enableImgui = patch::opengl_patch::enabled;
//bool patch::opengl_patch::disableFrustumCulling = patch::opengl_patch::enabled;
bool patch::opengl_patch::ignoreCameraMatrix[8] {false};
bool patch::opengl_patch::overrideGuiSize = true;

//if(patch::opengl_patch::enabled) {
//if(( 1 << 15 ) & GetAsyncKeyState(VK_NUMPAD0)) {

dk2::Size2i patch::opengl_patch::calcGuiSize(int width, int height) {
    if (height == 0) {
        height = 1;
    }
//    return dk2::Size2i {width, height};
    return dk2::Size2i {640, 480};  // its better keep original sizes
    float original_aspect = 640.f / 480.f;
    float window_aspect = (float) width / (float) height;
    dk2::Size2i result;
    if(window_aspect > original_aspect) {
        float adjusted_aspect = window_aspect / original_aspect;
        result = dk2::Size2i {(int) (640 * adjusted_aspect), 480};
    } else {
        float adjusted_aspect = window_aspect / original_aspect;
        result = dk2::Size2i {640, (int) (480 / adjusted_aspect)};
    }
//    result = dk2::Size2i {(int) (640 * adjusted_aspect), 480};
//    printf("%dx%d -> %dx%d\n", width, height, result.w, result.h);
    return result;
}

void patch::opengl_patch::selectEngine(dk2::MyWindow* window) {
    // OpenGL engine selection patch
    // This function handles the OpenGL rendering engine selection for the game


    {
        dk2::MyResources_instance.video_settings.setSelected3dEngine(2);
        dk2::MyResources_instance.video_settings.writeGuidIndex(-1);
        window->selected_dd_idx = -1;
    }
}

void ResizeOpenGL(int width, int height) {
    if (height == 0) {
        height = 1;
    }

    glViewport(0, 0, width, height);

    glMatrixMode(GL_PROJECTION);
    glLoadIdentity();
    gluPerspective(60.0, (double)width / (double)height, 0.1, 100.0);

    glMatrixMode(GL_MODELVIEW);
    glLoadIdentity();

    if(patch::opengl_patch::overrideGuiSize) {
        auto size = patch::opengl_patch::calcGuiSize(width, height);
        patch::opengl_patch::createOglTexture(dk2::MyWindow_instance.c_window_test.offScreenSurf, size.w, size.h, true);
        dk2::AABB aabb {(size.w - 640) / 2, (size.h - 480) / 2, 640, 480};
        dk2::CFrontEndComponent_instance.cgui_manager.aabb = aabb;
        dk2::CDefaultPlayerInterface_instance.cgui_manager.aabb = aabb;

        patch::opengl_patch::createOglTexture(dk2::g_primarySurf, size.w, size.h, true);
        patch::opengl_patch::createOglTexture(dk2::g_offScreen, size.w, size.h, true);
//        patch::opengl_patch::createOglTexture(dk2::g_primarySurf, width, height, true);
//        patch::opengl_patch::createOglTexture(dk2::g_offScreen, width, height, true);
    } else {
        patch::opengl_patch::createOglTexture(dk2::g_primarySurf, width, height, true);
        patch::opengl_patch::createOglTexture(dk2::g_offScreen, width, height, true);
    }
}

bool init_opengl(HWND hWnd, uint32_t width, uint32_t height) {
    patch::log::dbg("init_opengl: hWnd=0x%X res=%dx%d", hWnd, width, height);
    if (!hWnd) {
        std::cerr << "hWnd is NULL" << std::endl;
        return false;
    }

    if(!g_oglCtx.init(hWnd)) return false;

    glClearColor(0.1f, 0.1f, 0.15f, 1.0f);
    glClearDepth(1.0f);
    glEnable(GL_DEPTH_TEST);
    glDepthFunc(GL_LEQUAL);
    glHint(GL_PERSPECTIVE_CORRECTION_HINT, GL_NICEST);

    // Get initial window size for viewport
    RECT rect = {};
    GetClientRect(hWnd, &rect);
    ResizeOpenGL(rect.right - rect.left, rect.bottom - rect.top);

    if(patch::opengl_patch::enableImgui) {
        // Setup Dear ImGui context
        IMGUI_CHECKVERSION();
        ImGui::CreateContext();
        ImGuiIO& io = ImGui::GetIO(); (void)io;
        io.ConfigFlags |= ImGuiConfigFlags_NavEnableKeyboard;   // Enable Keyboard Controls
        io.ConfigFlags |= ImGuiConfigFlags_NavEnableGamepad;    // Enable Gamepad Controls

        // Setup Dear ImGui style
        ImGui::StyleColorsDark();
        //ImGui::StyleColorsClassic();

        // Setup scaling
        float main_scale = ImGui_ImplWin32_GetDpiScaleForMonitor(::MonitorFromPoint(POINT{ 0, 0 }, MONITOR_DEFAULTTOPRIMARY));
        ImGuiStyle& style = ImGui::GetStyle();
        style.ScaleAllSizes(main_scale);        // Bake a fixed style scale. (until we have a solution for dynamic style scaling, changing this requires resetting Style + calling this again)
        style.FontScaleDpi = main_scale;        // Set initial font scale. (using io.ConfigDpiScaleFonts=true makes this unnecessary. We leave both here for documentation purpose)

        // Setup Platform/Renderer backends
        ImGui_ImplWin32_InitForOpenGL(hWnd);
        ImGui_ImplOpenGL3_Init();
    }

    return true;
}


int *patch::opengl_patch::init(
        int *pstatus, uint32_t width, uint32_t height,
        uint32_t displayBitness, int initFlags, LPPALETTEENTRY entries_
) {
    if(dk2::g_primarySurf.dd_surf.dd_surface) {
        throw std::exception("unexpected");
    }
    if(dk2::g_offScreen.dd_surf.dd_surface) {
        throw std::exception("unexpected");
    }

    if(!g_oglInitialized) {
        cleanup();
        if(!init_opengl(dk2::getHWindow(), width, height)) {
            return *pstatus = -1, pstatus;
        }
        if(patch::opengl_patch::oneWindowOnly) {
            g_oglInitialized = true;
        }
    } else {
        throw std::exception("once");
    }

//    createOglTexture(dk2::g_primarySurf, width, height, true);
//    createOglTexture(dk2::g_offScreen, width, height, true);

    dk2::g_pCurOffScreen = &dk2::g_offScreen;
    return *pstatus = 0, pstatus;
}

void patch::opengl_patch::cleanup() {
    if(!g_oglInitialized) return;
    if(patch::opengl_patch::enableImgui) {
        ImGui_ImplOpenGL3_Shutdown();
        ImGui_ImplWin32_Shutdown();
        ImGui::DestroyContext();
    }

    g_oglCtx.cleanup();
    g_oglInitialized = false;
}
// Forward declare message handler from imgui_impl_win32.cpp
extern IMGUI_IMPL_API LRESULT ImGui_ImplWin32_WndProcHandler(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam);
bool patch::opengl_patch::handleInput(HWND hWnd, UINT Msg, WPARAM wParam, LPARAM lParam) {
    if(patch::opengl_patch::enableImgui && ImGui::GetCurrentContext() != nullptr) {
        if (ImGui_ImplWin32_WndProcHandler(hWnd, Msg, wParam, lParam)) ;//return true;
        ImGuiIO& io = ImGui::GetIO();
//        return io.WantCaptureMouse || io.WantCaptureKeyboard;
        io.MouseDrawCursor = io.WantCaptureMouse;
        return io.WantCaptureMouse;
    }
    return false;
}

void patch::opengl_patch::setFillColor(int r, int g, int b) {
//    glClearColor(r / 256.f, g / 256.f, b / 256.f, 1.0f);
}

void patch::opengl_patch::createViewport() {

}

void patch::opengl_patch::setViewport(uint32_t x, uint32_t y, uint32_t width, uint32_t height) {
//    patch::log::dbg("setViewport: pos=%dx%d res=%dx%d", x, y, width, height);
//    ResizeOpenGL(width, height);

    RECT rect = {};
    if(GetClientRect(dk2::getHWindow(), &rect)) {
        ResizeOpenGL(rect.right - rect.left, rect.bottom - rect.top);
    }
}

void patch::opengl_patch::getViewportDesc(LPDIRECTDRAWSURFACE handle, DDSURFACEDESC &desc) {
    RECT rect = {0,0,0,0};
    GetClientRect(dk2::getHWindow(), &rect);

    ZeroMemory(&desc, sizeof(desc));
    if(auto *tex = OglPatchTexture::get(handle)) {
        desc.dwWidth = tex->width;
        desc.dwHeight = tex->height;
        desc.lpSurface = tex->data;
        desc.lPitch = tex->width * 4;
        desc.ddpfPixelFormat.dwRGBBitCount = 32;
        desc.ddpfPixelFormat.dwRBitMask = 0xFF0000;
        desc.ddpfPixelFormat.dwGBitMask = 0xFF00;
        desc.ddpfPixelFormat.dwBBitMask = 0xFF;
        desc.ddpfPixelFormat.dwRGBAlphaBitMask = 0xFF000000;
        patch::log::dbg("getViewportDesc by prim: res=%dx%d", desc.dwWidth, desc.dwHeight);
    } else {
        desc.dwWidth = rect.right - rect.left;
        desc.dwHeight = rect.bottom - rect.top;
        desc.lpSurface = NULL;
        desc.lPitch = 0;
        desc.ddpfPixelFormat.dwRGBBitCount = 32;
        desc.ddpfPixelFormat.dwRBitMask = 0xFF0000;
        desc.ddpfPixelFormat.dwGBitMask = 0xFF00;
        desc.ddpfPixelFormat.dwBBitMask = 0xFF;
        desc.ddpfPixelFormat.dwRGBAlphaBitMask = 0xFF000000;
        patch::log::dbg("getViewportDesc by view: res=%dx%d", desc.dwWidth, desc.dwHeight);
    }
}

void patch::opengl_patch::setGammaRamp(DDGAMMARAMP &gammaRamp) {

}

void patch::opengl_patch::configureRenderState() {
    // D3DRENDERSTATE_SHADEMODE = 2 (D3D_SHADE_GOURAUD)
    glShadeModel(GL_SMOOTH);

    // D3DRENDERSTATE_TEXTUREPERSPECTIVE = 1 (perspective-correct texturing)
    // OpenGL does perspective correction by default; use nicest quality
    glHint(GL_PERSPECTIVE_CORRECTION_HINT, GL_NICEST);

    // D3DRENDERSTATE_DITHERENABLE = 1
    glEnable(GL_DITHER);

    // D3DRENDERSTATE_CULLMODE = 1 (D3DCULL_CCW)
//    glEnable(GL_CULL_FACE);
//    glCullFace(GL_BACK);
//    glFrontFace(GL_CCW);

    // D3DRENDERSTATE_SPECULARENABLE = 0 (specular already disabled by default)

    // D3DRENDERSTATE_SUBPIXEL = 1 (subpixel precision already enabled by default)

    // D3DRENDERSTATE_ZFUNC = 4 (D3DCMP_LESS)
    glDepthFunc(GL_LESS);

    // --- Texture Stage 0 ---
    // D3D: ColorOp = MODULATE2X, ColorArg1 = TEXTURE, ColorArg2 = CONSTANT
    // D3D: AlphaOp = MODULATE2X, AlphaArg1 = TEXTURE, AlphaArg2 = CONSTANT
    // OpenGL equivalent: GL_MODULATE textures with GL_CONSTANT
//    glActiveTexture(GL_TEXTURE0);
    glEnable(GL_TEXTURE_2D);
//    glTexEnvi(GL_TEXTURE_ENV, GL_TEXTURE_ENV_MODE, GL_MODULATE);

    // RGB combiner: MODULATE2X(TEXTURE, CONSTANT)
    // For extended combiners (GL_EXT_texture_env_combine):
    //   SOURCE0_RGB = TEXTURE, OPERAND0_RGB = SRC_COLOR
    //   SOURCE1_RGB = CONSTANT, OPERAND1_RGB = SRC_COLOR
    // Result = TextureColor * ConstantColor * 2
//#ifdef GL_EXT_texture_env_combine
//    glTexEnvi(GL_TEXTURE_ENV, GL_RGB_SCALE_EXT, 2);
//    glTexEnvi(GL_TEXTURE_ENV, GL_SOURCE0_RGB_EXT, GL_TEXTURE);
//    glTexEnvi(GL_TEXTURE_ENV, GL_OPERAND0_RGB_EXT, GL_SRC_COLOR);
//    glTexEnvi(GL_TEXTURE_ENV, GL_SOURCE1_RGB_EXT, GL_CONSTANT);
//    glTexEnvi(GL_TEXTURE_ENV, GL_OPERAND1_RGB_EXT, GL_SRC_COLOR);
//
//    // Alpha combiner
//    glTexEnvi(GL_TEXTURE_ENV, GL_SOURCE0_ALPHA_EXT, GL_TEXTURE);
//    glTexEnvi(GL_TEXTURE_ENV, GL_OPERAND0_ALPHA_EXT, GL_SRC_ALPHA);
//    glTexEnvi(GL_TEXTURE_ENV, GL_SOURCE1_ALPHA_EXT, GL_CONSTANT);
//    glTexEnvi(GL_TEXTURE_ENV, GL_OPERAND1_ALPHA_EXT, GL_SRC_ALPHA);
//#else
//    // Fallback: standard GL_MODULATE uses current color, not constant
//    // This approximates MODULATE2X with a scale
//    glTexEnvi(GL_TEXTURE_ENV, GL_SOURCE0_RGB, GL_TEXTURE);
//    glTexEnvi(GL_TEXTURE_ENV, GL_OPERAND0_RGB, GL_SRC_COLOR);
//    glTexEnvi(GL_TEXTURE_ENV, GL_RGB_SCALE_EXT ? GL_RGB_SCALE_EXT : 0, 2);
//#endif

    // --- Extra texture stages ---
    // D3D: SetTextureStageState(i, TEXCOORDINDEX, i) - use layer i for texcoords
    // D3D: SetTextureStageState(i, ADDRESS, 1) - D3DTADDRESS_REPEAT
//    for (int i = 0; i < dk2::MyDirectDraw_instance_triangles.texturesCount; ++i) {
//        glActiveTexture(GL_TEXTURE0 + i);
//        glEnable(GL_TEXTURE_2D);
//        // GL_REPEAT = D3DTADDRESS_WRAP
//        glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_WRAP_S, GL_REPEAT);
//        glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_WRAP_T, GL_REPEAT);
//    }
    glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_WRAP_S, GL_REPEAT);
    glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_WRAP_T, GL_REPEAT);

    updateTexRenderState(0);
}


