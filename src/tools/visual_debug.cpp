//
// Created by DiaLight on 3/30/2025.
//
#include "visual_debug.h"
#include <dk2/MyCEngineSurfDesc.h>
#include <dk2/MyDdSurface.h>
#include <dk2/MyDdSurfaceEx.h>
#include <dk2/MySurface.h>
#include <dk2/utils/AABB.h>
#include "dk2_functions.h"
#include "dk2_globals.h"
#include "dk2/CEngineDDSurface.h"
#include "patches/opengl/opengl_patch.h"

#include <CImg.h>
#include <string>
#include <vector>
using namespace cimg_library;


void println(dk2::CEngineSurface &surf) {
    printf("cengsurf: %dx%d pitch:%d bpp:%d bitmask:{%08X %08X %08X %08X} isbpp:%d surf:%p\n",
           surf.width, surf.height,
           surf.pitch,
           surf.fC_desc->desc.dwRGBBitCount,
           surf.fC_desc->desc.dwRBitMask,
           surf.fC_desc->desc.dwGBitMask,
           surf.fC_desc->desc.dwBBitMask,
           surf.fC_desc->desc.dwRGBAlphaBitMask,
           surf.fC_desc->desc.isBytePerPixel,
           surf.pixels
    );
}
void println(dk2::CEngineSurfaceBase &surf) {
    printf("cengsurf: %dx%d pitch:%d bpp:%d bitmask:{%08X %08X %08X %08X} isbpp:%d\n",
           surf.width, surf.height,
           surf.pitch,
           surf.fC_desc->desc.dwRGBBitCount,
           surf.fC_desc->desc.dwRBitMask,
           surf.fC_desc->desc.dwGBitMask,
           surf.fC_desc->desc.dwBBitMask,
           surf.fC_desc->desc.dwRGBAlphaBitMask,
           surf.fC_desc->desc.isBytePerPixel
    );
}
void println(dk2::MySurface &surf) {
    printf("dk2surf: %dx%d pitch:%d bpp:%d bitmask:{%08X %08X %08X %08X} isbpp:%d surf:%p\n",
           surf.size.w, surf.size.h,
           surf.lPitch,
           surf.desc.dwRGBBitCount,
           surf.desc.dwRBitMask,
           surf.desc.dwGBitMask,
           surf.desc.dwBBitMask,
           surf.desc.dwRGBAlphaBitMask,
           surf.desc.isBytePerPixel,
           surf.lpSurface
    );
}
void println(DDSURFACEDESC &desc) {
    printf("dd_surf: %dx%d pitch:%d bpp:%d bitmask:{r:%08X g:%08X b:%08X a:%08X} surf:%p\n",
           desc.dwWidth, desc.dwHeight,
           desc.lPitch,
           desc.ddpfPixelFormat.dwRGBBitCount,
           desc.ddpfPixelFormat.dwRBitMask,
           desc.ddpfPixelFormat.dwGBitMask,
           desc.ddpfPixelFormat.dwBBitMask,
           desc.ddpfPixelFormat.dwRGBAlphaBitMask,
           desc.lpSurface
    );
}
void println(CImg<unsigned char> &img) {
    int w = img.width();
    int h = img.height();
    int z = img.depth();
    int c = img.spectrum();
    printf("cimg: %dx%dx%d channels:%d\n", w, h, z, c);
}
void println(dk2::AABB aabb) {
    printf("aabb: %dx%d,%dx%d\n", aabb.minX, aabb.minY, aabb.maxX, aabb.maxY);
}

void println(dk2::MyDdSurface &surf) {
    if(surf.dd_surface == nullptr) {
        printf("dk2_dd_surf: nullptr\n");
        return;
    }
    DDSURFACEDESC desc;
    ZeroMemory(&desc, sizeof(desc));
    desc.dwSize = sizeof(desc);
    HRESULT hr = surf.dd_surface->GetSurfaceDesc(&desc);
    if(hr == DD_OK) {
        println(desc);
    } else {
        printf("dk2_dd_surf: GetSurfaceDesc: %08X\n", hr);
    }
}
void println(dk2::MyDdSurfaceEx &ddSurface) {
    println(ddSurface.dd_surf);
    println(ddSurface.surf);
}



CImg<unsigned char> from_bgra32(int width, int height, int pitch, void *data) {
    CImg<unsigned char> img(
        width, height,
        1,4,
        0
    );

    auto *lineSrc = (uint8_t *) data;
    for (int y = 0; y < height; ++y) {
        for (int x = 0; x < width; ++x) {
            auto *src = (uint8_t *) &lineSrc[x * 4];
            uint8_t b = src[0];
            uint8_t g = src[1];
            uint8_t r = src[2];
            uint8_t a = src[3];
            img(x, y, 0, 0) = r;
            img(x, y, 0, 1) = g;
            img(x, y, 0, 2) = b;
            img(x, y, 0, 3) = a;
        }
        lineSrc += pitch;
    }
    return img;
}

CImg<unsigned char> from_rgba32(int width, int height, int pitch, void *data) {
    CImg<unsigned char> img(
        width, height,
        1,4,
        0
    );

    auto *lineSrc = (uint8_t *) data;
    for (int y = 0; y < height; ++y) {
        for (int x = 0; x < width; ++x) {
            auto *src = (uint8_t *) &lineSrc[x * 4];
            uint8_t r = src[0];
            uint8_t g = src[1];
            uint8_t b = src[2];
            uint8_t a = src[3];
            img(x, y, 0, 0) = r;
            img(x, y, 0, 1) = g;
            img(x, y, 0, 2) = b;
            img(x, y, 0, 3) = a;
        }
        lineSrc += pitch;
    }
    return img;
}
CImg<unsigned char> toimg_error(int width, int height) {
    CImg<unsigned char> img(width, height, 1,4);
    for (int y = 0; y < img.height(); ++y) {
        for (int x = 0; x < img.width(); ++x) {
            if ((((x / 5) ^ (y / 5)) & 1) == 0) {
                img(x, y, 0, 0) = 0xFF;
                img(x, y, 0, 1) = 0x80;
                img(x, y, 0, 2) = 0x00;
                img(x, y, 0, 3) = 0xFF;
            } else {
                img(x, y, 0, 0) = 0x80;
                img(x, y, 0, 1) = 0x00;
                img(x, y, 0, 2) = 0xFF;
                img(x, y, 0, 3) = 0xFF;
            }
        }
    }
    return img;
}
CImg<unsigned char> toimg(dk2::MySurface &surf) {
    if (surf.desc.dwRGBBitCount == 32) return from_bgra32(surf.size.w, surf.size.h, surf.lPitch, surf.lpSurface);
    printf("[toimg error] ");
    println(surf);
    return toimg_error(surf.size.w, surf.size.h);
}
CImg<unsigned char> toimg(dk2::MyDdSurface &surf) {
    DDSURFACEDESC desc;
    ZeroMemory(&desc, sizeof(desc));
    desc.dwSize = sizeof(desc);
    CImg<unsigned char> img;
    HRESULT result;
    result = surf.dd_surface->Lock(NULL, &desc, DDLOCK_WAIT | DDLOCK_SURFACEMEMORYPTR, NULL);
    if(desc.ddpfPixelFormat.dwRGBBitCount == 32) {
        img = from_bgra32(desc.dwWidth, desc.dwHeight, desc.lPitch, desc.lpSurface);
    } else {
        printf("[toimg error] ");
        println(desc);
        img = toimg_error(desc.dwWidth, desc.dwHeight);
    }
    result = surf.dd_surface->Unlock(NULL);
    return img;
}

CImg<unsigned char> toimg(dk2::MyDdSurfaceEx &ddSurface) {
    if(ddSurface.surf.lpSurface) {
        return toimg(ddSurface.surf);
    }
    return toimg(ddSurface.dd_surf);
}

CImg<unsigned char> toimg_raw(dk2::CEngineSurfaceBase &esurf) {
    uint32_t sz;
    if(void *buf = esurf.v_lockBuf()) {
        CImg<unsigned char> img;
        if(esurf.fC_desc->desc.dwRGBBitCount == 32) {
            img = from_bgra32(esurf.width, esurf.height, esurf.pitch, buf);
        } else {
            printf("[toimg error] ");
            println(esurf);
            img = toimg_error(esurf.width, esurf.height);
        }
        esurf.v_unlockBuf(0);
        return img;
    }
    if(void *buf = esurf.v_getBufWithSize(&sz)) {
        if (esurf.fC_desc->desc.dwRGBBitCount == 32) return from_bgra32(esurf.width, esurf.height, esurf.pitch, buf);
    }
    if(esurf.getVtbl() == dk2::CEngineSurface::vftable) {
        auto *esurf1 = (dk2::CEngineSurface *) &esurf;
        if (esurf.fC_desc->desc.dwRGBBitCount == 32) return from_bgra32(esurf.width, esurf.height, esurf.pitch, esurf1->pixels);
    }
    printf("[toimg error] ");
    println(esurf);
    return toimg_error(esurf.width, esurf.height);
}
CImg<unsigned char> toimg(dk2::CEngineSurfaceBase &esurf) {
    CImg<unsigned char> img;
    char buf[sizeof(dk2::CEngineSurface)];
    dk2::CEngineSurface &surf = *(dk2::CEngineSurface *) buf;
    surf.fC_desc = &dk2::MyCEngineSurfDesc_bgra32_instance;
    *(void **) &surf = dk2::CEngineSurface::vftable;
    surf.width = esurf.width;
    surf.height = esurf.height;
    surf.pitch = esurf.width * dk2::MyCEngineSurfDesc_bgra32_instance.bytesPerPixel;
    surf.pixels = dk2::MyHeap_alloc(surf.height * surf.pitch);
    if(esurf.v_copySurf(&surf, 0, 0)) {
        img = toimg_raw(surf);
    } else {
        img = toimg_raw(esurf);
    }
    dk2::MyHeap_free(surf.pixels);
    return img;
}

void draw_alpha(CImg<unsigned char> &dst, int scale, int offs) {
    for (int y = 0; y < dst.height(); ++y) {
        for (int x = 0; x < dst.width(); ++x) {
            if (((((x + offs) / scale) ^ ((y + offs) / scale)) & 1) == 0) {
                dst(x, y, 0, 0) = 0x20;
                dst(x, y, 0, 1) = 0x20;
                dst(x, y, 0, 2) = 0x20;
            } else {
                dst(x, y, 0, 0) = 0x80;
                dst(x, y, 0, 1) = 0x00;
                dst(x, y, 0, 2) = 0x80;
            }
        }
    }
}

void show(CImg<unsigned char> &img, const char *title, int scale, int timeout) {
    DWORD startMs = GetTickCount();
    const CImg<> scaled = img.get_resize(img.width() * scale, img.height() * scale, img.depth(), img.spectrum());
    // CImg<> scaled = img;
    // scaled.resize(img.width() * 4, img.height() * 4, img.depth(), img.spectrum());
    const CImg<> fg_rgb = scaled.get_shared_channels(0, 2);  // Only RGB part of the foreground.
    const CImg<> fg_a = scaled.get_shared_channel(3);  // Only Alpha part of the foreground.

    CImg<unsigned char> draw = fg_rgb;
    std::string stitle = title;
    {
        stitle.push_back(' ');
        stitle += std::to_string(img.width());
        stitle.push_back('x');
        stitle += std::to_string(img.height());
    }
    CImgDisplay disp(draw,stitle.c_str(),0);
    int x = (CImgDisplay::screen_width() - disp.width()) / 2;
    int y = (CImgDisplay::screen_height() - disp.height()) / 2;
    disp.move(x, y);
//    disp.move(50, 50);
    int tick = 0;
    while (!disp.is_closed() && !disp.is_keyESC() && !disp.is_keyQ()) {
        // Handle display window resizing (if any)
        if (disp.is_resized()) {
            disp.resize().display(scaled);
        }
        draw_alpha(draw, 8 * scale, tick * scale / 10);
        draw.draw_image(0, 0, fg_rgb, fg_a, 1, 255);
        disp.display(draw);

        // Temporize event loop
        cimg::wait(20);
        tick++;
        if(timeout != -1 && (GetTickCount() - startMs) > timeout) break;
    }
    if(!disp.is_closed()) disp.close();
    cimg::wait(40);
}

void show(CImgList<unsigned char> &imgs, const char *title, int scale, int timeout) {
    DWORD startMs = GetTickCount();
    CImgList<unsigned char> scaleds(imgs.size());
    for (int i = 0; i < imgs.size(); ++i) {
        CImg<unsigned char> &img = imgs[i];
        scaleds[i] = img.get_resize(img.width() * scale, img.height() * scale, img.depth(), img.spectrum());
    }
    CImgList<unsigned char> fgs_rgb(imgs.size());
    for (int i = 0; i < imgs.size(); ++i) {
        CImg<unsigned char> &scaled = scaleds[i];
        fgs_rgb[i] = scaled.get_shared_channels(0, 2);  // Only RGB part of the foreground.
    }
    CImgList<unsigned char> fgs_a(imgs.size());
    for (int i = 0; i < imgs.size(); ++i) {
        CImg<unsigned char> &scaled = scaleds[i];
        fgs_a[i] = scaled.get_shared_channel(3);  // Only Alpha part of the foreground.
    }

    CImgList<unsigned char> draws(imgs.size());
    for (int i = 0; i < imgs.size(); ++i) {
        draws[i] = fgs_rgb[i];
    }
    CImgDisplay disp(draws, title, 0);
    disp.move(50, 50);
//    int x = 50;
//    for (int i = 0; i < imgs.size(); ++i) {
//        std::string title = "Img" + std::to_string(i);
//        auto &disp = displays.emplace_back(draws[i], title.c_str(), 0);
//        // disp.move(50, 50);
//        // disp.move(x, 50);
//        // x += draws[i].width() + 12;
//    }
    int tick = 0;
    while (!disp.is_closed() && !disp.is_keyESC() && !disp.is_keyQ()) {
        if (disp.is_resized()) {
            disp.resize().display(draws);
        }

        for (int i = 0; i < imgs.size(); ++i) {
            auto &draw = draws[i];
            draw_alpha(draw, 8 * scale, tick * scale / 10);
            draw.draw_image(0, 0, fgs_rgb[i], fgs_a[i], 1, 255);
        }
        disp.display(draws);

        // Temporize event loop
        cimg::wait(20);
        tick++;
        if(timeout != -1 && (GetTickCount() - startMs) > timeout) break;
    }
    if(!disp.is_closed()) disp.close();
    cimg::wait(40);
}
struct ImgWithTitle {
    CImg<unsigned char> img;
    std::string title;
};
void show_sep(std::vector<ImgWithTitle> &iwts, int scale, int timeout) {
    DWORD startMs = GetTickCount();
    CImgList<unsigned char> scaleds(iwts.size());
    for (int i = 0; i < iwts.size(); ++i) {
        CImg<unsigned char> &img = iwts[i].img;
        scaleds[i] = img.get_resize(img.width() * scale, img.height() * scale, img.depth(), img.spectrum());
    }
    CImgList<unsigned char> fgs_rgb(iwts.size());
    for (int i = 0; i < iwts.size(); ++i) {
        CImg<unsigned char> &scaled = scaleds[i];
        fgs_rgb[i] = scaled.get_shared_channels(0, 2);  // Only RGB part of the foreground.
    }
    CImgList<unsigned char> fgs_a(iwts.size());
    for (int i = 0; i < iwts.size(); ++i) {
        CImg<unsigned char> &scaled = scaleds[i];
        fgs_a[i] = scaled.get_shared_channel(3);  // Only Alpha part of the foreground.
    }

    CImgList<unsigned char> draws(iwts.size());
    for (int i = 0; i < iwts.size(); ++i) {
        draws[i] = fgs_rgb[i];
    }
    std::vector<CImgDisplay> displays;
    int x = 50;
    for (int i = 0; i < iwts.size(); ++i) {
        auto &disp = displays.emplace_back(draws[i], iwts[i].title.c_str(), 0);
        // disp.move(50, 50);
        // disp.move(x, 50);
        // x += draws[i].width() + 12;
    }
    int tick = 0;
    while (true) {
        bool hasDisplay = false;
        for (int i = 0; i < iwts.size(); ++i) {
            auto &disp = displays[i];
            if(disp.is_closed()) continue;
            if(disp.is_keyESC() || disp.is_keyQ()) {
                disp.close();
                continue;
            }
            hasDisplay = true;
            if (disp.is_resized()) {
                disp.resize().display(scaleds[i]);
            }

            auto &draw = draws[i];
            draw_alpha(draw, 8 * scale, tick * scale / 10);
            draw.draw_image(0, 0, fgs_rgb[i], fgs_a[i], 1, 255);
            disp.display(draws[i]);
        }
        if(!hasDisplay) break;

        // Temporize event loop
        cimg::wait(20);
        tick++;
        if(timeout != -1 && (GetTickCount() - startMs) > timeout) break;
    }
    cimg::wait(40);
}

void dump(int width, int height, int pitch, void *data, const char *title, int scale, int timeout) {
    CImg<unsigned char> img = from_bgra32(width, height, pitch, data);
    char buf[256];
    snprintf(buf, 256, "%s %p", title, data);
    show(img, buf, 4, timeout);
}
void dump(dk2::MySurface &surf, const char *title, int scale, int timeout) {
    println(surf);
    CImg<unsigned char> img = toimg(surf);
    char buf[256];
    snprintf(buf, 256, "%s %p", title, surf.lpSurface);
    show(img, buf, 4, timeout);
}
void dump(dk2::MySurface &surf1, dk2::MySurface &surf2, const char *title, int scale, int timeout) {
    println(surf1);
    println(surf2);
    CImgList<unsigned char> imgs = {
        toimg(surf1),
        toimg(surf2),
    };
    show(imgs, title, 4, timeout);
}
void dump(dk2::MySurface &surf1, dk2::MySurface &surf2, dk2::MySurface &surf3, const char *title, int scale, int timeout) {
    println(surf1);
    println(surf2);
    println(surf3);
    CImgList<unsigned char> imgs = {
        toimg(surf1),
        toimg(surf2),
        toimg(surf3),
    };
    show(imgs, title, 4, timeout);
}
void dump(std::vector<dk2::MySurface *> surfaces, const char *title, int scale, int timeout) {
    for (auto *surf : surfaces) {
        println(*surf);
    }
    CImgList<unsigned char> imgs(surfaces.size());
    for (int i = 0; i < surfaces.size(); ++i) {
        imgs[i] = toimg(*surfaces[i]);
    }
    show(imgs, title, 4, timeout);
}

void dump(dk2::MyDdSurface &surf, const char *title, int scale, int timeout) {
    if(patch::opengl_patch::enabled) return patch::opengl_patch::dumpTex(surf.dd_surface, title, scale, timeout);
    println(surf);
    CImg<unsigned char> img = toimg(surf);
    char buf[256];
    snprintf(buf, 256, "%s %p", title, surf.dd_surface);
    show(img, buf, scale, timeout);
}

void dump(dk2::MyDdSurfaceEx &surf, const char *title, int scale, int timeout) {
    if(patch::opengl_patch::enabled) return patch::opengl_patch::dumpTex(surf, title, scale, timeout);
    println(surf);
    CImg<unsigned char> img = toimg(surf);
    char buf[256];
    snprintf(buf, 256, "%s %p", title, surf.dd_surf.dd_surface);
    show(img, buf, scale, timeout);
}

void dump(dk2::CEngineSurfaceBase &surf, const char *title, int scale, int timeout) {
    println(surf);
    CImg<unsigned char> img = toimg(surf);
    show(img, title, scale, timeout);
}
void dump(std::vector<dk2::CEngineSurfaceBase *> &surfs, const char *title, int scale, int timeout) {
    CImgList<unsigned char> imgs;
    for (const auto& surf : surfs) {
        imgs.push_back(toimg(*surf));
    }
    show(imgs, title, 4, timeout);
}
void dump_sep(std::vector<SurfWithTitle> &surfs, int scale, int timeout) {
    std::vector<ImgWithTitle> iwts;
    for (const auto& swt : surfs) {
        iwts.push_back({toimg(*swt.surf), swt.title});
    }
    show_sep(iwts, 4, timeout);
}
void dump_sep(std::vector<dk2::CEngineSurfaceBase *> &surfs, const char *title, int scale, int timeout) {
    std::vector<ImgWithTitle> iwts;
    size_t i = 0;
    for (const auto& surf : surfs) {
        std::string title_s = title;
        title_s.push_back(' ');
        title_s += std::to_string(i++);
        iwts.push_back({toimg(*surf), title_s});
    }
    show_sep(iwts, 4, timeout);
}
void dump(const char *title, int scale, int timeout) {
    CImg<unsigned char> img = toimg_error(32, 32);
    show(img, title, 4, timeout);
}
void dump_bgra32(void *data, size_t width, size_t height, size_t pitch, const char *title, int scale, int timeout) {
    CImg<unsigned char> img = from_bgra32(width, height, pitch, data);
    char buf[256];
    snprintf(buf, 256, "%s %p", title, data);
    show(img, buf, 1, timeout);
}
void dump_rgba32(void *data, size_t width, size_t height, size_t pitch, const char *title, int scale, int timeout) {
    CImg<unsigned char> img = from_rgba32(width, height, pitch, data);
    char buf[256];
    snprintf(buf, 256, "%s %p", title, data);
    show(img, buf, 1, timeout);
}
