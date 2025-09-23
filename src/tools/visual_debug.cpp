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

#include <CImg.h>
#include <string>
#include <vector>
using namespace cimg_library;


void println(dk2::CEngineSurface &surf) {
    printf("cengsurf: %dx%d pitch:%d bpp:%d bitmask:{%08X %08X %08X %08X} isbpp:%d surf:%p\n",
           surf.width, surf.height,
           surf.lineWidth,
           surf.fC_desc->desc.dwRGBBitCount,
           surf.fC_desc->desc.dwRBitMask,
           surf.fC_desc->desc.dwGBitMask,
           surf.fC_desc->desc.dwBBitMask,
           surf.fC_desc->desc.dwRGBAlphaBitMask,
           surf.fC_desc->desc.isBytePerPixel,
           surf.pixels
    );
}
void println(dk2::MySurface &surf) {
    printf("dk2surf: %dx%d pitch:%d bpp:%d bitmask:{%08X %08X %08X %08X} isbpp:%d surf:%p\n",
           surf.dwWidth, surf.dwHeight,
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
    int c = img.spectrum();
    printf("cimg: %dx%d channels:%d\n", w, h, c);
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



CImg<unsigned char> from_argb(int width, int height, int pitch, void *data) {
    CImg<unsigned char> img(
        width, height,
        1,4,
        0
    );

    auto *line = (uint8_t *) data;
    for (int y = 0; y < height; ++y) {
      auto *pos = (uint32_t *) line;
      for (int x = 0; x < width; ++x) {
        uint32_t px = *pos;
        img(x, y, 0, 0) = (px >> 16) & 0xFF;
        img(x, y, 0, 1) = (px >> 8) & 0xFF;
        img(x, y, 0, 2) = (px >> 0) & 0xFF;
        img(x, y, 0, 3) = (px >> 24) & 0xFF;
        pos++;
      }
      line += pitch;
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
    if (surf.desc.dwRGBBitCount == 32) return from_argb(surf.dwWidth, surf.dwHeight, surf.lPitch, surf.lpSurface);
    printf("[toimg error] ");
    println(surf);
    return toimg_error(surf.dwWidth, surf.dwHeight);
}
CImg<unsigned char> toimg(dk2::MyDdSurface &surf) {
    DDSURFACEDESC desc;
    ZeroMemory(&desc, sizeof(desc));
    desc.dwSize = sizeof(desc);
    CImg<unsigned char> img;
    HRESULT result;
    result = surf.dd_surface->Lock(NULL, &desc, DDLOCK_WAIT | DDLOCK_SURFACEMEMORYPTR, NULL);
    if(desc.ddpfPixelFormat.dwRGBBitCount == 32) {
        img = from_argb(desc.dwWidth, desc.dwHeight, desc.lPitch, desc.lpSurface);
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

CImg<unsigned char> toimg_raw(dk2::CEngineSurface &esurf) {
    uint32_t sz;
    if(void *buf = esurf.v_lockBuf()) {
        CImg<unsigned char> img;
        if(esurf.fC_desc->desc.dwRGBBitCount == 32) {
            img = from_argb(esurf.width, esurf.height, esurf.lineWidth, buf);
        } else {
            printf("[toimg error] ");
            println(esurf);
            img = toimg_error(esurf.width, esurf.height);
        }
        esurf.v_unlockBuf(0);
        return img;
    }
    if(void *buf = esurf.v_getBufWithSize(&sz)) {
        if (esurf.fC_desc->desc.dwRGBBitCount == 32) return from_argb(esurf.width, esurf.height, esurf.lineWidth, buf);
    }
    if (esurf.fC_desc->desc.dwRGBBitCount == 32) return from_argb(esurf.width, esurf.height, esurf.lineWidth, esurf.pixels);
    printf("[toimg error] ");
    println(esurf);
    return toimg_error(esurf.width, esurf.height);
}
CImg<unsigned char> toimg(dk2::CEngineSurface &esurf) {
    CImg<unsigned char> img;
    char buf[sizeof(dk2::CEngineSurface)];
    dk2::CEngineSurface &surf = *(dk2::CEngineSurface *) buf;
    surf.fC_desc = &dk2::MyCEngineSurfDesc_argb32_instance;
    *(void **) &surf = dk2::CEngineSurface::vftable;
    surf.width = esurf.width;
    surf.height = esurf.height;
    surf.lineWidth = esurf.width * dk2::MyCEngineSurfDesc_argb32_instance.bytesize;
    surf.pixels = dk2::MyHeap_alloc(surf.height * surf.lineWidth);
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

void show(CImg<unsigned char> &img, int timeout) {
    DWORD startMs = GetTickCount();
    int scale = 4;
    const CImg<> scaled = img.get_resize(img.width() * scale, img.height() * scale, img.depth(), img.spectrum());
    // CImg<> scaled = img;
    // scaled.resize(img.width() * 4, img.height() * 4, img.depth(), img.spectrum());
    const CImg<> fg_rgb = scaled.get_shared_channels(0, 2);  // Only RGB part of the foreground.
    const CImg<> fg_a = scaled.get_shared_channel(3);  // Only Alpha part of the foreground.

    CImg<unsigned char> draw = fg_rgb;
    CImgDisplay disp(draw,"Img",0);
    int x = (CImgDisplay::screen_width() - disp.width()) / 2;
    int y = (CImgDisplay::screen_height() - disp.height()) / 2;
    disp.move(x, y);
//    disp.move(50, 50);
    int i = 0;
    while (!disp.is_closed() && !disp.is_keyESC() && !disp.is_keyQ()) {
        // Handle display window resizing (if any)
        if (disp.is_resized()) {
            disp.resize().display(scaled);
        }
        draw_alpha(draw, 8 * scale, i * scale / 10);
        draw.draw_image(0, 0, fg_rgb, fg_a, 1, 255);
        disp.display(draw);

        // Temporize event loop
        cimg::wait(20);
        i++;
        if(timeout != -1 && (GetTickCount() - startMs) > timeout) break;
    }
    if(!disp.is_closed()) disp.close();
    cimg::wait(40);
}

void show(CImgList<unsigned char> &imgs, int timeout) {
    DWORD startMs = GetTickCount();
    int scale = 4;
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
    CImgDisplay disp(draws, "Imgs", 0);
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

void dump(dk2::MySurface &surf, int timeout) {
    println(surf);
    CImg<unsigned char> img = toimg(surf);
    show(img, timeout);
}
void dump(dk2::MySurface &surf1, dk2::MySurface &surf2, int timeout) {
    println(surf1);
    println(surf2);
    CImgList<unsigned char> imgs = {
        toimg(surf1),
        toimg(surf2),
    };
    show(imgs, timeout);
}
void dump(dk2::MySurface &surf1, dk2::MySurface &surf2, dk2::MySurface &surf3, int timeout) {
    println(surf1);
    println(surf2);
    println(surf3);
    CImgList<unsigned char> imgs = {
        toimg(surf1),
        toimg(surf2),
        toimg(surf3),
    };
    show(imgs, timeout);
}
void dump(std::vector<dk2::MySurface *> surfaces, int timeout) {
    for (auto *surf : surfaces) {
        println(*surf);
    }
    CImgList<unsigned char> imgs(surfaces.size());
    for (int i = 0; i < surfaces.size(); ++i) {
        imgs[i] = toimg(*surfaces[i]);
    }
    show(imgs, timeout);
}

void dump(dk2::CEngineSurface &surf, int timeout) {
    println(surf);
    CImg<unsigned char> img = toimg(surf);
    show(img, timeout);
}
void dump(std::vector<dk2::CEngineSurface *> &surfs, int timeout) {
    CImgList<unsigned char> imgs;
    for (const auto& surf : surfs) {
        imgs.push_back(toimg(*surf));
    }
    show(imgs, timeout);
}
void dump(int timeout) {
    CImg<unsigned char> img = toimg_error(32, 32);
    show(img, timeout);
}
