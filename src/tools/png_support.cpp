//
// Created by DiaLight on 6/1/2026.
//

#include "png_support.h"
#include "lodepng.h"
#include <sstream>
#include <Windows.h>
#include <filesystem>

#include "dk2/CEngineSurface.h"
#include "dk2/MyCEngineSurfDesc.h"
#include "dk2_functions.h"
#include "dk2_globals.h"
#include "patches/opengl/opengl_patch.h"
#include "dk2/utils/Bgra.h"


bool save_rgba32(void *data, size_t width, size_t height, const char *pngFile) {
    try {
        std::vector<unsigned char> png;
        unsigned error = lodepng::encode(png, (const unsigned char *) data, width, height, LCT_RGBA);
        if (error) {
            printf("lodepng::encode ERR: %d\n", error);
            return false;
        }
        std::stringstream ss;
        ss << pngFile;
        std::string file = ss.str();
        std::filesystem::path path(file);
        std::filesystem::create_directories(path.parent_path());
        error = lodepng::save_file(png, file);
        if (error) {
            printf("lodepng::save_file ERR: %d\n", error);
            return false;
        }
    } catch (...) {
        printf("png_support::save: failed to save %s\n", pngFile);
        return false;
    }
    return true;
}

bool png_support::save(dk2::CEngineSurfaceBase &surf, const char *pngFile) {
    if(patch::opengl_patch::enabled) {  // patch
        auto *data = (uint8_t *) surf.v_lockBuf();

        std::vector<unsigned char> image2(surf.width * surf.height * sizeof(uint32_t));
        auto *lineSrc = (uint8_t *) data;
        auto *lineDst = (uint8_t *) image2.data();
        for(size_t y = 0; y < surf.height; y++) {
            for (size_t x = 0; x < surf.width; x++) {
//                *(uint32_t *) &lineDst[x * 4] = *(uint32_t *) &lineSrc[x * 4];
                // BGRA -> RGBA
                dk2::Bgra color;
                if(surf.fC_desc->desc.dwRGBBitCount == 32) {
                    auto *src = (uint8_t *) &lineSrc[x * 4];
                    color.blue = src[0];
                    color.green = src[1];
                    color.red = src[2];
                    color.alpha = src[3];
                } else {
                    auto *src = (uint8_t *) &lineSrc[x * 2];
                    color.blue = src[0];
                    color.green = src[1];
                    color.red = 0;
                    color.alpha = 255;
                }
                auto *dst = (uint8_t *) &lineDst[x * 4];
                dst[0] = color.red;
                dst[1] = color.green;
                dst[2] = color.blue;
                dst[3] = color.alpha;
            }
            lineSrc += surf.pitch;
            lineDst += surf.width * 4;
        }
        surf.v_unlockBuf(0);
        return save_rgba32(image2.data(), surf.width, surf.height, pngFile);
    }
    dk2::MyCEngineSurfDesc rgba32;
    ZeroMemory(&rgba32, sizeof(rgba32));
    rgba32.bool0 = 1;
    rgba32._bitsiz = 0x20;
    rgba32.bytesPerPixel = 4;
    rgba32.rbitcount = 8;
    rgba32.gbitcount = 8;
    rgba32.bbitcount = 8;
    rgba32.abitcount = 8;
    rgba32._rmask = 0xFF;
    rgba32._gmask = 0xFF00;
    rgba32._bmask = 0xFF0000;
    rgba32._amask = 0xFF000000;
    rgba32.bool2C = 0;
    rgba32.desc = {
            0xFF, 0xFF00, 0xFF0000, 0xFF000000, 0x20, 0
    };
    rgba32.ddPixFmt = {
            0, 0, 0, 0x20, 0xFF, 0xFF00, 0xFF0000, 0xFF000000
    };

    alignas(dk2::CEngineSurface) uint8_t tmpl_buf[sizeof(dk2::CEngineSurface)];
    dk2::CEngineSurface &tmpl = *(dk2::CEngineSurface *) tmpl_buf;
    ZeroMemory(&tmpl, sizeof(tmpl));
    *(void **) &tmpl = dk2::CEngineSurface::vftable;
    tmpl.width = surf.width;
    tmpl.height = surf.height;
    tmpl.pitch = tmpl.width * rgba32.bytesPerPixel;
    std::vector<uint8_t> buffer;
    buffer.resize(tmpl.pitch * tmpl.height);
    tmpl.pixels = &buffer[0];
    tmpl.fC_desc = &rgba32;
    if (!surf.v_copySurf(&tmpl, 0, 0)) {
        printf("png_support::save: failed to copy\n");
        return false;
    }
    return save_rgba32(tmpl.pixels, tmpl.width, tmpl.height, pngFile);
}

bool png_support::save_bgra32(void *data, size_t width, size_t height, size_t pitch, const char *pngFile) {
    size_t bytesPerPixel = 4;
    std::vector<uint8_t> rgba_buffer;
    rgba_buffer.resize(width * bytesPerPixel * height);

    // bgra32 to rgba32
    auto *src_line = (uint8_t *) data;
    auto *dst_line = (uint8_t *) &rgba_buffer[0];
    for (unsigned y = 0; y < height; ++y) {
        for (unsigned x = 0; x < width; ++x) {
            auto b = src_line[x * 4 + 0];
            auto g = src_line[x * 4 + 1];
            auto r = src_line[x * 4 + 2];
            auto a = src_line[x * 4 + 3];
            dst_line[x * 4 + 0] = r;
            dst_line[x * 4 + 1] = g;
            dst_line[x * 4 + 2] = b;
            dst_line[x * 4 + 3] = a;
        }
        src_line += pitch;
        dst_line += width * bytesPerPixel;
    }
    return save_rgba32(&rgba_buffer[0], width, height, pngFile);
}

int getByteOffs(uint32_t mask) {
    if (mask == 0xFF) return 0;
    if (mask == 0xFF00) return 1;
    if (mask == 0xFF0000) return 2;
    if (mask == 0xFF000000) return 3;
    return -1;
}

dk2::CEngineSurface *createSurf(uint32_t width, uint32_t height) {
    dk2::CEngineSurface *surf = (dk2::CEngineSurface *) dk2::MyHeap_alloc(sizeof(dk2::CEngineSurface));
    *(void **) surf = dk2::CEngineSurface::vftable;
    surf->width = width;
    surf->height = height;
    surf->pitch = width * dk2::MyCEngineSurfDesc_bgra32_instance.bytesPerPixel;
    surf->pixels = dk2::MyHeap_alloc(surf->pitch * height);
    surf->fC_desc = &dk2::MyCEngineSurfDesc_bgra32_instance;
    return surf;
}

dk2::CEngineSurface *png_support::load(const char *pngFile) {
    unsigned error;
    std::vector<unsigned char> fileBuffer;
    error = lodepng::load_file(fileBuffer, pngFile);
    if (error) {
        printf("lodepng::load_file: failed to load \"%s\". error=%d\n", pngFile, error);
        return NULL;
    }
    unsigned w, h;
    std::vector<unsigned char> rgba;
    error = lodepng::decode(rgba, w, h, fileBuffer, LCT_RGBA);
    if (error || w == 0 || h == 0) {
        printf("lodepng::decode: failed to decode \"%s\". error=%d\n", pngFile, error);
        return NULL;
    }
    dk2::CEngineSurface *tmpl = createSurf(w, h);

    int ro = getByteOffs(tmpl->fC_desc->_rmask);
    int go = getByteOffs(tmpl->fC_desc->_gmask);
    int bo = getByteOffs(tmpl->fC_desc->_bmask);
    int ao = getByteOffs(tmpl->fC_desc->_amask);
    if (ro < 0 || go < 0 || bo < 0 || ao < 0) {
        printf("unsupported rgba mask in png file \"%s\"\n", pngFile);
        tmpl->v_scalar_destructor(1);
        return NULL;
    }

    // rgba32 to ???32
    auto *src_line = (uint8_t *) &rgba[0];
    auto *dst_line = (uint8_t *) tmpl->pixels;
    for (unsigned y = 0; y < h; ++y) {
        for (unsigned x = 0; x < w; ++x) {
            int r = src_line[x * 4 + 0];
            int g = src_line[x * 4 + 1];
            int b = src_line[x * 4 + 2];
            int a = src_line[x * 4 + 3];
            dst_line[x * 4 + ro] = r;
            dst_line[x * 4 + go] = g;
            dst_line[x * 4 + bo] = b;
            dst_line[x * 4 + ao] = a;
        }
        src_line += w * 4;
        dst_line += tmpl->pitch;
    }
    return tmpl;
}


