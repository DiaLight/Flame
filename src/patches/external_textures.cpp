//
// Created by DiaLight on 10/8/2025.
//

#include <Windows.h>
#include <filesystem>
#include <lodepng.h>
#include <sstream>
#include <string>
#include <vector>
#include "dk2/CEngineCompressedSurface.h"
#include "dk2/CEngineSurface.h"
#include "dk2/MyCESurfHandle.h"
#include "dk2_functions.h"
#include "dk2_globals.h"
#include "external_textures.h"
#include "patches/logging.h"
#include "tools/flame_config.h"


struct Rgba32 {

    alignas(dk2::MyCEngineSurfDesc) uint8_t desc_buf[sizeof(dk2::MyCEngineSurfDesc)];

    Rgba32() {
        dk2::MyCEngineSurfDesc &rgba32 = desc();
        ZeroMemory(&rgba32, sizeof(rgba32));
        rgba32.f0 = 1;
        rgba32._bitsiz = 0x20;
        rgba32.bytesize = 4;
        rgba32.rbitcount = 8;
        rgba32.gbitcount = 8;
        rgba32.bbitcount = 8;
        rgba32.abitcount = 8;
        rgba32._rmask = 0xFF;
        rgba32._gmask = 0xFF00;
        rgba32._bmask = 0xFF0000;
        rgba32._amask = 0xFF000000;
        rgba32.f2C = 0;
        rgba32.desc = {
            0xFF, 0xFF00, 0xFF0000, 0xFF000000, 0x20, 0
        };
        rgba32.ddPixFmt = {
            0, 0, 0, 0x20, 0xFF, 0xFF00, 0xFF0000, 0xFF000000
        };
    }

    inline dk2::MyCEngineSurfDesc &desc() {
        return *(dk2::MyCEngineSurfDesc *) desc_buf;
    }

};

std::string getTexturePath(const std::string &name) {
    std::stringstream ss;
    ss << dk2::dk2HomeDir << "flame/resources/default/EngineTextures/" << name << ".png";
    return ss.str();
}

bool save32_(int width, int height, int pitch, std::vector<uint8_t> &buffer, const std::string &name) {
    unsigned error;
    std::vector<unsigned char> png;
    try {
        error = lodepng::encode(png, (const unsigned char*) buffer.data(), width, height);
        if (error) {
            patch::log::err("Failed to encode png %s: %d\n", name.c_str(), error);
            return false;
        }
        std::string file = getTexturePath(name);
        std::filesystem::path path(file);
        std::filesystem::create_directories(path.parent_path());
        error = lodepng::save_file(png, file);
        if (error) {
            patch::log::err("Failed to save encoded png %s: %d\n", name.c_str(), error);
            return false;
        }
    } catch (...) {
        printf("failed to save %s\n", name.c_str());
        return false;
    }
    return true;
}

flame_config::define_flame_option<bool> o_external_textures(
    "flame:external-textures", flame_config::OG_Config,
    "Dump textures to flame/resources/default and load them back\n",
    false
);

void patch::external_textures::dumpTextures() {
    if(!*o_external_textures) return;
    FILE *f = fopen(dk2::MyTextures_instance.textureCacheFile_dir, "rb");
    uint32_t signature;
    fread(&signature, sizeof(signature), 1, f);
    uint32_t file_size;
    fread(&file_size, sizeof(file_size), 1, f);
    uint32_t version;
    fread(&version, sizeof(version), 1, f);
    int32_t num_entries;
    fread(&num_entries, sizeof(num_entries), 1, f);

    size_t texturesExtracted = 0;
    DWORD time = GetTickCount();
    for (int i = 0; i < num_entries; ++i) {
        std::string name;
        while (true) {
            char c;
            fread(&c, sizeof(c), 1, f);
            if (c == '\0') break;
            name.push_back(c);
        }
        uint32_t offset;
        fread(&offset, sizeof(offset), 1, f);

        std::string file = getTexturePath(name);
        std::filesystem::path path(file);
        if(std::filesystem::exists(path)) continue;

        DWORD cur = GetTickCount();
        if ((cur - time) > 3000) {
            time = cur;
            printf("Extracting textures (%6d/%6d): %s\n", i, num_entries, name.c_str());
        }
        dk2::CEngineCompressedSurface *ret = dk2::MyTextures_instance.loadCompressed((char *) name.c_str());
        if (ret) {
            alignas(dk2::CEngineSurface) uint8_t decompressed_buf[sizeof(dk2::CEngineSurface)];
            dk2::CEngineSurface &dec = *(dk2::CEngineSurface *) decompressed_buf;
            ZeroMemory(&dec, sizeof(dec));
            *(void **) &dec = dk2::CEngineSurface::vftable;

            Rgba32 rgba32;
            dec.width = ret->width;
            dec.height = ret->height;
            dec.fC_desc = &rgba32.desc();
            dec.lineWidth = dec.width * dec.fC_desc->bytesize;
            std::vector<uint8_t> buffer;
            buffer.resize(dec.width * dec.height * dec.fC_desc->bytesize);
            dec.pixels = buffer.data();
            if (!ret->v_copySurf(&dec, 0, 0)) {
                patch::log::err("failed to decompress %s", name.c_str());
            } else {
                if(save32_(dec.width, dec.height, dec.lineWidth, buffer, name.c_str())) {
                    texturesExtracted++;
                }
            }
            ret->v_scalar_destructor(1u);
        }
    }
    fclose(f);
    if(texturesExtracted != 0) {
        printf("Textures unpacked %d to flame/resources/default\n", texturesExtracted);
    }
}


namespace {

    dk2::CEngineSurfaceBase *createSurf_orig(uint8_t width, uint8_t height) {
        alignas(dk2::MyCESurfHandle) uint8_t handle_buf[sizeof(dk2::MyCESurfHandle)];
        dk2::MyCESurfHandle &handle = *(dk2::MyCESurfHandle *) handle_buf;
        ZeroMemory(&handle, sizeof(handle));
        handle.reductionLevel_andFlags |= 0x80;
        handle.cesurf = nullptr;
        handle.surfWidth8 = 0;
        handle.surfHeight8 = 0;
        handle.create();
        return handle.cesurf;
    }

    dk2::CEngineSurface *createSurf(uint32_t width, uint32_t height) {
        dk2::CEngineSurface *surf = (dk2::CEngineSurface *) dk2::MyHeap_alloc(sizeof(dk2::CEngineSurface));
        surf->fC_desc = &dk2::MyCEngineSurfDesc_argb32_instance;
        surf->width = width;
        surf->height = height;
        surf->lineWidth = width * surf->fC_desc->bytesize;
        *(void **) surf = dk2::CEngineSurface::vftable;
        surf->pixels = dk2::MyHeap_alloc(height * width * surf->fC_desc->bytesize);
        return surf;
    }

    int getByteOffs(uint32_t mask) {
        if (mask == 0xFF) return 0;
        if (mask == 0xFF00) return 1;
        if (mask == 0xFF0000) return 2;
        if (mask == 0xFF000000) return 3;
        return -1;
    }

}


dk2::CEngineSurfaceBase *patch::external_textures::loadFlameTexture(char *texName) {
    if(!*o_external_textures) return NULL;
    if (strstr(texName, "PRESCALED_TO") != NULL) {
        // don't try to load prescaled textures
        return NULL;
    }
    std::string file = getTexturePath(texName);

    unsigned error;
    std::vector<unsigned char> buffer;
    error = lodepng::load_file(buffer, file);
    if (error) {
        //        printf("failed to load %s from resources. using EngineTextures.dat\n", texName);
        return NULL;
    }
    lodepng::State state;
    state.decoder.ignore_crc = 1;
    state.decoder.zlibsettings.ignore_adler32 = 1;
    unsigned w, h;
    std::vector<unsigned char> rgba;
    error = lodepng::decode(rgba, w, h, state, buffer);
    if (error || w == 0 || h == 0) {
        printf("failed to decode %s from resources. using EngineTextures.dat\n", texName);
        return NULL;
    }
    dk2::CEngineSurface *surf = createSurf(w, h);
    int ro = getByteOffs(surf->fC_desc->_rmask);
    int go = getByteOffs(surf->fC_desc->_gmask);
    int bo = getByteOffs(surf->fC_desc->_bmask);
    int ao = getByteOffs(surf->fC_desc->_amask);
    if (ro < 0 || go < 0 || bo < 0 || ao < 0) {
        printf("invalid rgba mask %s in resources. using EngineTextures.dat\n", texName);
        return NULL;
    }
    uint8_t *line = (uint8_t *) surf->pixels;
    for (unsigned y = 0; y < h; ++y) {
        for (unsigned x = 0; x < w; ++x) {
            int r = rgba[y * w * 4 + x * 4 + 0];
            int g = rgba[y * w * 4 + x * 4 + 1];
            int b = rgba[y * w * 4 + x * 4 + 2];
            int a = rgba[y * w * 4 + x * 4 + 3];
            line[x * 4 + ro] = r;
            line[x * 4 + go] = g;
            line[x * 4 + bo] = b;
            line[x * 4 + ao] = a;
        }
        line += surf->lineWidth;
    }
    //  printf("loaded from resources %s\n", texName);
    return surf;
}


