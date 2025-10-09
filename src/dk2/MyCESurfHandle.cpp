//
// Created by DiaLight on 10/9/2025.
//

#include "dk2/MyCESurfHandle.h"
#include "dk2/MyStringHashMap_MyCESurfHandle_entry.h"
#include "dk2/MyStringHashMap_entry.h"
#include "dk2_functions.h"
#include "dk2_globals.h"
#include "patches/external_textures.h"


void dk2::MyCESurfHandle::resolveSurface() {
    if (this->cesurf != nullptr) return;
    if ((this->reductionLevel_andFlags & 0x80) != 0) {
        this->create();
        return;
    }
    char *f0_name = MyStringHashMap_MyCESurfHandle_instance.entries.buf[this->mapIdx].name;
    char texName[256];
    sprintf(texName, "%sMM%d", f0_name, this->reductionLevel_andFlags & 7);
    int f24_reductionLevel = mydd_devTexture.reductionLevel;
    if (this->surfWidth8) {
        if (mydd_devTexture.reductionLevel <= (this->reductionLevel_andFlags & 7) || !this->nextByReduction) {
            this->cesurf = (CEngineSurface *) patch::external_textures::loadFlameTexture(texName);
            if (!this->cesurf) {  // patch
                this->cesurf = (CEngineSurface*) MyTextures_instance.loadCompressed(texName);
            }
            if (!this->cesurf) {
                int EntryIdx = ((MyStringHashMap *)&MyStringHashMap_MyCESurfHandle_instance)->getEntryIdx(f0_name);
                MyStringHashMap_MyCESurfHandle_instance.entries.buf[EntryIdx].value->loadPrescaled();
            }
        }
        return;
    }
    int v5 = MyTextures_instance.texNameToFileOffsetMap.getEntryIdx(texName);
    if ( v5 < 0 ) {
        this->loadPrescaled();
        return;
    }
    dk2::_fseek(
        MyTextures_instance.fileHandle,
        (int) MyTextures_instance.texNameToFileOffsetMap.entries.buf[v5].value,
        0);
    int width = -1;
    int height = -1;
    readFromFile(&width, 4u, 1u, MyTextures_instance.fileHandle);
    readFromFile(&height, 4u, 1u, MyTextures_instance.fileHandle);

    BOOL needsRescale = width < 16;
    unsigned __int8 height_ = height;
    if ( height < 16 ) needsRescale = 1;
    if ( width > 128 ) needsRescale = 1;
    if ( height > 128 ) needsRescale = 1;
    if ( needsRescale ) {
        this->loadPrescaled();
        return;
    }
    this->surfWidth8 = width;
    this->surfHeight8 = height_;
    this->createReduction();
    if (!f24_reductionLevel || !this->nextByReduction) {
        this->cesurf = (CEngineSurface *) patch::external_textures::loadFlameTexture(texName);
        if (!this->cesurf) { // patch
            this->cesurf = (CEngineSurface*) MyTextures_instance.loadCompressed(texName);
        }
    }
}
