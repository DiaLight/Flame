//
// Created by DiaLight on 07.10.2024.
//

#include "dk2/CBridge.h"
#include "dk2/CWorld.h"
#include "dk2/entities/CRoom.h"
#include "dk2/entities/data/MyRoomDataObj.h"
#include "dk2/entities/data/MyTerrainDataObj.h"
#include "dk2/world/map/MyMapElement.h"
#include "dk2/CEffect.h"
#include "dk2/CEffectElement.h"
#include "dk2/CLight.h"
#include "dk2/MyFoundThingResult.h"
#include "dk2/entities/CPhysicalThing.h"
#include "dk2/entities/CMovingThing.h"
#include "dk2/entities/CPlayer.h"
#include "dk2/entities/player/MyTaskStack.h"
#include "dk2/entities/CDoor.h"
#include "dk2/entities/CTrap.h"
#include "dk2/CBridgeCmd.h"
#include "dk2/sound/TbSysCommand_StopHandle.h"
#include "dk2_globals.h"
#include "dk2_functions.h"
#include "patches/micro_patches.h"
#include "patches/logging.h"
#include "dk2/resources/file/MyFile.h"
#include "dk2/math/vec.h"
#include "dk2/math/q12_utils.h"

void dk2::CBridge::sub_43E320(
        unsigned int a2_x,
        unsigned int a3_y,
        MyTerrainDataObj *a4,
        CEngineStaticMeshDataArrays *a5_arrays) {
    CWorld *f14_cworld = this->f0_pGameSession->pWorld;
    MyMapElement *v7_mapElem = f14_cworld->getMapElem(a2_x, a3_y);
    int v11_bool1 = this->v_fDC(a2_x, a3_y);
    int v8_bool2 = 0;
    BOOL v9_bool3 = CCamera_sub_44DB70(this->camera._mode);
    BOOL v12_bool3 = v9_bool3;
    if ((v7_mapElem->_playerIdFFF & 0x2000) == 0 && !v11_bool1 && !v9_bool3) {
        if ((v7_mapElem->flags_and_burnLevel & 0x40) != 0) {
            if ((g_MyTerrainDataObj_arr[v7_mapElem->arr6DA4A8_idx]->_flags & 0x1000000) != 0) {
                v8_bool2 = 1;
            } else {
                a4 = f14_cworld->v_f70_508DD0_getTerrainDataObj(38);
                v8_bool2 = 1;
            }
        } else {
            a4 = f14_cworld->v_f70_508DD0_getTerrainDataObj(27);
            v8_bool2 = 1;
        }
    }
    if ((a4->_flags & 0x10) != 0) {
        if ((v7_mapElem->_playerIdFFF & 0x2000) != 0 || v11_bool1 || v12_bool3)
            this->sub_443610(a2_x, a3_y, v7_mapElem, a4, a5_arrays);
    } else {
        this->sub_43E860(a2_x, a3_y, v8_bool2, a4, a5_arrays);
    }
}


void dk2::CBridge::sub_443610(
        int a2_x,
        unsigned int a3_y,
        MyMapElement *a4,
        MyTerrainDataObj *a5,
        CEngineStaticMeshDataArrays *a6_arrs) {
    CRoom *v7_room = a4->getRoom();
    {  // patch
        if(v7_room == nullptr) {
            return;  // fix
        }
    }
    MyRoomDataObj *f19_pRoomDataObj = v7_room->pRoomDataObj;
    switch (f19_pRoomDataObj->someTy) {
        case 1: {
            CEngineStaticMeshData *v10 = &a6_arrs->field_1B4_CEngineStaticMeshData_arr[a6_arrs->field_2E8_CEngineStaticMeshData_count];
            v10->field_0_MyMeshResourceHolder_idx = f19_pRoomDataObj->f1B.idx;
            v10->field_4_mat3x3f_idx = 0;
            v10->byte_8_vec3b.x = 0;
            v10->byte_8_vec3b.y = 0;
            v10->byte_8_vec3b.z = 0;
            v10->field_C_flags = 0;
            v10->f10 = -1;
            v10->field_11_scale = 0;
            v10->field_15_eos = 0;
            if ((a5->_flags & 0x20000000) != 0) {
                Vec3ub *p_byte_8_vec3b = &a6_arrs->field_1B4_CEngineStaticMeshData_arr[a6_arrs->field_2E8_CEngineStaticMeshData_count].byte_8_vec3b;
                p_byte_8_vec3b->x = a5->_vec.x;
                p_byte_8_vec3b->y = a5->_vec.y;
                p_byte_8_vec3b->z = a5->_vec.z;
            }
            ++a6_arrs->field_2E8_CEngineStaticMeshData_count;
            this->sub_444F10(a2_x, a3_y, a5, v7_room, a6_arrs);
            break;
        }
        case 2:
            this->sub_443910(a2_x, a3_y, a5, v7_room, a6_arrs);
            break;
        case 3:
            this->sub_446140(a2_x, a3_y, a5, v7_room, a6_arrs);
            break;
        case 4:
            this->sub_446210(a2_x, a3_y, a5, v7_room, a6_arrs);
            break;
        case 5:
            this->sub_444970(a2_x, a3_y, a5, v7_room, a6_arrs);
            this->sub_444F10(a2_x, a3_y, a5, v7_room, a6_arrs);
            break;
        case 7:
            this->sub_443F20(a2_x, a3_y, a5, v7_room, a6_arrs);
            this->sub_444F10(a2_x, a3_y, a5, v7_room, a6_arrs);
            break;
        case 8:
            if ((v7_room->destroyed & 1) != 0)
                this->sub_4463B0(a2_x, a3_y, a5, v7_room, a6_arrs);
            else
                this->sub_4462E0(a2_x, a3_y, a5, v7_room, a6_arrs);
            break;
        case 9:
        case 0xC:
            this->sub_4464C0(a2_x, a3_y, a5, v7_room, a6_arrs);
            this->sub_444F10(a2_x, a3_y, a5, v7_room, a6_arrs);
            break;
        case 0xA:
            this->sub_446640(a2_x, a3_y, a5, v7_room, a6_arrs);
            break;
        case 0xB:
            this->sub_446800(a2_x, a3_y, a4, a5, v7_room, a6_arrs);
            break;
        case 0xD:
            this->sub_446800(a2_x, a3_y, a4, a5, v7_room, a6_arrs);
            this->sub_444F10(a2_x, a3_y, a5, v7_room, a6_arrs);
            break;
        default:
            return;
    }
}

dk2::MySurface * dk2::CBridge::loadPng(const char *name) {
    this->surf.lpSurface = NULL;

    char file_buf[sizeof(MyFile)];
    MyFile& file = *(MyFile*) file_buf;
    file.constructor_empty();

    int status = -1;
    TbGraphicFileLoader* loader = NULL;
    int try_level = 0;
    if (this->pngPrefix_2635[0]) {
        sprintf(CBridge_instance.resourcePath, "%s%s", this->pngPrefix_2635, name);
        loader = MyFile_openImage(&file, &MyResources_instance.engineTexturesFileMan, CBridge_instance.resourcePath, MyResources_instance.gameCfg.fun_55D540());
    }
    if (!loader) {
        loader = MyFile_openImage(&file, &MyResources_instance.engineTexturesFileMan, name, MyResources_instance.gameCfg.fun_55D540());
    }
    if (loader) {
        if (*loader->readHeader(&status, &file, &this->surf) >= 0) {
            MyFileContent_instance.resize(this->surf.size.h * this->surf.lPitch);
            this->surf.lpSurface = MyFileContent_instance.buf;
            if (*loader->readBody(&status, &this->surf, &file, NULL) >= 0) {
                try_level = -1;
                file.destructor();
                return &this->surf;
            }
        }
    }
    sprintf(g_temp_string, "Unable to load Bitmap Resource, '%s'. Continue will use 'NoTexture'", name);
    patch::log::dbg(g_temp_string);
    loader = MyFile_openImage(&file, &MyResources_instance.engineTexturesFileMan, "NoTexture", MyResources_instance.gameCfg.fun_55D540());
    if (loader) {
        if (*loader->readHeader(&status, &file, &this->surf) >= 0) {
            MyFileContent_instance.resize(this->surf.size.h * this->surf.lPitch);
            this->surf.lpSurface = MyFileContent_instance.buf;
            if (*loader->readBody(&status, &this->surf, &file, NULL) >= 0) {
                try_level = -1;
                file.destructor();
                return &this->surf;
            }
        }
    }
    MyWindow_log_printf(&MyWindow_instance, "Unable to Load Bitmap Resource, '%s'\n", name);
    try_level = -1;
    file.destructor();
    return NULL;
}

namespace dk2 {

    void call_CRenderInfo_fun_4B45B0(CRenderInfo *p_f44_renderInfo, int v79) {
        p_f44_renderInfo->fun_4B45B0(CWorld_instance.RedTexture_texIdx, 0, v79);
        p_f44_renderInfo->r48 = -1;
        p_f44_renderInfo->g49 = -1;
        p_f44_renderInfo->b4A = -1;
    }
    void call_TbSysCommand_StopHandle(int *pstatus, uint32_t f3C2) {
        char v110_buf[sizeof(TbSysCommand_StopHandle)];
        TbSysCommand_StopHandle &v110 = *(TbSysCommand_StopHandle *) v110_buf;
        *(void **) &v110 = TbSysCommand_StopHandle::vftable;
        v110.f4 = f3C2;
        g_MySound_ptr->v_fun_567A40(pstatus, &v110);
    }
}

int dk2::CBridge::updateCameraState(UpdateCameraStateArgs *arg0) {
    this->curUpdateCamState2629 = *arg0;
    if (this->updateCameraState2621.gameTick278_last + 4 < this->curUpdateCamState2629.gameTick278_last)
        this->updateCameraState2621 = *arg0;

    this->float_obj_thing.init4(getTimeMs());

    {
        int v4 = 205 * g_initTimeDelta / 14 + 50;
        if (v4 < 50) v4 = 50;
        if (v4 > 255) v4 = 255;
        g_byte69752C = v4;
    }

    CWorld *f14_pWorld = this->f0_pGameSession->pWorld;

    if (MyResources_instance.gameCfg.useFe_playMode == 3) {
        unsigned int v105 = 16;
        do {
            unsigned int v6 = this->x13CB + 1;
            this->x13CB = v6;
            if (v6 >= this->MyCMapFlags.cmap_size.w || this->y13CF >= this->MyCMapFlags.cmap_size.h) {
                int f13CF_y13CF = this->y13CF;
                this->x13CB = 0;

                unsigned int v8 = f13CF_y13CF + 1;
                this->y13CF = v8;
                if (!this->MyCMapFlags.cmap_size.w || v8 >= this->MyCMapFlags.cmap_size.h)
                    this->y13CF = 0;
            }

            unsigned __int16 v9 = this->v_fBC_getPlayerId();
            Pos2us v104p{(uint16_t) this->x13CB, (uint16_t) this->y13CF};
            unsigned __int8 v11 = ((CPlayer *) sceneObjects[v9])->taskStack->sub_508290(&v104p);
            if ((f14_pWorld->v_getMapElem(this->x13CB, this->y13CF)->_playerIdFFF & 0x2000) != 0) {
                uint16_t PFEffectId = *this->MyCMapFlags.getPFEffectId(this->x13CB, this->y13CF);

                int v13 = (PFEffectId >> 13) & 1;
                if (v11 == 1 || v11 == 2) {
                    if (!v13)
                        this->fun_43D9B0(this->x13CB, this->y13CF, this->x13CB, this->y13CF, 1);
                } else if (v13) {
                    this->fun_43D9B0(this->x13CB, this->y13CF, this->x13CB, this->y13CF, 0);
                }
            }
            --v105;
        } while (v105);
    }
    if (this->f3BC)
        sceneEffects[this->f3BC]->renderInfo.fun_4B3AD0();
    unsigned int v14 = 0;

    int try_level;
    do {
        if (f14_pWorld->v_fun_510210(v14)) {
            AABB v108_;
            f14_pWorld->v_fun_510230(&v108_, v14);

            CBridgeCmd cmd2;
            cmd2.cmd = 6;
            ((uint16_t *) &cmd2.a1)[0] = v108_.minX;
            ((uint16_t *) &cmd2.a1)[1] = v108_.minY;
            ((uint16_t *) &cmd2.a2)[0] = LOWORD(v108_.maxX) - LOWORD(v108_.minX) + 1;
            ((uint16_t *) &cmd2.a2)[1] = LOWORD(v108_.maxY) - LOWORD(v108_.minY) + 1;
            cmd2.a3 = 0;

            try_level = 0;
            this->v_f28_handleBridgeCmd(&cmd2);
            try_level = -1;
        }
        ++v14;
    } while (v14 < 4);
    int minX_ = this->field_C.minX;
    int minY_ = this->field_C.minY;
    Vec3f v108i;
    v108i.x = minX_;
    v108i.y = minY_;
    v108i.z = this->field_C.maxX;
    int maxY_ = this->field_C.maxY;

    int v19 = this->field_20.minX;

    int v110_v = v19;
    int v111_v = this->field_20.minY;
    int maxX = this->field_20.maxX;

    int v20 = this->field_20.maxY;
    if ((v19 != maxX || v111_v != v20) && (v19 != minX_ || maxX != v108i.z || v111_v != minY_ || v20 != maxY_)) {
        __int16 v22 = v20 + 1;
        if (f14_pWorld->v_getCMapHeight_508FB0() < v20 + 1)
            v22 = f14_pWorld->v_getCMapHeight_508FB0();

        int v23 = maxX + 1;

        __int16 v24;
        if (f14_pWorld->v_getCMapWidth_508FA0() >= v23)
            v24 = v23;
        else
            v24 = f14_pWorld->v_getCMapWidth_508FA0();

        CBridgeCmd cmd;
        cmd.cmd = 6;
        ((uint16_t *) &cmd.a1)[0] = (v110_v - 1) & ((v110_v - 1 < 0) - 1);
        ((uint16_t *) &cmd.a1)[1] = v111_v - 1 < 0 ? 0 : v111_v - 1;
        ((uint16_t *) &cmd.a2)[0] = v24 - ((v110_v - 1) & ((v110_v - 1 < 0) - 1));
        ((uint16_t *) &cmd.a2)[1] = v22 - (v111_v - 1 < 0 ? 0 : v111_v - 1);
        cmd.a3 = 0;

        try_level = 1;
        this->v_f28_handleBridgeCmd(&cmd);
        minY_ = v108i.y;
        minX_ = v108i.x;
        this->field_1C = 0;
        this->field_5A = 0;
        try_level = -1;
    }
    if (minX_ != v108i.z || minY_ != maxY_) {
        int v26 = maxY_ + 1;
        if (v26 >= f14_pWorld->v_getCMapHeight_508FB0())
            v26 = (uint16_t) f14_pWorld->v_getCMapHeight_508FB0();
        int v104i = v108i.z + 1;

        unsigned __int16 v28;
        if (v104i >= f14_pWorld->v_getCMapWidth_508FA0())
            v28 = f14_pWorld->v_getCMapWidth_508FA0();
        else
            v28 = v104i;

        CBridgeCmd cmd;
        ((uint16_t *) &cmd.a1)[0] = (minX_ - 1) & ((minX_ - 1 < 0) - 1);
        ((uint16_t *) &cmd.a1)[1] = minY_ - 1 < 0 ? 0 : minY_ - 1;
        ((uint16_t *) &cmd.a2)[0] = v28 - ((uint16_t *) &cmd.a1)[0];
        ((uint16_t *) &cmd.a2)[1] = v26 - ((uint16_t *) &cmd.a1)[1];
        ((uint16_t *) &cmd.a3)[0] = 0;
        ((uint16_t *) &cmd.a3)[1] = 0;
        cmd.cmd = 6;

        try_level = 2;
        this->v_f28_handleBridgeCmd(&cmd);
        try_level = -1;
    }
    if (!sceneObjectsPresent[this->f30_tagId30])
        this->f30_tagId30 = 0;
    if (getTimeMs() > this->timeMs1397 + 200) {
        DWORD v30 = getTimeMs();
        int v31 = this->f139B;
        this->timeMs1397 = v30;
        this->f139B = v31 == 0;
    }
    if (this->f139F) {
        if (this->f0_pGameSession->gameTick > this->f13A3) {
            this->f139F = 0;
            this->f13A3 = 0;
        }
        __int16 v33 = this->f13BB;
        __int16 v35 = this->f13B7;

        CBridgeCmd cmd;
        cmd.cmd = 6;
        ((uint16_t *) &cmd.a1)[0] = v35;
        ((uint16_t *) &cmd.a1)[1] = v33;
        ((uint16_t *) &cmd.a2)[0] = this->f13BF - v35;
        ((uint16_t *) &cmd.a2)[1] = this->f13C3 - v33;
        cmd.a3 = 0;

        try_level = 3;
        this->v_f28_handleBridgeCmd(&cmd);
        try_level = -1;
    }
    MyGameSession *f0_pGameSession = this->f0_pGameSession;
    int v104i2 = 0;

    CDefaultPlayerInterface *fC_pPlayer = f0_pGameSession->pPlayer;
    if (fC_pPlayer)
        v104i2 = fC_pPlayer->v_fun_4096B0();
    unsigned __int16 f30_tagId30 = this->f30_tagId30;

    Vec3i f16_pos;
    memset(&f16_pos, 0, sizeof(f16_pos));

    if (f30_tagId30) {
        CPhysicalThing *v40 = (CPhysicalThing *) sceneObjects[f30_tagId30];
        f16_pos = v40->f16_pos;
        int fE_type = v40->fE_type;
        if (fE_type == 0 || fE_type == 3 || fE_type == 4) {
            MyGameSession *v42 = this->f0_pGameSession;
            unsigned int v45 = 3 * v42->gameTicksPerSecond;
            v40->field_34 = (v45 >> 2) + v42->pWorld->getGameTick();
        }
    }

    CBridge *f10_pBridge = this->f0_pGameSession->pBridge;
    int v47 = f10_pBridge->v_fCC_getCameraMode();
    if (v47 != 1) {
        if (v47 == 2 || v47 == 10 && !MyResources_instance.gameCfg.useFe3d) {
            CCamera *v56 = this->v_fD0_getCamera();
            Vec3q12 v108 = v56->location + v56->locationOffset;
            f16_pos.y = v108.y.value;
            f16_pos.x = v108.x.value;
            f16_pos.z = 4608;
            MyMapElement *v57 = f14_pWorld->v_getMapElem(v108.x.value >> 12, v108.y.value >> 12);

            unsigned int v58 = -1;

            CLight *v117 = 0;

            unsigned int v60 = v57 - g_dword6DA49C;
            unsigned int v59 = v60 / g_dword6DA490;
            unsigned int v105 = v60 % g_dword6DA490 - 1;

            int v110_ = v60 % g_dword6DA490 + 1;
            if (v105 <= v110_) {
                unsigned int v118 = v59 - 1;
                unsigned int v115 = v59 + 1;
                do {
                    unsigned int v61 = v118;
                    unsigned int v107 = v118;
                    if (v118 <= v115) {
                        while (true) {
                            if (f14_pWorld->v_testCoordsInBounds_509090(v105, v61)) {
                                unsigned __int16 v62 = *this->MyCMapFlags.getPFEffectId(v105, v107) & 0x1FFF;
                                if (v62) {
                                    __int16 v64;
                                    do {
                                        CLight *v63;
                                        if (v62)
                                            v63 = (CLight *) sceneEffects[v62];
                                        else
                                            v63 = 0;
                                        v64 = v63->field_2;
                                        if (v63->fF0_type == 2) {
                                            int dword_134 = v63->dword_134;
                                            if ((dword_134 & 0x10) != 0 && (dword_134 & 0x4000) != 0) {
                                                unsigned int v66 = v63->fD2_pos.sub_43C260((Vec3i *) &v108);
                                                if (v66 < v58) {
                                                    v58 = v66;
                                                    v117 = v63;
                                                }
                                            }
                                        }
                                        v62 = v64;
                                    } while (v64);
                                }
                            }
                            if (++v107 > v115)
                                break;
                            v61 = v107;
                        }
                    }
                    ++v105;
                } while (v105 <= v110_);
            }
            if (!v117) {
                int v116;
                call_TbSysCommand_StopHandle(&v116, this->f3C2);
                this->f3C2 = 0;
            } else {
                int v67 = g_MySound_ptr->v_CSoundSystem_fun_5678F0(
                        this->f3C2,
                        this->f3BE,
                        251,
                        &v117->fD2_pos);
                this->f3C2 = v67;
                if (v67)
                    this->f3C2 = g_MySound_ptr->v_fun_567A10(v67, 15, 100 - ((100 * v58) >> 14));
            }
        } else if (v47 != 7) {
            if (this->f3C2) {
                int status;
                call_TbSysCommand_StopHandle(&status, this->f3C2);
                this->f3C2 = 0;
            }
            Pos2i *MousePos = MyWindow_instance.getMousePos();
            if (MyResources_instance.gameCfg.useFe3d) {
                MyFoundThingResult a2;
                if (this->v_f4C_findThingAtLoc(MousePos->x, MousePos->y, &a2) != 0) {
                    if (a2._bool) {
                        f16_pos.x = a2.x_if12.value;
                        f16_pos.y = a2.y_if12.value;
                        f16_pos.z = 0x1E00;
                    } else {
                        f16_pos.x = a2.x_if12.value;
                        f16_pos.y = a2.y_if12.value;
                        f16_pos.z = 0x1C00;
                    }
                }
            } else {
                MyFoundThingResult a2;
                if (this->v_f48_actWithObjUnderHand(MousePos->x, MousePos->y, v104i2, &a2) != 0) {
                    if (a2._bool) {
                        f16_pos.x = a2.x_if12.value;
                        f16_pos.y = a2.y_if12.value;
                        f16_pos.z = 0x1E00;
                    } else {
                        f16_pos.x = a2.x_if12.value;
                        f16_pos.y = a2.y_if12.value;
                        f16_pos.z = 0x1C00;
                    }
                }
            }
        }
    } else {
        int v49 = f14_pWorld->v_getMEPlayerTagId();
        unsigned __int16 v50 = ((CPlayer *) f14_pWorld->v_getCTag_508C40(v49))->creaturePossessed;
        if (v50) {
            CThing *v51 = (CThing *) sceneObjects[v50];
            f16_pos.x = v51->f16_pos.x;
            f16_pos.y = v51->f16_pos.y;
            f16_pos.z = 4608;
        }

        if (this->f3C2) {
            int status;
            call_TbSysCommand_StopHandle(&status, this->f3C2);
            this->f3C2 = 0;
        }
    }

    if (this->sceneEffect33E) {
        CEffectElement *v68 = (CEffectElement *) sceneEffects[this->sceneEffect33E];
        CPlayer *v69 = (CPlayer *) sceneObjects[this->v_fBC_getPlayerId()];
        if ((v69->playerFlags & 0x80000) != 0 || v69->status) {
            v68->renderInfo._flags2 &= ~1u;
            AABB v119;
            memset(&v119, 0, sizeof(v119));
            this->sub_44E130(&v119, 0);
        } else {
            CCamera *v70 = this->v_fD0_getCamera();
            int w = this->MyCMapFlags.cmap_size.w;
            int h = this->MyCMapFlags.cmap_size.h;
            if (v70->fun_44D620()
                && f16_pos.x >= 0
                && f16_pos.y >= 0
                && (f16_pos.x >> 12 < w)
                && (f16_pos.y >> 12 < h)) {
                if (f16_pos.x < 0
                    || (f16_pos.x & 0xFFFFF000) == 0
                    || f16_pos.y < 0
                    || (f16_pos.y & 0xFFFFF000) == 0
                    || (f16_pos.x >> 12 >= w - 1)
                    || f16_pos.y >> 12 >= h - 1) {
                    v68->renderInfo._flags2 &= ~1u;
                    v68->word_111 = 0;
                    v68->f113 = 0;
                    v68->f115 = 0;
                } else {
                    v68->init(&f16_pos);
                    if (f10_pBridge->field_4A.minX == f10_pBridge->field_4A.maxX
                        && f10_pBridge->field_4A.minY == f10_pBridge->field_4A.maxY
                        && this->field_C.minX == this->field_C.maxX
                        && this->field_C.minY == this->field_C.maxY) {
                        v68->renderInfo._flags2 ^= (v68->renderInfo._flags2 ^ v104i2) & 1;
                    } else {
                        v68->renderInfo._flags2 &= ~1u;
                    }
                    if ((f14_pWorld->v_getMapElem_2(&f16_pos)->_playerIdFFF & 0x2000) != 0) {
                        v68->word_111 = 511;
                        v68->f113 = 511;
                        v68->f115 = 511;
                    } else {
                        v68->word_111 = 0;
                        v68->f113 = 0;
                        v68->f115 = 0;
                    }
                    if (this->f32__allowToDrop)
                        v68->renderInfo._allowToDrop = 63;
                    else
                        v68->renderInfo._allowToDrop = 31;
                }
            } else {
                v68->renderInfo._flags2 &= ~1u;
            }
        }
    }
    int v103 = -1;
    uint16_t v104t = 0;
    int v117 = 0;
    unsigned int v118 = 0;
    unsigned int f10_bool = 0;
    unsigned int v115 = 0;
    unsigned int v105 = 0;
    unsigned int v107 = 0;
    uint16_t w_x = this->f30_tagId30;
    try_level = 4;

    int v116;
    if (w_x) {
        CPhysicalThing *v72 = (CPhysicalThing *) sceneObjects[w_x];
        if (v72->v_f34()) {
            CWorldEntry *f28_pWorldEntry = v72->renderInfo.pWorldEntry;
            v104t = w_x;
            if ((f28_pWorldEntry->u.weB_flags & 0x10000) != 0) {
                v110_v = *v72->renderInfo.sub_43C240(&v116);
                v72->renderInfo._rangVal1 = 4095;
                v72->renderInfo._randVal2 = 4095;
            }

            v103 = *(DWORD *) &v72->renderInfo.r48;
            f10_bool = (v72->renderInfo.f4D >> 1) & 1;
            v117 = v72->renderInfo.f73;
            v105 = v72->renderInfo.f4D & 1;
            v107 = v72->renderInfo.f7B;
            v115 = v72->renderInfo.f4C >> 7;
            v118 = v72->renderInfo.f77;

            int v79 = 0;
            if (v72->fE_type == 4 && ((CDoor *) v72)->typeId == 8) v79 = 1;
            if (v72->fE_type == 3 && ((CTrap *) v72)->typeId == 8) v79 = 1;
            call_CRenderInfo_fun_4B45B0(&v72->renderInfo, v79);
        }
    }

    DWORD v81_timeMs = getTimeMs();
    int v84 = 0;
    int v83 = 0;
    if (this->f1323 + 50 < v81_timeMs) {
        v84 = 1;
        v83 = (v81_timeMs - this->f1323) / 0x32;
        this->f1323 = this->f1323 + 50 * v83;
    }
    if (v84 && !MyResources_instance.video_settings.sine_wave_water) {
        this->Obj448C20.emulateWater1(
                (signed int) (this->camera.locationOffset.x.value + this->camera.location.x.value) >> 12,
                (signed int) (this->camera.location.y.value + this->camera.locationOffset.y.value) >> 12);
        this->Obj448C20.emulateWater2();
    }
//  ret_void_0args_0((void *)this->field_131F);
    this->camera.sub_44BED0(arg0);
    if (v84) {
        for (CEffect *i = this->effect_list; i; i = i->next) {
            if (!i->sub_434E80(arg0, v83))
                i->v_field_8();
        }
        for (CLight *j = this->light_list; j; j = j->f13c_next) {
            if (!j->sub_43A2E0())
                j->v_field_8();
        }

        for(CEffect *cur = this->effect_list; cur;) {
            CEffect *next = cur->next;
            if (cur->v_field_4() && !cur->elements_list)
                this->v_f9C(cur);
            cur = next;
        }
        for(CLight *cur = this->light_list; cur;) {
            CLight *next = cur->f13c_next;
            if (cur->v_field_4())
                this->v_fA8(cur);
            cur = next;
        }
        this->cpp_441110();
    }

    int v91 = this->f1327;
    Vec3q12 v108;
    v108.x.value = 0;
    v108.y.value = 0;
    this->f1327 = v91 + 200;
    if (v91 + 200 > 0)
        this->f1327 = 0;
    v108.z.value = -v91;

    int v92 = this->f132B;
    if (v92 > 0) {
        this->f132B = v92 - 1;
        unsigned int v93 = randomInt(0xC8u, &this->f72, "D:\\Dev\\DK2\\Projects\\Source\\Game\\Bridge.cpp", 4070);
        v108.x.value = v108.x.value + v93 - 100;
        unsigned int v94 = randomInt(0xC8u, &this->f72, "D:\\Dev\\DK2\\Projects\\Source\\Game\\Bridge.cpp", 4071);
        v108.y.value = v108.y.value + v94 - 100;
    }
    this->camera.setLocOffset(&v108);
    v116 = this->pCPCEngineInterface->v_f2C_updateCameraState(arg0);
    if (v104t) {
        CPhysicalThing *v95 = (CPhysicalThing *) sceneObjects[v104t];
        if (v95->v_f34()) {
            if ((v95->renderInfo.pWorldEntry->u.weB_flags & 0x10000) != 0) {
                v95->renderInfo._rangVal1 = v110_v;
                v95->renderInfo._randVal2 = v110_v;
            }
            bool v98 = f10_bool == 0;
            *(DWORD *) &v95->renderInfo.r48 = v103;
            if (!v98) {
                v95->renderInfo.sub_4B4580(v117, v107);
            }
            unsigned int v99 = v115;
            if (v115 || v105)
                v95->renderInfo.fun_4B45B0(v118, v107, v105);
            if (!f10_bool && !v99)
                v95->renderInfo.fun_4B4610();
        }
    }
    int v100 = this->f96;
    this->updateCameraState2621 = this->curUpdateCamState2629;
    this->f96 = v100 + 1;
    this->timeMs = getTimeMs();
    return v116;
}

