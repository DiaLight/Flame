//
// Created by DiaLight on 07.10.2024.
//

#include "dk2/CBridge.h"
#include "dk2/CWorld.h"
#include "dk2/entities/CRoom.h"
#include "dk2/entities/data/MyRoomDataObj.h"
#include "dk2/entities/data/MyTerrainDataObj.h"
#include "dk2/world/map/MyMapElement.h"
#include "dk2_globals.h"
#include "dk2_functions.h"
#include "patches/micro_patches.h"

void dk2::CBridge::sub_43E320(
        unsigned int a2_x,
        unsigned int a3_y,
        MyTerrainDataObj *a4,
        CEngineStaticMeshDataArrays *a5_arrays) {
    CWorld *f14_cworld = this->f0_pMyProfiler->cworld;
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
            v10->field_0_MyMeshResourceHolder_idx = f19_pRoomDataObj->f1B.fF;
            v10->field_4_mat3x3f_idx = 0;
            v10->byte_8_vec3b.x = 0;
            v10->byte_8_vec3b.y = 0;
            v10->byte_8_vec3b.z = 0;
            v10->field_C_flags = 0;
            v10->f10 = -1;
            v10->field_11_scale = 0;
            v10->field_15_eos = 0;
            if ((a5->_flags & 0x20000000) != 0) {
                Vec3b *p_byte_8_vec3b = &a6_arrs->field_1B4_CEngineStaticMeshData_arr[a6_arrs->field_2E8_CEngineStaticMeshData_count].byte_8_vec3b;
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
