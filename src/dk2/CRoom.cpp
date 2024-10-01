//
// Created by DiaLight on 30.09.2024.
//

#include "dk2/entities/CRoom.h"
#include "room_type.h"
#include "dk2/entities/CPlayer.h"
#include "dk2_globals.h"
#include "dk2/CBridgeCmd.h"
#include "dk2/entities/data/MyRoomDataObj.h"
#include "dk2/entities/data/MyTerrainDataObj.h"
#include "dk2/world/map/MyMapElement.h"
#include "tools/bug_hunter.h"
#include "patches/micro_patches.h"


namespace dk2 {

    MyMapElement *getMapElem(Pos2ub &loc) {
        CMap &cmap = g_CWorld_ptr->cmap;
        return &cmap.mapElements[loc.x + loc.y * cmap.width];
    }

    void testFire(CRoom *_this) {
        MyMapElement *mapElem;
        for (Pos2ub loc = _this->firstSlab; loc.x || loc.y; loc = mapElem->nextSlab) {
            mapElem = getMapElem(loc);
            uint8_t burnLevel = (mapElem->flags >> 1) & 0xF;
            if ((mapElem->_playerId & 0x1000) == 0) continue;
            if (burnLevel >= 9) continue;
            mapElem->roomSetBurnLevel(burnLevel + 1);
            burnLevel = (mapElem->flags >> 1) & 0xF;
            if (burnLevel == 8) {
                *(DWORD *) _this->field_49_union_start = 1;  // FlagToBurn
                mapElem->roomSetBurnLevel(9);
            } else if (burnLevel == 4) {
                CBridgeCmd v21_cmd;
                v21_cmd.a1 = loc.x | (loc.y << 16);
                v21_cmd.a2 = 0;
                v21_cmd.a3 = 0;
                v21_cmd.cmd = 3;
                int v22_try;
                v22_try = 0;
                g_CWorld_ptr->execCBridgeCmd(&v21_cmd);
                v22_try = -1;
            }
        }
    }
}

int dk2::CRoom::tickWoodenBridge() {
    unsigned int v3 = (this->f0_tagId + g_CWorld_ptr->getGameTick()) % (5 * Obj6F2550_instance.gameTick);
    if (v3 == 0) { // fire tick
        testFire(this);
    }

    // if nothing to burn then exit
    if (*(DWORD *) this->field_49_union_start != 1) return 1;

    // tick remove mapElem by burning
    __int16 v8_unkIdx = this->pRoomDataObj->f421;
    bool anyBridgesBurned = false;
    int burnedCount = 0;
    MyMapElement *mapElem;
    for (Pos2ub pos = this->firstSlab; pos.x || pos.y; pos = mapElem->nextSlab) {
        mapElem = getMapElem(pos);
        if ((mapElem->_playerId & 0x1000) == 0) continue;
        uint8_t burnLevel = (mapElem->flags >> 1) & 0xF;
        if (burnLevel != 9) continue;
        auto *player = (CPlayer *) sceneObjects[this->playerId];
        if (!player->fun_4C5DB0(pos.x, pos.y, 0)) continue;

        anyBridgesBurned = true;
        ++burnedCount;
        mapElem->roomSetBurnLevel(0);
        if (v8_unkIdx) {
            CBridgeCmd v21_cmd;
            v21_cmd.a1 = (pos.x << 12) + 2048;
            v21_cmd.a2 = (pos.y << 12) + 2048;
            v21_cmd.a3 = 0;
            __int16 v14 = 0;
            Pos2ub v19_bridgeLoc;
            g_CWorld_ptr->v_sub_509580(v8_unkIdx, this->playerId, (int) &v21_cmd, (int) &v14, (int) &v19_bridgeLoc);
        }
        if (burnedCount == 8) break;
    }
    if (!anyBridgesBurned) *(DWORD *) this->field_49_union_start = 0; // FlagToBurn
    return 1;
}

unsigned int dk2::CMap::attachToRoom(
        int a2_x,
        int a3_y,
        unsigned __int16 a4_roomObjId,
        __int16 a5_playerId,
        int a6,
        int a7) {
    int v8_y = a3_y;
    MyMapElement *v9_mapElem = &this->mapElements[a2_x + a3_y * this->width];
    int v10_flags = g_MyTerrainDataObj_arr[v9_mapElem->arr6DA4A8_idx]->_flags;
    if ((v10_flags & 0x80u) == 0) {
        if ((v10_flags & 0x100) != 0)
            v9_mapElem->_playerId |= 0x1000u;
    } else {
        v9_mapElem->_playerId &= ~0x1000u;
    }
    int typeId = ((CRoom *) sceneObjects[a4_roomObjId])->typeId;
    if(wooden_bridge_burn_fix::enabled) {
        if (typeId != CRoom_typeId_WoodenBridge) {  // ignore reset burn level at attach cell to room
            v9_mapElem->roomSetBurnLevel(0);
        }
    } else {
        v9_mapElem->roomSetBurnLevel(0);
    }
    v9_mapElem->fun_4559D0(a5_playerId);
    MyRoomDataObj *v11_roomDataObj = this->world->v_fun_50D0B0(typeId);
    this->fun_44FC40(a2_x, v8_y, (int) v11_roomDataObj->f44E, v9_mapElem->_playerId & 0xFFF, 0, a7);
//    v9_mapElem->roomId = v9_mapElem->roomId ^ ((v9_mapElem->roomId ^ a4_roomObjId) & 0xFFF);
    v9_mapElem->roomId = (v9_mapElem->roomId & 0xF000) | (a4_roomObjId & 0xFFF);
    return this->sub_4522A0(a2_x, v8_y);
}

int dk2::MyRooms::sub_4ED1A0(
        int a2_x,
        int arg4_y,
        int a4_roomTypeId,
        __int16 a5_playerId,
        unsigned __int16 a6_roomObjId,
        BYTE *a7_pNearCountNeg,
        int a8) {
    if ((g_MyTerrainDataObj_arr[this->world->getMapElem(a2_x, arg4_y)->arr6DA4A8_idx]->_flags & 0x80) != 0) {
        int *p_y; // esi
        p_y = &g_deltaLocs[0].y;
        do {
            int v11 = a2_x + *(p_y - 1);
            int v12 = *p_y + arg4_y;
            CBridgeCmd bridgeCmd;
            bridgeCmd.a3 = -8192;
            bridgeCmd.a1 = (v11 << 12) + 2048;
            bridgeCmd.a2 = (v12 << 12) + 2048;
            bridgeCmd.cmd = 8;
            CWorld *f6_world = this->world;
            int v20_try = 0;
            f6_world->execCBridgeCmd(&bridgeCmd);
            v20_try = -1;
            p_y += 2;
        } while ((int) p_y < (int) 0x6BC374);
//        } while ( (int)p_y < (int)&dword_6BC374 );
    }
    CRoom *v19[4];
    memset(v19, 0, sizeof(v19));
    CRoom *a3 = 0;
    int v14 = this->sub_4ED320(a2_x, arg4_y, a4_roomTypeId, a5_playerId, a6_roomObjId, a7_pNearCountNeg, &a3, v19);
    if(wooden_bridge_burn_fix::enabled) {
        if(((BYTE) a4_roomTypeId) == CRoom_typeId_WoodenBridge) {
            CMap &map = this->world->cmap;
            map.mapElements[a2_x + arg4_y * map.width].roomSetBurnLevel(0);
        }
    }
    CRoom *v15 = a3;
    int arg4_ya = v14;
    if (!a3)
        return arg4_ya;
    if (a8 != 8) {
        a3->orientation = a8;
        v15 = a3;
    }
    v15->removeObject();
    this->fun_4ECEB0(a3, a2_x, arg4_y);
    this->fun_4EF5E0(a3);
    this->RoomManager_cpp_4EDFC0((int) a3);
    a3->sub_4E4480();
    if ((BYTE) a4_roomTypeId == 8 || (BYTE) a4_roomTypeId == 17 || (BYTE) a4_roomTypeId == 22)
        ((CPlayer *) sceneObjects[(unsigned __int16) a5_playerId])->sub_4BA720(a2_x, arg4_y);
    return arg4_ya;
}


const char *CRoom_typeId_toString(int ty) {
    switch (ty) {
#define _CRoom_typeId_toString(id, pascalName) case CRoom_typeId_##pascalName: return #pascalName;
        CRoom_types(_CRoom_typeId_toString)
    }
    return "Unknown";
}
