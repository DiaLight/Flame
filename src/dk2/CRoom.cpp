//
// Created by DiaLight on 30.09.2024.
//

#include <set>
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
#include "dk2_functions.h"
#include "dk2_memory.h"


namespace dk2 {

    MyMapElement *getMapElem(Pos2ub &loc) {
        CMap &cmap = g_CWorld_ptr->cmap;
        return &cmap.mapElements[loc.x + loc.y * cmap.width];
    }

    void testFire(CRoom *_this) {
        MyMapElement *mapElem;
        for (Pos2ub loc = _this->firstSlab; loc.x || loc.y; loc = mapElem->nextSlab) {
            mapElem = getMapElem(loc);
            uint8_t burnLevel = (mapElem->flags_and_burnLevel >> 1) & 0xF;
            if ((mapElem->_playerIdFFF & 0x1000) == 0) continue;
            if (burnLevel >= 9) continue;
            mapElem->roomSetBurnLevel(burnLevel + 1);
            burnLevel = (mapElem->flags_and_burnLevel >> 1) & 0xF;
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
        if ((mapElem->_playerIdFFF & 0x1000) == 0) continue;
        uint8_t burnLevel = (mapElem->flags_and_burnLevel >> 1) & 0xF;
        if (burnLevel != 9) continue;
        auto *player = (CPlayer *) sceneObjects[this->playerId];
        if (!player->destroyRoom(pos.x, pos.y, 0)) continue;

        anyBridgesBurned = true;
        ++burnedCount;
        mapElem->roomSetBurnLevel(0);
        if (v8_unkIdx) {
            Vec3i pos2;
            pos2.x = (pos.x << 12) + 2048;
            pos2.y = (pos.y << 12) + 2048;
            pos2.z = 0;
            uint16_t v14_direction = 0;
            CEffect *effect;
            g_CWorld_ptr->v_sub_509580(v8_unkIdx, this->playerId, &pos2, &v14_direction, &effect);
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
        int a6_bool,
        int a7_bool2) {
    int v8_y = a3_y;
    MyMapElement *v9_mapElem = &this->mapElements[a2_x + a3_y * this->width];
    int v10_flags = g_MyTerrainDataObj_arr[v9_mapElem->arr6DA4A8_idx]->_flags;
    if ((v10_flags & 0x80u) == 0) {
        if ((v10_flags & 0x100) != 0)
            v9_mapElem->_playerIdFFF |= 0x1000u;
    } else {
        v9_mapElem->_playerIdFFF &= ~0x1000u;
    }
    int typeId = ((CRoom *) sceneObjects[a4_roomObjId])->typeId;
    if (wooden_bridge_burn_fix::enabled) {
        if (typeId != CRoom_typeId_WoodenBridge) {  // ignore reset burn level at attach cell to room
            v9_mapElem->roomSetBurnLevel(0);
        }
    } else {
        v9_mapElem->roomSetBurnLevel(0);
    }
    v9_mapElem->fun_4559D0(a5_playerId);
    MyRoomDataObj *v11_roomDataObj = this->world->v_f98_50D0B0_getMyRoomDataObj(typeId);
    this->tickSlab(a2_x, v8_y, (int) v11_roomDataObj->_terrainType, v9_mapElem->_playerIdFFF & 0xFFF, 0, a7_bool2);
    v9_mapElem->_roomIdFFF = (v9_mapElem->_roomIdFFF & 0xF000) | (a4_roomObjId & 0xFFF);
    return this->sub_4522A0(a2_x, v8_y);
}

int dk2::MyRooms::eventAttachAndReset(
        int a2_x,
        int arg4_y,
        int a4_roomTypeId,
        unsigned __int16 a5_playerId,
        unsigned __int8 a6_roomNum,
        int8_t *a7_pNearCountNeg,
        int a8) {
    if ((g_MyTerrainDataObj_arr[this->world->getMapElem(a2_x, arg4_y)->arr6DA4A8_idx]->_flags & 0x80) != 0) {
        int *p_y = &g_deltaLocs[0].y;
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
    CRoom *roomArr[4];
    memset(roomArr, 0, sizeof(roomArr));
    CRoom *a3_room = 0;
    int v14 = this->attachToNearForceOrCreate(a2_x, arg4_y, a4_roomTypeId, a5_playerId, a6_roomNum, a7_pNearCountNeg, &a3_room, roomArr);
    if (wooden_bridge_burn_fix::enabled) {
        if (((BYTE) a4_roomTypeId) == CRoom_typeId_WoodenBridge) {
            CMap &map = this->world->cmap;
            map.mapElements[a2_x + arg4_y * map.width].roomSetBurnLevel(0);
        }
    }
    CRoom *v15 = a3_room;
    int arg4_ya = v14;
    if (!a3_room)
        return arg4_ya;
    if (a8 != 8) {
        a3_room->orientation = a8;
        v15 = a3_room;
    }
    v15->removeObjectsInRoom();
    this->calcRoomWallAlignmentMap(a3_room, a2_x, arg4_y);
    this->calcSpecialTileOffset(a3_room);
    this->RoomManager_cpp_4EDFC0(a3_room);
    a3_room->tickChangeSize();
    if ((BYTE) a4_roomTypeId == 8 || (BYTE) a4_roomTypeId == 17 || (BYTE) a4_roomTypeId == 22)
        ((CPlayer *) sceneObjects[(unsigned __int16) a5_playerId])->updateOwnedArea(a2_x, arg4_y);
    return arg4_ya;
}

#define MaxRoomCount (override_max_room_count::limit * 7)  // 0x2A0

int dk2::MyRooms::createRooms(CWorld *a2_world) {
    DWORD *v3 = (DWORD *) dk2::operator_new(sizeof(CRoom) * MaxRoomCount + 4);  // 0x1BBA4
    CRoom *v4;
    if (v3) {
        v4 = (CRoom *) (v3 + 1);
        *v3 = MaxRoomCount;
        typedef void (*___for_each_construct_t)(char *, uint32_t, int, void (__thiscall *)(void *),
                                                void (__thiscall *)(void *));
        for_each_construct<CRoom>((char *) v3 + 4, MaxRoomCount);
    } else {
        v4 = nullptr;
    }
    this->CRoom_arr_p = v4;
    if (!v4)
        return 0;
    this->firstRoomId = 0;
    this->_nextRoomId = 0;
    this->changedAreaRoomList = 0;
    unsigned int i;
    for (i = 0; i < MaxRoomCount; ++i) {
        CRoom *v7 = &this->CRoom_arr_p[i];
        unsigned __int16 f0_tagId = v7->f0_tagId;
        v7->roomManagerNode.x = 0;
        v7->roomManagerNode.y = 0;
        CRoom *fA_CRoom_arr_p = this->CRoom_arr_p;
        fA_CRoom_arr_p[i].playerRoomListNodeX = 0;
        fA_CRoom_arr_p[i].playerRoomListNodeY = 0;
        CRoom *v10 = this->CRoom_arr_p;
        v10[i].changedAreaRoomListNode.x = 0;
        v10[i].changedAreaRoomListNode.y = 0;
        ((CRoom *) sceneObjects[f0_tagId])->roomManagerNode.y = this->_nextRoomId;
        if (this->_nextRoomId)
            ((CRoom *) sceneObjects[this->_nextRoomId])->roomManagerNode.x = f0_tagId;
        this->_nextRoomId = f0_tagId;
    }
    this->world = a2_world;
    g_CWorld_ptr = a2_world;
    g_MyRooms_pInstance = this;
    this->thingManager = 1;
    return 1;
}

int dk2::MyRooms::createRoom(
        int a2_roomTypeId,
        unsigned __int16 a3_playerId,
        unsigned __int16 *a4_pRoomObjId) {
    if (this->roomsCount >= MaxRoomCount)
        return 0;
    unsigned __int16 roomObjId;
    if (this->_forceSetSceneIdx) {
        roomObjId = this->_forceRoomSceneIdx;
        this->_forceSetSceneIdx = 0;
        this->_forceRoomSceneIdx = 0;
    } else {
        roomObjId = this->_nextRoomId;
    }
    if (!((CRoom *) sceneObjects[roomObjId])->init(a2_roomTypeId, a3_playerId))
        return 0;
    CRoom *v6 = (CRoom *) sceneObjects[roomObjId];
    // unlink X
    if (v6->roomManagerNode.x) {
        ((CRoom *) sceneObjects[((CRoom *) sceneObjects[roomObjId])->roomManagerNode.x])->roomManagerNode.y = v6->roomManagerNode.y;
    } else {
        this->_nextRoomId = v6->roomManagerNode.y;
    }
    // unlink Y
    if (((CRoom *) sceneObjects[roomObjId])->roomManagerNode.y) {
        ((CRoom *) sceneObjects[((CRoom *) sceneObjects[roomObjId])->roomManagerNode.y])->roomManagerNode.x = ((CRoom *) sceneObjects[roomObjId])->roomManagerNode.x;
    }
    CRoom *v7 = (CRoom *) sceneObjects[roomObjId];
    v7->roomManagerNode.x = 0;
    v7->roomManagerNode.y = 0;
    __int16 f10__nextRoomId = this->_nextRoomId;
    if (roomObjId == f10__nextRoomId)
        this->_nextRoomId = f10__nextRoomId - 1;
    // link to list
    ((CRoom *) sceneObjects[roomObjId])->roomManagerNode.y = this->firstRoomId;
    if (this->firstRoomId)
        ((CRoom *) sceneObjects[this->firstRoomId])->roomManagerNode.x = roomObjId;
    this->firstRoomId = roomObjId;
    this->roomsCount++;
    *a4_pRoomObjId = roomObjId;
    return 1;
}


int dk2::CPlayer::fun_4C5C30_buildRoom(
        int a2_x,
        int a3_y,
        int a4_roomTypeId,
        int a5_gameTick,
        int a6_bool,
        int a7_bool,
        int a8_orientation) {
    unsigned int v10_moneyCost = g_pCWorld->v_f98_50D0B0_getMyRoomDataObj(a4_roomTypeId)->moneyCost;
    if (!a6_bool && v10_moneyCost > this->money) return 0;
    if (!a7_bool) {
        int v11_playerId_and_roomTypeId = this->f0_tagId | (a4_roomTypeId << 16);
        if (!g_pCWorld->v_sub_509280(a2_x, a3_y, v11_playerId_and_roomTypeId, a4_roomTypeId))
            return 0;
    }
    uint8_t maxRoomLimit = 96;
    if (override_max_room_count::enabled) {
        maxRoomLimit = override_max_room_count::limit;
    }
    uint8_t numRoomsLeft = maxRoomLimit - this->numberOfRooms;
    int8_t roomsCountNeg;
    if (!g_pCWorld->rooms.eventAttachAndReset(
            a2_x,
            a3_y,
            a4_roomTypeId,
            this->f0_tagId,
            numRoomsLeft,
            &roomsCountNeg,
            a8_orientation))
        return 0;
    this->numberOfRooms += roomsCountNeg;
    if (a6_bool)
        return 1;
    this->moneyRoom_4BA420(-v10_moneyCost, 0, 0, 0);
    this->statictics.moneySpent += v10_moneyCost;
    if (g_pCWorld->getGameTick() == a5_gameTick)
        return 1;
    MyRoomDataObj *v12 = g_pCWorld->v_f98_50D0B0_getMyRoomDataObj(a4_roomTypeId);
    int v13 = g_pCWorld->v_f70_508DD0_getTerrainDataObj(v12->_terrainType)->f195;
    if (!v13)
        return 1;
    Vec3i v15_vec;
    v15_vec.x = (a2_x << 12) + 2048;
    v15_vec.y = (a3_y << 12) + 2048;
    v15_vec.z = 0;
    MySound_ptr->CSoundSystem::fun_5678F0(0, v13, 241, &v15_vec);
    return 1;
}

namespace dk2 {
    bool hasPlayerRoomWithTypeExcept(int x, int y, char typeId, __int16 playerId, std::set<int> &visited) {
        CMap &cmap = g_pCWorld->cmap;
        if(0 > x || x >= cmap.width) return false;
        if(0 > y || y >= cmap.height) return false;
        if(visited.contains(x | (y << 8))) return false;
        return cmap.hasPlayerRoomWithType(x, y, typeId, playerId);
    }
    void travelRoom(int x, int y, char typeId, __int16 playerId, std::set<int> &visited) {
        if(!hasPlayerRoomWithTypeExcept(x, y, typeId, playerId, visited)) return;
        visited.insert(x | (y << 8));
        travelRoom(x, y - 1, typeId, playerId, visited);
        travelRoom(x + 1, y, typeId, playerId, visited);
        travelRoom(x, y + 1, typeId, playerId, visited);
        travelRoom(x - 1, y, typeId, playerId, visited);
    }
}

int dk2::CPlayer::destroyRoom(int a2_x, int a3_y, int a4_bool) {
    int v6_y = a3_y;
    if (!g_pCWorld->v_sub_5092B0(a2_x, a3_y, this->f0_tagId) && a4_bool)
        return 0;
    MyMapElement *v7_mapElem = g_pCWorld->v_getMapElem(a2_x, v6_y);
    CRoom *room = v7_mapElem->getRoom();
    int salePrice = (unsigned __int16) room->pRoomDataObj->_getSalePrice();
    uint8_t maxRoomLimit = 96;
    if (override_max_room_count::enabled) {
        maxRoomLimit = override_max_room_count::limit;
    }
    uint8_t numRoomsLeft = maxRoomLimit - this->numberOfRooms;

    uint8_t roomTypeId = room->typeId;  // remember now as room obj will be released
    int8_t deltaRooms;
    if(numRoomsLeft < 4) {  // remove whole room
        std::set<int> visited;
        travelRoom(a2_x, a3_y, room->typeId, room->playerId, visited);
        deltaRooms = 0;
        {
            int8_t localDeltaRooms = 0;
            if (!g_pCWorld->rooms.eventRemoveReset(a2_x, a3_y, 4, &localDeltaRooms)) return 0;
            deltaRooms += localDeltaRooms;
            visited.erase(a2_x | (a3_y << 8));
        }
        if(deltaRooms > numRoomsLeft && !visited.empty()) {
            salePrice *= visited.size();
            for(auto pos : visited) {
                uint8_t x = pos;
                uint8_t y = pos >> 8;
                int8_t localDeltaRooms = 0;
                if (!g_pCWorld->rooms.eventRemoveReset(x, y, 4, &localDeltaRooms)) return 0;
                deltaRooms += localDeltaRooms;
            }
        }
    } else {
        if (!g_pCWorld->rooms.eventRemoveReset(a2_x, v6_y, numRoomsLeft, &deltaRooms)) return 0;
    }

    this->numberOfRooms += deltaRooms;
    MyRoomDataObj *v9_roomDataObj = g_pCWorld->v_f98_50D0B0_getMyRoomDataObj(roomTypeId);
    MyTerrainDataObj *v10_terrainDataObj = g_pCWorld->v_f70_508DD0_getTerrainDataObj(v9_roomDataObj->_terrainType);
    Vec3i v15_vec;
    v15_vec.x = (a2_x << 12) + 2048;
    v15_vec.y = (v6_y << 12) + 2048;
    v15_vec.z = 4096;
    if (a4_bool) {
        this->moneyRoom_4BA420(salePrice, 0, a2_x, v6_y);
        g_pCWorld->sub_50FB70(this->f0_tagId, &v15_vec, salePrice, 0);
        int v12 = v10_terrainDataObj->f195;
        if (v12) {
            MySound_ptr->v_CSoundSystem_fun_5678F0(0, v12, 245, &v15_vec);
            return 1;
        }
    } else {
        int v14 = v10_terrainDataObj->f195;
        if (v14)
            MySound_ptr->v_CSoundSystem_fun_5678F0(0, v14, 244, &v15_vec);
    }
    return 1;
}

const char *CRoom_typeId_toString(int ty) {
    switch (ty) {
#define _CRoom_typeId_toString(id, pascalName) case CRoom_typeId_##pascalName: return #pascalName;
        CRoom_types(_CRoom_typeId_toString)
    }
    return "Unknown";
}
