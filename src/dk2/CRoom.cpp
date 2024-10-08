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
    this->fun_44FC40(a2_x, v8_y, (int) v11_roomDataObj->_terrainType, v9_mapElem->_playerIdFFF & 0xFFF, 0, a7);
//    v9_mapElem->roomId = v9_mapElem->roomId ^ ((v9_mapElem->roomId ^ a4_roomObjId) & 0xFFF);
    v9_mapElem->_roomIdFFF = (v9_mapElem->_roomIdFFF & 0xF000) | (a4_roomObjId & 0xFFF);
    return this->sub_4522A0(a2_x, v8_y);
}

int dk2::MyRooms::sub_4ED1A0__reattach2(
        int a2_x,
        int arg4_y,
        int a4_roomTypeId,
        unsigned __int16 a5_playerId,
        unsigned __int16 a6_roomObjId,
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
    CRoom *v19[4];
    memset(v19, 0, sizeof(v19));
    CRoom *a3 = 0;
    int v14 = this->sub_4ED320__reattach1(a2_x, arg4_y, a4_roomTypeId, a5_playerId, a6_roomObjId, a7_pNearCountNeg, &a3, v19);
    if (wooden_bridge_burn_fix::enabled) {
        if (((BYTE) a4_roomTypeId) == CRoom_typeId_WoodenBridge) {
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

#define MaxRoomCount (96 * 7)  // 0x2A0

int dk2::MyRooms::createRooms(CWorld *a2_world) {
    static_assert(0xA9 == sizeof(CRoom));
    static_assert(0x1BBA4u == (sizeof(CRoom) * 0x2A0 + 4));
    DWORD *v3 = (DWORD *) __nh_malloc(sizeof(CRoom) * MaxRoomCount + 4, 1);  //operator new(0x1BBA4u);
    CRoom *v4;
    if (v3) {
        v4 = (CRoom *) (v3 + 1);
        *v3 = MaxRoomCount;
        typedef void (*___for_each_construct_t)(char *, uint32_t, int, void (__thiscall *)(void *),
                                                void (__thiscall *)(void *));
        auto __for_each_construct = (___for_each_construct_t) 0x00635EC0;
        __for_each_construct(
                (char *) v3 + 4,
                0xA9u,
                MaxRoomCount,
                (void (__thiscall *)(void *)) 0x004E3790, // CRoom::constructor
                (void (__thiscall *)(void *)) 0x004E37F0 // CRoom::destructor
        );
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
        v7->roomManagerNodeX = 0;
        v7->roomManagerNodeY = 0;
        CRoom *fA_CRoom_arr_p = this->CRoom_arr_p;
        fA_CRoom_arr_p[i].playerRoomListNodeX = 0;
        fA_CRoom_arr_p[i].playerRoomListNodeY = 0;
        CRoom *v10 = this->CRoom_arr_p;
        v10[i].changedAreaRoomListNodeX = 0;
        v10[i].changedAreaRoomListNodeY = 0;
        ((CRoom *) sceneObjects[f0_tagId])->roomManagerNodeY = this->_nextRoomId;
        if (this->_nextRoomId)
            ((CRoom *) sceneObjects[this->_nextRoomId])->roomManagerNodeX = f0_tagId;
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
    if (this->_counter >= MaxRoomCount)
        return 0;
    unsigned __int16 roomObjId;
    if (this->f16) {
        roomObjId = this->_roomSceneObjId;
        this->f16 = 0;
        this->_roomSceneObjId = 0;
    } else {
        roomObjId = this->_nextRoomId;
    }
    if (!((CRoom *) sceneObjects[roomObjId])->init(a2_roomTypeId, a3_playerId))
        return 0;
    CRoom *v6 = (CRoom *) sceneObjects[roomObjId];
    // unlink X
    if (v6->roomManagerNodeX) {
        ((CRoom *) sceneObjects[((CRoom *) sceneObjects[roomObjId])->roomManagerNodeX])->roomManagerNodeY = v6->roomManagerNodeY;
    } else {
        this->_nextRoomId = v6->roomManagerNodeY;
    }
    // unlink Y
    if (((CRoom *) sceneObjects[roomObjId])->roomManagerNodeY) {
        ((CRoom *) sceneObjects[((CRoom *) sceneObjects[roomObjId])->roomManagerNodeY])->roomManagerNodeX = ((CRoom *) sceneObjects[roomObjId])->roomManagerNodeX;
    }
    CRoom *v7 = (CRoom *) sceneObjects[roomObjId];
    v7->roomManagerNodeX = 0;
    v7->roomManagerNodeY = 0;
    __int16 f10__nextRoomId = this->_nextRoomId;
    if (roomObjId == f10__nextRoomId)
        this->_nextRoomId = f10__nextRoomId - 1;
    // link to list
    ((CRoom *) sceneObjects[roomObjId])->roomManagerNodeY = this->firstRoomId;
    if (this->firstRoomId)
        ((CRoom *) sceneObjects[this->firstRoomId])->roomManagerNodeX = roomObjId;
    this->firstRoomId = roomObjId;
    this->_counter++;
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
    size_t maxRoomLimit = 96;
    if (override_max_room_count::enabled) {
        maxRoomLimit = override_max_room_count::limit;
    }
    int v9_roomNum = maxRoomLimit - this->numberOfRooms;
    int8_t roomsCountNeg;
    if (!g_pCWorld->rooms.sub_4ED1A0__reattach2(
            a2_x,
            a3_y,
            a4_roomTypeId,
            this->f0_tagId,
            v9_roomNum,
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
    bool hasNearPlayerRoomWithTypeExcept(int x, int y, char typeId, __int16 playerId, std::set<int> &visited) {
        if(hasPlayerRoomWithTypeExcept(x, y - 1, typeId, playerId, visited)) return true;
        if(hasPlayerRoomWithTypeExcept(x + 1, y, typeId, playerId, visited)) return true;
        if(hasPlayerRoomWithTypeExcept(x, y + 1, typeId, playerId, visited)) return true;
        if(hasPlayerRoomWithTypeExcept(x - 1, y, typeId, playerId, visited)) return true;
        return false;
    }
    void travelRoom(int x, int y, char typeId, __int16 playerId, std::set<int> &visited) {
        if(!hasPlayerRoomWithTypeExcept(x, y, typeId, playerId, visited)) return;
        visited.insert(x | (y << 8));
        travelRoom(x, y - 1, typeId, playerId, visited);
        travelRoom(x + 1, y, typeId, playerId, visited);
        travelRoom(x, y + 1, typeId, playerId, visited);
        travelRoom(x - 1, y, typeId, playerId, visited);
    }
    int getNewRoomsCountIfRemove(int x, int y) {
        CRoom &room = *g_pCWorld->v_getMapElem(x, y)->getRoom();
        CMap &cmap = g_pCWorld->cmap;
        if(!cmap.hasNearPlayerRoomWithType(x, y, room.typeId, room.playerId)) return -1;

        std::set<int> visited;
        visited.insert(x | (y << 8));
        Pos2ub pos = room.firstSlab;
        size_t splitCount = 0;
        while(pos.x || pos.y) {
            if(!visited.contains(pos.x | (pos.y << 8))) {
                travelRoom(pos.x, pos.y, room.typeId, room.playerId, visited);
                splitCount++;
            }
            pos = cmap.mapElements[pos.x + pos.y * cmap.width].nextSlab;
        }
        return splitCount - 1;
    }
}

int dk2::CPlayer::destroyRoom(int a2_x, int a3_y, int a4_bool) {
    int v6_y = a3_y;
    if (!g_pCWorld->v_sub_5092B0(a2_x, a3_y, this->f0_tagId) && a4_bool)
        return 0;
    MyMapElement *v7_mapElem = g_pCWorld->v_getMapElem(a2_x, v6_y);
    CRoom *room = v7_mapElem->getRoom();
    int salePrice = (unsigned __int16) room->pRoomDataObj->_getSalePrice();
    size_t maxRoomLimit = 96;
    if (override_max_room_count::enabled) {
        maxRoomLimit = override_max_room_count::limit;
    }
    int v9_roomNum = maxRoomLimit - this->numberOfRooms;

    if(override_max_room_count::enabled && override_max_room_count::predictLimit) {
        // trying predict limit reach on room destroy
        if(v9_roomNum <= 4) {
            int splitCount = getNewRoomsCountIfRemove(a2_x, a3_y);
            if(v9_roomNum < splitCount) return false;
        }
    }

    uint8_t roomTypeId = room->typeId;  // room obj will be released
    int8_t roomsCountNeg;
    if (!g_pCWorld->rooms.sub_4ED440__sailRoom2(a2_x, v6_y, v9_roomNum, &roomsCountNeg))
        return 0;
    this->numberOfRooms += roomsCountNeg;
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
