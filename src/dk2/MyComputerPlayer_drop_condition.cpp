//
// Created by DiaLight on 02.05.2025.
//

#include "MyComputerPlayer_drop_condition.h"
#include "patches/micro_patches.h"
#include "dk2/utils/Vec3i.h"
#include "dk2/MyComputerPlayer.h"
#include "dk2/CWorld.h"
#include "dk2/world/map/MyMapElement.h"
#include "dk2/entities/CPlayer.h"
#include "dk2/world/nav/MyNavigationSystem.h"
#include "computer_player_flags.h"


bool drop_condition(dk2::MyComputerPlayer *cp, dk2::Vec3i &v59_loc) {
    unsigned int v71_locX = 0;
    unsigned int v69_locY = 0;
    int v32_respondIdx = getCurrentEventTask(cp);
    bool v74_whileBool = true;
    unsigned int v33_locX = cp->respondToAttack[v32_respondIdx].x;
    unsigned __int16 v34_locY = cp->respondToAttack[v32_respondIdx].y;
    dk2::CWorld *v35_cworld = cp->world;
    unsigned int v73_locY = v34_locY;
    dk2::CWorld *v36_cworld = v35_cworld;
    int v37_cmapHeight = v35_cworld->v_getCMapHeight_508FB0();
    unsigned int v65_cmapHeight = v37_cmapHeight;
    unsigned int v39_cmapWidth = v36_cworld->v_getCMapWidth_508FA0();
    dk2::CWorld *v40_cworld = cp->world;
    int v41_maxSize;
    if (v39_cmapWidth <= v65_cmapHeight)
        v41_maxSize = v40_cworld->v_getCMapHeight_508FB0();
    else
        v41_maxSize = v40_cworld->v_getCMapWidth_508FA0();
    int v62_maxSize_x2 = 2 * v41_maxSize;
    if (cp->world->v_testCoordsInBounds_509090(v33_locX, v73_locY)) {
        dk2::CWorld *v42_cworld = cp->world;
        dk2::MyMapElement *v43_mapElement = &v42_cworld->cmap.mapElements[v33_locX + v73_locY * v42_cworld->cmap.width];
        if ((v42_cworld->cmap.pNavigationSystem->map.mapBuf[v73_locY * v42_cworld->cmap.pNavigationSystem->map.width + v33_locX] & 8) == 0
            && !v43_mapElement->sub_454110()
            && (v43_mapElement->_playerIdFFF & 0xFFF) == cp->cplayer->f0_tagId) {
            v71_locX = v33_locX;
            v69_locY = v73_locY;
            v74_whileBool = false;
        }
    }
    unsigned int v44_locX = v33_locX + 1;
    unsigned int v66_deltaY = 0;
    int f3C_health = 0;
    bool v27_doDrop = true;
    v65_cmapHeight = 1;
    int v70 = 1;
    int v72 = 1;
    if (v74_whileBool) {
        do {
            if (f3C_health) {
                while (true) {
                    if (cp->world->v_testCoordsInBounds_509090(v44_locX, v73_locY)) {
                        dk2::CWorld *v48_cworld = cp->world;
                        dk2::MyMapElement *v49_mapElem = &v48_cworld->cmap.mapElements[
                                v44_locX + v73_locY * v48_cworld->cmap.width];
                        if ((v48_cworld->cmap.pNavigationSystem->map.mapBuf[
                                     v73_locY * v48_cworld->cmap.pNavigationSystem->map.width +
                                     v44_locX] & 8) == 0
                            && !v49_mapElem->sub_454110()
                            && (v49_mapElem->_playerIdFFF & 0xFFF) == cp->cplayer->f0_tagId) {
                            break;
                        }
                    }
                    v44_locX += v66_deltaY;
                    if (!--v72) {
                        v65_cmapHeight = v66_deltaY;
                        v72 = v70;
                        f3C_health = 0;
                        if (v70 < v62_maxSize_x2)
                            goto LABEL_80;
                        v71_locX = 0;
                        goto LABEL_79;
                    }
                }
            } else {
                while (true) {
                    if (cp->world->v_testCoordsInBounds_509090(v44_locX, v73_locY)) {
                        dk2::CWorld *v45_cworld = cp->world;
                        dk2::MyMapElement *v46_mapElem = &v45_cworld->cmap.mapElements[
                                v44_locX + v73_locY * v45_cworld->cmap.width];
                        if ((v45_cworld->cmap.pNavigationSystem->map.mapBuf[
                                     v73_locY * v45_cworld->cmap.pNavigationSystem->map.width +
                                     v44_locX] & 8) == 0
                            && !v46_mapElem->sub_454110()
                            && (v46_mapElem->_playerIdFFF & 0xFFF) == cp->cplayer->f0_tagId) {
                            break;
                        }
                    }
                    bool v47 = v70 == 1;
                    v73_locY += v65_cmapHeight;
                    --v70;
                    if (v47) {
                        f3C_health = 1;
                        v70 = ++v72;
                        v66_deltaY = -v65_cmapHeight;
                        goto LABEL_80;
                    }
                }
            }
            v71_locX = v44_locX;
            v69_locY = v73_locY;
            LABEL_79:
            v74_whileBool = false;
            LABEL_80:;
        } while (v74_whileBool);
        v27_doDrop = true;
    }
    if (v71_locX) {
        cp->respondToAttack[getCurrentEventTask(cp)].x = v71_locX;
        cp->respondToAttack[getCurrentEventTask(cp)].y = v69_locY;
        int v50_respondIdx = getCurrentEventTask(cp);
        v59_loc.x = (cp->respondToAttack[v50_respondIdx].x << 12) + 2048;
        v59_loc.y = (cp->respondToAttack[v50_respondIdx].y << 12) + 2048;
        v59_loc.z = 0;
    } else {
        v27_doDrop = false;
    }
    return v27_doDrop;
}

