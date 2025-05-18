//
// Created by DiaLight on 5/17/2025.
//

#include "limit_tps.h"
#include <tools/flame_config.h>
#include <Windows.h>


namespace {

    DWORD g_lastTime = 0;

}


flame_config::define_flame_option<int> o_limitTps(
    "flame:limit-tps",
    "For displays with high frequency you can limit game loop time\n"
    "I don't know what fps value the dk2 developers were adjusting to\n"
    "I was comfortable with 60 (frames/ticks) per second\n"
    "use value 0 to disable limit",
    60
);

void patch::limit_tps::call() {
    int tps = *o_limitTps;
    if (tps <= 0) return;
    DWORD now = GetTickCount();
    DWORD loopTime = now - g_lastTime;
    int mspt = 1000 / tps;  // calc milliseconds per tick
    if (loopTime < mspt) {
        SleepEx(mspt - loopTime, FALSE);
    }
    g_lastTime = GetTickCount();
}
