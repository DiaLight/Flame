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
    "flame:limit-tps", flame_config::OG_Config,
    "For displays with high frequency you can limit game loop time\n"
    "I don't know what fps value the dk2 developers were adjusting to\n"
    "I was comfortable with 60 (frames/ticks) per second\n"
    "use value 0 to disable limit",
    60
);

flame_config::define_flame_option<int> o_test1(
    "flame:experimental:test", flame_config::OG_Config,
    "",
    0
);

void patch::limit_tps::call() {
    int tps = *o_limitTps;
    if (tps <= 0) return;
    DWORD now = GetTickCount();
    DWORD loopTime = now - g_lastTime;
    int mspt = 1000 / tps;  // calc milliseconds per tick
    int freeTime = mspt - loopTime;
    if (freeTime > 0) {
        // 60 tps == 16 ms loop time
        // 30 tps == 33 ms loop time
        int test = *o_test1;
        switch (test) {
            case 1: {
                // SleepEx does not guarantee waking up thread in time
                // dont sleep if it slightly longer than threshold
                // because thread context swap can be longer than couple milliseconds
                if (freeTime > 3) {  // bad solution, worth testing
                    SleepEx(freeTime, FALSE);
                }
            } break;
            case 2: {
                WaitForSingleObjectEx(GetCurrentThread(), freeTime, TRUE);
            } break;
            case 3: {
                WaitForSingleObject(GetCurrentThread(), freeTime);
            } break;
            case 4: {
                SleepEx(freeTime, TRUE);
            } break;
            case 5: {
                // DK2 working in single-threaded mode because sync issues
                // Sleep does not calling sys calls as far as I know
                // But it can be precise in waiting
                // worst solution but worth testing
                Sleep(freeTime);
            } break;
            default: {
                SleepEx(freeTime, FALSE);
            } break;
        }
    }
    DWORD end = GetTickCount();
    int waitTime = end - now;
    if (waitTime > (mspt * 2)) {
        printf("[warning] was waiting for too long %d ms. expected %d ms\n", waitTime, freeTime);
    }
    g_lastTime = end;
}
