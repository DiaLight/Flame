//
// Created by DiaLight on 7/6/2026.
//

#include "dk2_functions.h"
#include "dk2_globals.h"
#include "dk2/MyDLVec2i.h"
#include "dk2/MyLVec3f.h"
#include "dk2/math/vec.h"
#include "dk2/math/mat.h"
#include "patches/opengl/opengl_patch.h"
#include "tools/visual_debug.h"
#include "patches/opengl/visual_value.h"
#include <cmath>
#include <exception>


namespace dk2 {
//    struct MyLVec3f {
//        Vec3f vec;
//        MyLVec3f *next;
//    };
//    struct MyDLVec2i {
//        int x;
//        int y;
//        MyDLVec2i *prev;
//        MyDLVec2i *next;
//    };

    MyLVec3f *MyLLVec3f_linkVec(MyLVec3f **this_, const Vec3f &vec) {
        MyLVec3f *result = (MyLVec3f *) MyHeap_alloc(sizeof(MyLVec3f));
        if (result) {
            result->vec = vec;
            result->next = NULL;
            result->next = *this_;
            *this_ = result;
        } else {
            throw std::exception("unexpected");
        }
        return result;
    }

    void MyLLVec3f_cull(MyLVec3f **this_, float from, float to, int dim) {
        MyLVec3f *first = NULL;
        MyLVec3f *last = NULL;
        float curVal = from;
        for (int i = 0; i < 2; ++i) {
            for (MyLVec3f *vec1 = *this_; vec1; vec1 = vec1->next) {
                for (MyLVec3f *vec2 = vec1->next; vec2; vec2 = vec2->next) {
                    bool cond1 = *(&vec1->vec.x + dim) < (double) curVal && (double) curVal < *(&vec2->vec.x + dim);
                    bool cond2 = *(&vec1->vec.x + dim) > (double) curVal && (double) curVal > *(&vec2->vec.x + dim);
                    if (!cond1 && !cond2) continue;

                    MyLVec3f *item = (MyLVec3f *) MyHeap_alloc(sizeof(MyLVec3f));
                    if (item) {
                        Vec3f v = vec2->vec - vec1->vec;
                        double v8 = curVal - *(&vec1->vec.x + dim);
                        double v9 = 1.0 / (*(&vec2->vec.x + dim) - *(&vec1->vec.x + dim));
                        item->vec = (v * v8) * v9 + vec1->vec;
                        item->next = NULL;
                    } else {
                        item = NULL;
                    }
                    *(&item->vec.x + dim) = curVal;
                    if (first) {
                        MyLVec3f *v12 = last;
                        last = item;
                        v12->next = item;
                    } else {
                        last = item;
                        first = item;
                    }
                }
            }
            curVal = to;
        }
        if (first) {
            last->next = *this_;
            *this_ = first;
        }
        MyLVec3f *v15 = NULL;
        for (MyLVec3f *cur = *this_; cur; ) {
            float dval = *(&cur->vec.x + dim);
            if ((double) from <= dval && dval <= (double) to) {
                MyLVec3f *next = cur->next;
                v15 = cur;
                cur = next;
                continue;
            }

            MyLVec3f *next = cur->next;
            if (v15) {
                v15->next = next;
            } else {
                *this_ = next;
            }
            cur->next = NULL;
            MyHeap_free(cur);
            cur = next;
        }
    }

    void MyLLVec3f_removeNearPoints(MyLVec3f **this_) {
        MyLVec3f *last = NULL;
        MyLVec3f *cur = *this_;
        for (; cur; ) {
            MyLVec3f *next = cur->next;
            MyLVec3f *cur2 = *this_;
            if (cur2) {
                for (; cur2; cur2 = cur2->next) {
                    if (cur == cur2) continue;
                    float dx = fabs(cur->vec.x - cur2->vec.x);
                    float dy = fabs(cur->vec.y - cur2->vec.y);
                    if (dx >= 0.0099999998 || dy >= 0.0099999998) continue;
                    if (last) {
                        last->next = next;
                    } else {
                        *this_ = next;
                    }
                    cur->next = NULL;
                    MyHeap_free(cur);
                    cur = next;
                    break;
                }
                if (cur2) continue;
            }
            last = cur;
            cur = next;
        }
    }

    void MyLLVec3f_doMatAndCalcMinMax(MyLVec3f **this_, float *outMin, float *outMax) {
        *outMin = 1.0e30;
        *outMax = -1.0e30;
        for (MyLVec3f *cur = *this_; cur; cur = cur->next) {
            Vec3f delta = cur->vec - g_activeCameraState.v3f;
            Vec3f sceneDelta = g_activeCameraState.viewMat * delta;
            if (sceneDelta.z < (double) *outMin) *outMin = sceneDelta.z;
            if (sceneDelta.z > (double) *outMax) *outMax = sceneDelta.z;
        }
    }

    MyDLVec2i *MyLLVec3f_toMyDLVec2i(MyLVec3f **this_) {
        if (!*this_) return NULL;
        double minY = (*this_)->vec.y;
        MyLVec3f *minYVec = *this_;
        for (MyLVec3f *v1 = *this_; v1; v1 = v1->next) {
            if (v1->vec.y < minY) {
                minY = v1->vec.y;
                minYVec = v1;
            }
        }

        MyDLVec2i *nobj = (MyDLVec2i *) MyHeap_alloc(sizeof(MyDLVec2i));
        MyDLVec2i *first;
        if (nobj) {
            nobj->x = strangeOptimizedMultiplyAddCast(minYVec->vec.x, 1, 0);
            nobj->y = strangeOptimizedMultiplyAddCast(minYVec->vec.y, 1, 0);
            nobj->prev = NULL;
            nobj->next = NULL;
            first = nobj;
        } else {
            first = NULL;
        }
        MyDLVec2i *last = first;
        MyLVec3f *v10 = minYVec;
        double v11 = 0.0;
        float vec_x = minYVec->vec.x;
        float vec_y = minYVec->vec.y;
        while (true) {
            MyLVec3f *v12 = minYVec;
            double v13 = 1000.0;
            MyLVec3f *v14 = *this_;
            float i;
            for (i = 0.0; v14; v14 = v14->next) {
                if (v14 != v10) {
                    double v15 = v14->vec.y - vec_y;
                    double v16 = v14->vec.x - vec_x;
                    float v19 = 0.0;
                    if (v15 != 0.0 || v16 < 0.0)
                        v19 = atan2(-v15, -v16) + 3.1415927;
                    float v20 = v19 - v11;
                    if (v20 >= 0.0 && v20 < v13) {
                        v12 = v14;
                        v13 = v20;
                        i = v19;
                    }
                }
            }
            v10 = v12;
            if (v12 == minYVec) {
                MyDLVec2i *result = first;
                last->next = first;
                first->prev = last;
                return result;
            }
            vec_x = v12->vec.x;
            vec_y = v12->vec.y;
            MyDLVec2i *no2 = (MyDLVec2i *) MyHeap_alloc(sizeof(MyDLVec2i));
            if (no2) {
                no2->x = strangeOptimizedMultiplyAddCast(vec_x, 1, 0);
                no2->y = strangeOptimizedMultiplyAddCast(vec_y, 1, 0);
                no2->prev = last;
                no2->next = NULL;

                v11 = i;
                last->next = no2;
                last = no2;
            } else {
                v11 = i;
                last->next = NULL;
                last = NULL;
            }
        }
    }

    void MyLLVec3f_destroy(MyLVec3f **this_) {
        MyLVec3f *cur = *this_;
        while (cur) {
            MyLVec3f *next = cur->next;
            cur->next = NULL;
            MyHeap_free(cur);
            cur = next;
        }
        *this_ = NULL;
    }

}


dk2::MyDLVec2i *dk2::computeFrustumContour2D() {
    float trgSubLeft = g_activeCameraState.trg.x - g_activeCameraState.leftRight.x;
    float rightSubTrg = g_activeCameraState.leftRight.y - g_activeCameraState.trg.x;
    float trgSubTop = g_activeCameraState.trg.y - g_activeCameraState.topBottom.x;
    float botSubTrg = g_activeCameraState.topBottom.y - g_activeCameraState.trg.y;

    long double v1 = 1.0 / sqrt(g_activeCameraState.ww240_viewRange * g_activeCameraState.ww240_viewRange + trgSubLeft * trgSubLeft);
    g_vec_760B70 = Vec3f{(float) (v1 * g_activeCameraState.ww240_viewRange), 0.0, (float) (v1 * trgSubLeft)};

    long double v4 = 1.0 / sqrt(-g_activeCameraState.ww240_viewRange * -g_activeCameraState.ww240_viewRange + rightSubTrg * rightSubTrg);
    g_vec_760B38 = Vec3f{(float) (v4 * -g_activeCameraState.ww240_viewRange), 0.0, (float) (v4 * rightSubTrg)};

    long double v5 = 1.0 / sqrt(g_activeCameraState.ww240_viewRange * g_activeCameraState.ww240_viewRange + trgSubTop * trgSubTop);
    g_vec_760B18 = Vec3f{0.0, (float) (v5 * g_activeCameraState.ww240_viewRange), (float) (v5 * trgSubTop)};

    long double v7 = 1.0 / sqrt(-g_activeCameraState.ww240_viewRange * -g_activeCameraState.ww240_viewRange + botSubTrg * botSubTrg);
    g_vec_760B28 = Vec3f{0.0, (float) (v7 * -g_activeCameraState.ww240_viewRange), (float) (v7 * botSubTrg)};

    float v37 = 1.0;
    if ((g_activeCameraState.flags & 8) != 0)
        v37 = 2.0 / (rightSubTrg / g_activeCameraState.ww240_viewRange + 2.0);

    Mat3x3f mat;
    Vec3f vec;

    static VisualBool ignoreCamState("computeFrustum identity g_activeCameraState");
    if (ignoreCamState) {
        mat = Mat3x3f{.m={
                {1.f, 0.f, 0.f},
                {0.f, 1.f, 0.f},
                {0.f, 0.f, 1.f},
        }};
        vec = Vec3f{0, 0, 0};
    } else {
        mat = transpose(g_activeCameraState.viewMat);
        vec = g_activeCameraState.v3f;
    }

    Vec3f o57 = Vec3f{-1.0, -1.0, -1.0};
    Vec3f o59 = Vec3f{1.0, -1.0, -1.0};
    Vec3f o61 = Vec3f{-1.0, 1.0, -1.0};
    Vec3f o60 = Vec3f{1.0, 1.0, -1.0};

    float v71 = rightSubTrg / g_activeCameraState.ww240_viewRange;
    float v72 = -(trgSubLeft / g_activeCameraState.ww240_viewRange);
    float v73 = botSubTrg / g_activeCameraState.ww240_viewRange;
    float v38 = -(trgSubTop / g_activeCameraState.ww240_viewRange);
    Vec3f o48 = (((Vec3f{v72, v38, 1.f} * g_activeCameraState.farPlane) * v37) + Vec3f{-1.f, -1.f, 0.f});
    Vec3f o51 = (((Vec3f{v71, v38, 1.f} * g_activeCameraState.farPlane) * v37) + Vec3f{1.f, -1.f, 0.f});
    Vec3f o55 = (((Vec3f{v72, v73, 1.f} * g_activeCameraState.farPlane) * v37) + Vec3f{-1.f, 1.f, 0.f});
    Vec3f o54 = (((Vec3f{v71, v73, 1.f} * g_activeCameraState.farPlane) * v37) + Vec3f{1.f, 1.f, 0.f});

    Vec3f o58 = Vec3f{0.0, 0.0, g_activeCameraState.farPlane};

    MyLVec3f *v36 = NULL;
    int try_level = 0;
    MyLLVec3f_linkVec(&v36, vec + (mat * o57));
    MyLLVec3f_linkVec(&v36, vec + (mat * o59));
    MyLLVec3f_linkVec(&v36, vec + (mat * o61));
    MyLLVec3f_linkVec(&v36, vec + (mat * o60));
    MyLLVec3f_linkVec(&v36, vec + (mat * o48));
    MyLLVec3f_linkVec(&v36, vec + (mat * o51));
    MyLLVec3f_linkVec(&v36, vec + (mat * o55));
    MyLLVec3f_linkVec(&v36, vec + (mat * o54));
    MyLLVec3f_linkVec(&v36, vec + (mat * o58));
    MyLLVec3f_cull(&v36, g_cullFrom, g_cullTo, 2);
    MyLLVec3f_removeNearPoints(&v36);
    MyLLVec3f_doMatAndCalcMinMax(&v36, &g_viewZMin, &g_viewZMax);
    MyDLVec2i *result = MyLLVec3f_toMyDLVec2i(&v36);
    try_level = -1;
    MyLLVec3f_destroy(&v36);
    return result;
}


