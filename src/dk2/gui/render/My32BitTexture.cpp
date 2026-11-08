//
// Created by DiaLight on 6/19/2026.
//
#include "dk2/My32BitTexture.h"
#include "dk2_globals.h"
#include "dk2_functions.h"
#include <valarray>


namespace dk2 {

    inline void memset32(void* dest, uint32_t value, int count) {
        auto* dst = (uint32_t *) dest;
        for (int i = 0; i < count; ++i) dst[i] = value;
    }


    bool inside(AABB &aabb, int x, int y) {
        return aabb.minX <= x && x < aabb.maxX
               && aabb.minY <= y && y < aabb.maxY;
    }

}


void dk2::My32BitTexture::fun_5C4B50(int x, int y, Bgraf color) {
    if ((g_MyNBitTexture_surf_f0 & 8) != 0 || (g_MyNBitTexture_surf_f0 & 0x10) != 0) {
        if (inside(g_MyNBitTexture_renderSurfAabb, x, y)) {
            auto *dst = (uint8_t *) g_MyNBitTexture_lpSurface + y * g_MyNBitTexture_myRenderSurface->lPitch + 4 * x;
            *(DWORD *) dst = color.blue | ((color.green | (*(unsigned __int16 *) &color.red << 8)) << 8);
        }
    } else if ((g_MyNBitTexture_surf_f0 & 0x20) != 0) {
        int v5 = (unsigned __int8) g_MyNBitTexture_fill2PaletteMap[color.fill];
        BYTE g = g_paletteEntries[v5].peGreen;
        BYTE r = g_paletteEntries[v5].peRed;
        BYTE b = g_paletteEntries[v5].peBlue;
        if (inside(g_MyNBitTexture_renderSurfAabb, x, y)) {
            auto *dst = (uint8_t *) g_MyNBitTexture_lpSurface + y * g_MyNBitTexture_myRenderSurface->lPitch + 4 * x;
            *(DWORD *) dst = b | ((g | ((r | 0xFFFFFF00) << 8)) << 8);
        }
    } else {
        if (inside(g_MyNBitTexture_renderSurfAabb, x, y)) {
            auto *dst = (uint8_t *) g_MyNBitTexture_lpSurface + y * g_MyNBitTexture_myRenderSurface->lPitch + 4 * x;
            *(DWORD *) dst = color.blue | ((color.green | (*(unsigned __int16 *) &color.red << 8)) << 8);
        }
    }
}

void dk2::My32BitTexture::fun_5C8810(AABB *a1, Bgraf color) {
    AABB aabb;
    a1->intersection(&aabb, &g_MyNBitTexture_renderSurfAabb);
    int Width = AABB_getWidth(&aabb);
    int v16 = Width;
    int Height = AABB_getHeight(&aabb);
    int offs = aabb.minY * g_MyNBitTexture_myRenderSurface->lPitch + 4 * aabb.minX;
    if ((g_MyNBitTexture_surf_f0 & 8) != 0) {
        int v6 = Height - 1;
        if (v6 >= 0) {
            AABB *a1a = (AABB *) (v6 + 1);
            do {
                if (Width - 1 >= 0) {
                    int v7 = Width;
                    do {
                        offs += 4;
                        --v7;
                        *(DWORD *) ((char *) g_MyNBitTexture_lpSurface + offs - 4) =
                                color.blue | ((color.green | (*(unsigned __int16 *) &color.red << 8)) << 8);
                    } while (v7);
                }
                offs += g_MyNBitTexture_myRenderSurface->lPitch - 4 * Width;
                a1a = (AABB *) ((char *) a1a - 1);
            } while (a1a);
        }
    } else if ((g_MyNBitTexture_surf_f0 & 0x10) != 0) {
        int v8 = Height - 1;
        if (v8 >= 0) {
            AABB *a1b = (AABB *) (v8 + 1);
            int v9 = Width - 1;
            do {
                if (v9 >= 0) {
                    int v10 = v9 + 1;
                    do {
                        offs += 4;
                        --v10;
                        *(DWORD *) ((char *) g_MyNBitTexture_lpSurface + offs - 4) =
                                color.blue | ((color.green | (*(unsigned __int16 *) &color.red << 8)) << 8);
                    } while (v10);
                    Width = v16;
                }
                offs += g_MyNBitTexture_myRenderSurface->lPitch - 4 * Width;
                a1b = (AABB *) ((char *) a1b - 1);
            } while (a1b);
        }
    } else {
        unsigned __int8 f0_blue;
        if ((g_MyNBitTexture_surf_f0 & 0x20) != 0) {
            Bgraf v19_color;
            int v11 = (unsigned __int8) g_MyNBitTexture_fill2PaletteMap[color.fill];
            v19_color.red = g_paletteEntries[v11].peRed;
            v19_color.green = g_paletteEntries[v11].peGreen;
            v19_color.blue = g_paletteEntries[v11].peBlue;
            v19_color.alpha = -1;
            *(DWORD *) &color.blue = *(DWORD *) &v19_color.blue;
            f0_blue = v19_color.blue;
        } else {
            f0_blue = color.blue;
        }
        auto *line = (uint8_t *) g_MyNBitTexture_lpSurface + offs;
        for (int y = 0; y < Height; ++y) {
            if (Width > 0) {
                memset32(line, f0_blue | ((color.green | (*(unsigned __int16 *) &color.red << 8)) << 8), Width);
            }
            line += g_MyNBitTexture_myRenderSurface->lPitch;
        }
    }
}

void dk2::My32BitTexture::f1C_5C4D90(int a2, int a3, int a4, int a5, Bgraf a6_color) {
    int v6 = a2;
    int minX = a4;
    if (a2 == a4) {
        this->v_f24(a2, a3, a5 - a3, a6_color);
        return;
    }
    int minY = a3;
    int v9 = a5;
    if (a3 == a5) {
        this->v_f20(a2, a3, a4 - a2, a6_color);
        return;
    }

    {
        if (a2 >= g_MyNBitTexture_renderSurfAabb.minX) {
            if (a2 < g_MyNBitTexture_renderSurfAabb.maxX) {
                if (a4 >= g_MyNBitTexture_renderSurfAabb.minX) {
                    if (a4 >= g_MyNBitTexture_renderSurfAabb.maxX) {
                        int v10 = (a5 - a3) * (a4 - g_MyNBitTexture_renderSurfAabb.maxX + 1) / (a4 - a2);
                        minX = g_MyNBitTexture_renderSurfAabb.maxX - 1;
                        v9 = a5 - v10;
                    }
                } else {
                    int v10 = (a5 - minY) * (a4 - g_MyNBitTexture_renderSurfAabb.minX) / (a4 - v6);
                    minX = g_MyNBitTexture_renderSurfAabb.minX;
                    v9 = a5 - v10;
                }
            } else {
                if (a4 >= g_MyNBitTexture_renderSurfAabb.maxX) return;
                v6 = g_MyNBitTexture_renderSurfAabb.maxX - 1;
                minY = a3 - (a3 - a5) * (a2 - g_MyNBitTexture_renderSurfAabb.maxX + 1) / (a2 - a4);
                a3 = minY;
                if (a4 < g_MyNBitTexture_renderSurfAabb.minX) {
                    int v10 = (a5 - minY) * (a4 - g_MyNBitTexture_renderSurfAabb.minX) / (a4 - v6);
                    minX = g_MyNBitTexture_renderSurfAabb.minX;
                    v9 = a5 - v10;
                }
            }
        } else {
            if (a4 < g_MyNBitTexture_renderSurfAabb.minX) return;
            v6 = g_MyNBitTexture_renderSurfAabb.minX;
            minY = a3 - (a3 - a5) * (a2 - g_MyNBitTexture_renderSurfAabb.minX) / (a2 - a4);
            a3 = minY;
            if (a4 >= g_MyNBitTexture_renderSurfAabb.maxX) {
                int v10 = (a5 - minY) * (a4 - g_MyNBitTexture_renderSurfAabb.maxX + 1) / (a4 - g_MyNBitTexture_renderSurfAabb.minX);
                minX = g_MyNBitTexture_renderSurfAabb.maxX - 1;
                v9 = a5 - v10;
            }
        }
    }

    {
        if (minY >= g_MyNBitTexture_renderSurfAabb.minY) {
            if (minY < g_MyNBitTexture_renderSurfAabb.maxY) {
                if (v9 >= g_MyNBitTexture_renderSurfAabb.minY) {
                    if (v9 >= g_MyNBitTexture_renderSurfAabb.maxY) {
                        int v12 = (minX - v6) * (v9 - g_MyNBitTexture_renderSurfAabb.maxY + 1) / (v9 - minY);
                        v9 = g_MyNBitTexture_renderSurfAabb.maxY - 1;
                        minX -= v12;
                    }
                } else {
                    int v12 = (minX - v6) * (v9 - g_MyNBitTexture_renderSurfAabb.minY) / (v9 - minY);
                    v9 = g_MyNBitTexture_renderSurfAabb.minY;
                    minX -= v12;
                }
            } else {
                if (v9 >= g_MyNBitTexture_renderSurfAabb.maxY) return;
                int v13 = (v6 - minX) * (minY - g_MyNBitTexture_renderSurfAabb.maxY + 1) / (minY - v9);
                minY = g_MyNBitTexture_renderSurfAabb.maxY - 1;
                a3 = g_MyNBitTexture_renderSurfAabb.maxY - 1;
                v6 -= v13;
                if (v9 < g_MyNBitTexture_renderSurfAabb.minY) {
                    int v12 = (minX - v6) * (v9 - g_MyNBitTexture_renderSurfAabb.minY) / (v9 - minY);
                    v9 = g_MyNBitTexture_renderSurfAabb.minY;
                    minX -= v12;
                }
            }
        } else {
            if (v9 < g_MyNBitTexture_renderSurfAabb.minY) return;
            int v11 = (v6 - minX) * (minY - g_MyNBitTexture_renderSurfAabb.minY) / (minY - v9);
            minY = g_MyNBitTexture_renderSurfAabb.minY;
            a3 = g_MyNBitTexture_renderSurfAabb.minY;
            v6 -= v11;
            if (v9 >= g_MyNBitTexture_renderSurfAabb.maxY) {
                int v12 = (minX - v6) * (v9 - g_MyNBitTexture_renderSurfAabb.maxY + 1) /
                          (v9 - g_MyNBitTexture_renderSurfAabb.minY);
                v9 = g_MyNBitTexture_renderSurfAabb.maxY - 1;
                minX -= v12;
            }
        }
    }


    int a5a = v6;
    int v35 = minY;
    int a2a = 2 * std::abs(minX - v6);
    int a4a = minX - v6 <= 0 ? -1 : 1;
    signed int v14 = 2 * std::abs(v9 - minY);
    int lPitch = g_MyNBitTexture_myRenderSurface->lPitch;
    int v36 = v9 - minY <= 0 ? -1 : 1;
    int v34 = lPitch * v36;
    int v16 = lPitch * minY + 4 * v6;
    if ((g_MyNBitTexture_surf_f0 & 8) != 0) {
        if (a2a <= v14) {
            int v19 = a2a - (v14 >> 1);
            int v20 = a6_color.blue | ((a6_color.green | (*(unsigned __int16 *) &a6_color.red << 8)) << 8);
            *(DWORD *) ((char *) g_MyNBitTexture_lpSurface + v16) = v20;
            if (minY != v9) {
                int v21 = minY;
                do {
                    if (v19 >= 0) {
                        v19 -= v14;
                        v16 += 4 * a4a;
                    }
                    v21 += v36;
                    v16 += v34;
                    v19 += a2a;
                    *(DWORD *) ((char *) g_MyNBitTexture_lpSurface + v16) = v20;
                } while (v21 != v9);
            }
        } else {
            int v17 = v14 - (a2a >> 1);
            int v18 = a6_color.blue | ((a6_color.green | (*(unsigned __int16 *) &a6_color.red << 8)) << 8);
            *(DWORD *) ((char *) g_MyNBitTexture_lpSurface + v16) = v18;
            if (v6 != minX) {
                do {
                    if (v17 >= 0) {
                        v16 += v34;
                        v17 -= a2a;
                    }
                    v17 += v14;
                    a5a += a4a;
                    v16 += 4 * a4a;
                    *(DWORD *) ((char *) g_MyNBitTexture_lpSurface + v16) = v18;
                } while (a5a != minX);
            }
        }
    } else if ((g_MyNBitTexture_surf_f0 & 0x10) != 0) {
        if (a2a <= v14) {
            int v24 = a2a - (v14 >> 1);
            int v25 = a6_color.blue | ((a6_color.green | (*(unsigned __int16 *) &a6_color.red << 8)) << 8);
            *(DWORD *) ((char *) g_MyNBitTexture_lpSurface + v16) = v25;
            if (minY != v9) {
                int v26 = minY;
                do {
                    if (v24 >= 0) {
                        v24 -= v14;
                        v16 += 4 * a4a;
                    }
                    v26 += v36;
                    v16 += v34;
                    v24 += a2a;
                    *(DWORD *) ((char *) g_MyNBitTexture_lpSurface + v16) = v25;
                } while (v26 != v9);
            }
        } else {
            int v22 = v14 - (a2a >> 1);
            int v23 = a6_color.blue | ((a6_color.green | (*(unsigned __int16 *) &a6_color.red << 8)) << 8);
            *(DWORD *) ((char *) g_MyNBitTexture_lpSurface + v16) = v23;
            if (v6 != minX) {
                do {
                    if (v22 >= 0) {
                        v16 += v34;
                        v22 -= a2a;
                    }
                    v22 += v14;
                    a5a += a4a;
                    v16 += 4 * a4a;
                    *(DWORD *) ((char *) g_MyNBitTexture_lpSurface + v16) = v23;
                } while (a5a != minX);
            }
        }
    } else {
        if ((g_MyNBitTexture_surf_f0 & 0x20) != 0) {
            Bgraf v37;
            v37.alpha = -1;
            int v27 = (unsigned __int8) g_MyNBitTexture_fill2PaletteMap[a6_color.fill];
            v37.red = g_paletteEntries[v27].peRed;
            v37.green = g_paletteEntries[v27].peGreen;
            unsigned __int8 peBlue = g_paletteEntries[v27].peBlue;
            minY = a3;
            v37.blue = peBlue;
            *(DWORD *) &a6_color.blue = *(DWORD *) &v37.blue;
        }
        if (a2a <= v14) {
            int v31 = a2a - (v14 >> 1);
            int v32 = a6_color.blue | ((a6_color.green | (*(unsigned __int16 *) &a6_color.red << 8)) << 8);
            *(DWORD *) ((char *) g_MyNBitTexture_lpSurface + v16) = v32;
            if (minY != v9) {
                int v33 = v35;
                do {
                    if (v31 >= 0) {
                        v31 -= v14;
                        v16 += 4 * a4a;
                    }
                    v33 += v36;
                    v16 += v34;
                    v31 += a2a;
                    *(DWORD *) ((char *) g_MyNBitTexture_lpSurface + v16) = v32;
                } while (v33 != v9);
            }
        } else {
            int v29 = v14 - (a2a >> 1);
            int v30 = a6_color.blue | ((a6_color.green | (*(unsigned __int16 *) &a6_color.red << 8)) << 8);
            *(DWORD *) ((char *) g_MyNBitTexture_lpSurface + v16) = v30;
            if (v6 != minX) {
                do {
                    if (v29 >= 0) {
                        v16 += v34;
                        v29 -= a2a;
                    }
                    v29 += v14;
                    a5a += a4a;
                    v16 += 4 * a4a;
                    *(DWORD *) ((char *) g_MyNBitTexture_lpSurface + v16) = v30;
                } while (a5a != minX);
            }
        }
    }
}

