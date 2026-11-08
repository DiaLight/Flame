//
// Created by DiaLight on 6/19/2026.
//
#include "dk2/text/render/MyTextRenderer.h"
#include "dk2/text/MyTRArgs.h"
#include "dk2/utils/AABB.h"
#include "dk2/utils/Pos2i.h"
#include "dk2/Obj62C964.h"
#include "dk2/text/render/CharImageReader.h"
#include "dk2/text/render/CharRenderCtx.h"
#include "dk2/text/render/MyFontEntryHeader.h"
#include "dk2/text/render/CharImageWriter.h"
#include "dk2/text/textmap/font/MyTextFont.h"
#include "dk2/text/MyTRBase.h"
#include "dk2/text/MyTR2.h"
#include "dk2/text/MyTR4.h"
#include "dk2/text/MyTR5.h"
#include "dk2/text/MyTR6.h"
#include "dk2/text/MyCRBase.h"
#include "dk2/text/MyCR0.h"
#include "dk2/text/MyCR1.h"
#include "dk2/text/MyCR2.h"
#include "dk2/text/MyCR3.h"
#include "dk2/text/MyDRBase.h"
#include "dk2/text/MyDR0.h"
#include "dk2/AABBc.h"
#include "dk2/TbFontRenderCallback.h"
#include "dk2/utils/Bgra.h"
#include "dk2/dk2_memory.h"
#include "dk2_functions.h"
#include "dk2_globals.h"
#include "patches/opengl/opengl_patch.h"


int *dk2::MyTextRenderer::renderText(
        int *pstatus,
        AABB *textAabb,
        BYTE *btnStr,
        FontObj *a5obj,
        AABB *a6) {

    FontObjWr *p_f4_fontObjWr = &this->fontObjWr;
    Pos2i a4;
    if (*this->fontObjWr.setRenderer(&a4.x, a5obj) < 0) return *pstatus = -1, pstatus;

    MyTRArgs args;
    args.myCR = 0;
    args.renderCtx.f0 = 0;
    args.renderCtx.renderCtx.constructor();
    args.renderCtx.activeCtx.constructor();
    args.renderCtx.f17C = 0;
    args.renderCtx.linesCount = 0;
    args.renderCtx.renderZero = 0;
    args.activeCtx.constructor();
    args.myCR = this->myCR;
    args.activeCtx.activeCtx.f0 = this->f68;
    args.linesCount = 0;
    args.activeCtx.f0 = this->f64;
    args.activeCtx.activeCtx.activeCtx.myDR = this->myDR;
    args.activeCtx.activeCtx.activeCtx.activeCtx.pMyTextFont = a5obj->getFont_addRef();
    args.activeCtx.activeCtx.activeCtx.activeCtx.f18 = this->f74;
    args.activeCtx.activeCtx.activeCtx.activeCtx.strPos = (char *) btnStr;
    args.activeCtx.activeCtx.activeCtx.activeCtx.pTbFontRenderCallback = a5obj->pTbFontRenderCallback;
    args.activeCtx.activeCtx.activeCtx.activeCtx.pFontObjWr = p_f4_fontObjWr;
    args.activeCtx.activeCtx.activeCtx.activeCtx.pChrStart = &this->curX;

    this->curX = textAabb->minX;
    this->_end_f7C_curY = textAabb->minY;
    if (this->f75) {
        a4.x = 0;
        unsigned int len = strlen((char *) btnStr) + 1;
        Obj62C964 *f70_pObj62C964 = this->pObj62C964;
        a4.y = 0;
        Pos2i *f4_buf = f70_pObj62C964->buf;
        unsigned int size = f4_buf ? f70_pObj62C964->pos - f4_buf : 0;
        if (size >= len) {
            if (len < f70_pObj62C964->getLength())
                f70_pObj62C964->sub_62D270(&f70_pObj62C964->buf[len], f70_pObj62C964->pos);
        } else {
            int v22 = f4_buf ? f70_pObj62C964->pos - f4_buf : 0;
            f70_pObj62C964->sub_62D000(f70_pObj62C964->pos, len - v22, &a4);
        }
        args.activeCtx.activeCtx.activeCtx.activeCtx.pPos2i = this->pObj62C964->buf;
    }

    AABBc v33_aabb;
    memset(&v33_aabb.bb, 0, sizeof(v33_aabb.bb));
    v33_aabb.c = 0;

    AABB v35_aabb;
    memset(&v35_aabb, 0, sizeof(v35_aabb));

    this->myTR->v_linesOneTypeEx_doCalcAabbAndDraw_verticalMiddle(
            textAabb,
            &args,
            &v35_aabb,
            &v33_aabb);

    if (this->f75) {
        Obj62C964 *v24 = this->pObj62C964;
        a4.x = 0;
        a4.y = 0;
        Pos2i *v25 = v24->buf;
        unsigned int v26 = v25 ? v24->pos - v25 : 0;
        if (v26 >= args.activeCtx.activeCtx.activeCtx.activeCtx.index) {
            unsigned int v28 = v25 ? v24->pos - v25 : 0;
            if (args.activeCtx.activeCtx.activeCtx.activeCtx.index < v28) {
                v24->sub_62D270(
                        &v25[args.activeCtx.activeCtx.activeCtx.activeCtx.index],
                        v24->pos);
            }
        } else {
            int v27 = v25 ? v24->pos - v25 : 0;
            v24->sub_62D000(
                    v24->pos,
                    args.activeCtx.activeCtx.activeCtx.activeCtx.index - v27,
                    &a4);
        }
    }
    if (a6) *a6 = v33_aabb.bb;
    args.activeCtx.activeCtx.activeCtx.activeCtx.pMyTextFont->v_release();

    return *pstatus = 0, pstatus;
}

int dk2::MyTR2::linesOneTypeEx_doCalcAabbAndDraw_verticalMiddle(
        AABB *aabb,
        MyTRArgs *args,
        AABB *textAabb,
        AABBc *out_a5) {
    int v6 = this->v_linesOneTypeEx_doCalcAabb_verticalMiddle(aabb, args, textAabb);
    // if !isRegularChar && !isEndOfString
    if (v6 != 1 && v6 != 3)
        return 1;
    // align center vertically
    AABB renderAabb;
    renderAabb.minX = aabb->minX;
    renderAabb.maxX = aabb->maxX;
    renderAabb.maxY = aabb->maxY;
    renderAabb.minY = (aabb->maxY + textAabb->minY - aabb->minY - textAabb->maxY) / 2 + aabb->minY;
    args->activeCtx = args->renderCtx;
    this->v_linesOneTypeEx_doDrawOrCalcAabb(1, &renderAabb, args, textAabb, out_a5);
    return 1;
}

int dk2::MyTR4::linesOneTypeEx_doCalcAabbAndDraw_verticalMiddle(
        AABB *a2,
        MyTRArgs *a3,
        AABB *a4,
        AABBc *out_a5) {
    int v6 = this->v_linesOneTypeEx_doCalcAabb_verticalMiddle(a2, a3, a4);
    if (v6 != 1 && v6 != 3)
        return 1;
    a3->activeCtx = a3->renderCtx;
    this->v_linesOneTypeEx_doDrawOrCalcAabb(1, a2, a3, a4, out_a5);
    return 1;
}

int dk2::MyTR5::linesOneTypeEx_doCalcAabbAndDraw_verticalMiddle(
        AABB *a2,
        MyTRArgs *a3,
        AABB *a4,
        AABBc *out_a5) {
    int v6 = this->v_linesOneTypeEx_doCalcAabb_verticalMiddle(a2, a3, a4);
    if (v6 != 1 && v6 != 3)
        return 1;
    AABB v11;
    v11.minX = a2->minX;
    v11.maxX = a2->maxX;
    v11.maxY = a2->maxY;
    v11.minY = a2->maxY + a4->minY - a2->minY - a4->maxY + a2->minY;
    a3->activeCtx = a3->renderCtx;
    this->v_linesOneTypeEx_doDrawOrCalcAabb(1, &v11, a3, a4, out_a5);
    return 1;
}

int dk2::MyTR6::linesOneTypeEx_doCalcAabbAndDraw_verticalMiddle(
        AABB *a2,
        MyTRArgs *a3,
        AABB *a4,
        AABBc *out_a5) {
    int v6 = this->v_linesOneTypeEx_doCalcAabb_verticalMiddle(a2, a3, a4);
    if (v6 != 1 && v6 != 3)
        return 1;
    AABB v9;
    v9.minX = a2->minX;
    v9.maxX = a2->maxX;
    v9.maxY = a2->maxY;
    v9.minY = (a4->minY + v9.maxY - a4->maxY - a2->minY) / 2 + a2->minY;
    a3->activeCtx = a3->renderCtx;
    this->v_linesOneTypeEx_doDrawOrCalcAabb(1, &v9, a3, a4, out_a5);
    return 1;
}

int dk2::MyTRBase::linesOneTypeEx_doDrawOrCalcAabb(
        int isDraw,
        AABB *aabb,
        MyTRArgs *args,
        AABB *out_aabb,
        AABBc *out_a5) {
    AABB aabb_cpy = *aabb;
    AABB charsAabb;
    memset(&charsAabb, 0, sizeof(charsAabb));
    args->renderCtx = args->activeCtx;
    args->linesCount = 0;
    AABB commonAabb;
    memset(&commonAabb, 0, sizeof(commonAabb));
    char isFirstChars = 0;
    AABB tmpAabb;
    int charsType;
    do {
        charsType = args->myCR->v_chars_doCalcAabbInMiddle(
                &aabb_cpy,
                &args->activeCtx,
                &charsAabb);
        // if !isInvalidChar
        if (charsType != 2) {
            ++args->linesCount;
            if (isDraw)
                args->myCR->v_chars_doCalcAabbAndRenderInMiddle(
                        &aabb_cpy,
                        &args->renderCtx,
                        &charsAabb,
                        out_a5);
        }
        int maxY = charsAabb.maxY;
        if (charsAabb.minX != charsAabb.maxX || charsAabb.minY != charsAabb.maxY) {
            if (isFirstChars) {
                commonAabb = *commonAabb.getOuter(&tmpAabb, &charsAabb);
                maxY = charsAabb.maxY;
            } else {
                commonAabb = charsAabb;
            }
            isFirstChars = 1;
        }
        aabb_cpy.minY = maxY;
    } while (charsType == 1);
    *out_aabb = commonAabb;
    // if isEndOfString
    if (charsType == 3) return charsType;
    if (!charsType) return charsType;
    return 1;
}

int dk2::MyCR0::chars_doCalcAabbAndRenderInMiddle(
        AABB *a2,
        MyMultilineRenderCtx *a3,
        AABB *a4,
        AABBc *out_a5) {
    int v5 = this->v_chars_doCalcAabbInMiddle(a2, a3, a4);
    if (v5 != 1 && v5 != 3) return 1;
    a3->activeCtx = a3->renderCtx;
    a3->renderZero = 0;
    chars_doDrawOrCalcAabb(1, a2, a3, a4, out_a5);
    return 1;
}

int dk2::MyCR1::chars_doCalcAabbAndRenderInMiddle(
        AABB *a2,
        MyMultilineRenderCtx *a3,
        AABB *a4,
        AABBc *out_a5) {
    int v5 = this->v_chars_doCalcAabbInMiddle(a2, a3, a4);
    if (v5 != 1 && v5 != 3)
        return 1;
    a3->renderZero = 0;
    AABB v9;
    v9.minY = a2->minY;
    v9.maxX = a2->maxX;
    v9.maxY = a2->maxY;
    v9.minX = a4->minX + a2->maxX - a4->maxX - a2->minX + a2->minX;
    a3->activeCtx = a3->renderCtx;
    chars_doDrawOrCalcAabb(1, &v9, a3, a4, out_a5);
    return 1;
}

int dk2::MyCR2::chars_doCalcAabbAndRenderInMiddle(
        AABB *aabb,
        MyMultilineRenderCtx *ctx,
        AABB *out_aabb,
        AABBc *out_a5) {
    int v5 = this->v_chars_doCalcAabbInMiddle(aabb, ctx, out_aabb);
    // if !isRegularChar && !isEndOfString
    if (v5 != 1 && v5 != 3)
        return 1;
    ctx->renderZero = 0;
    AABB v9;
    v9.minY = aabb->minY;
    v9.maxX = aabb->maxX;
    v9.maxY = aabb->maxY;
    v9.minX = (out_aabb->minX + aabb->maxX - out_aabb->maxX - aabb->minX) / 2 + aabb->minX;
    ctx->activeCtx = ctx->renderCtx;
    chars_doDrawOrCalcAabb(1, &v9, ctx, out_aabb, out_a5);
    return 1;
}

int dk2::chars_doDrawOrCalcAabb(int isDraw, AABB *aabb, MyMultilineRenderCtx *c2, AABB *out_aabb, AABBc *out_a5) {
    c2->renderCtx = c2->activeCtx;
    c2->linesCount = 0;
    AABB src_aabb;
    src_aabb.minX = aabb->minX;
    src_aabb.minY = aabb->minY;
    src_aabb.maxX = aabb->maxX;
    src_aabb.maxY = 0x7FFFFFFF;

    AABB charsAabb;
    memset(&charsAabb, 0, sizeof(charsAabb));

    AABBc commonAabb_;
    commonAabb_.c = 0;
    memset(&commonAabb_, 0, 16);

    AABB commonAabb;
    int i;
    for (i = charsOneTypeEx_doCalcAabb(&src_aabb, &c2->activeCtx, &charsAabb);
         i == 1;  // isRegularChar
         i = charsOneTypeEx_doCalcAabb(&src_aabb, &c2->activeCtx, &charsAabb)) {
        if (isDraw)
            charsOneTypeEx_doCalcAabbAndDraw(&src_aabb, &c2->renderCtx, &charsAabb, out_a5);
        if (charsAabb.minX != charsAabb.maxX || charsAabb.minY != charsAabb.maxY) {
            AABB *pCommonAabb_;
            if (commonAabb_.c)
                pCommonAabb_ = commonAabb_.bb.getOuter(&commonAabb, &charsAabb);
            else
                pCommonAabb_ = &charsAabb;
            commonAabb_.constructor(pCommonAabb_);
        }
        ++c2->linesCount;
        src_aabb.minX = charsAabb.maxX;
    }
    // i == 3  // isEndOfString
    if (i == 3 && (charsAabb.minX != charsAabb.maxX || charsAabb.minY != charsAabb.maxY)) {
        if (commonAabb_.c) {
            commonAabb_.constructor(commonAabb_.bb.getOuter(&commonAabb, &charsAabb));
        } else {
            commonAabb_.constructor(&charsAabb);
        }
    }
    // i == 2  // isInvalidChar
    AABB *v8;
    if (i == 2) {
        v8 = aabb;
        if (charsAabb.maxX - charsAabb.minX > aabb->maxX - aabb->minX) {
            c2->activeCtx.activeCtx.myDR->v_MyDR67B9E0_sub_62E8C0(
                    isDraw,
                    &src_aabb,
                    &c2->activeCtx.activeCtx.activeCtx,
                    &charsAabb,
                    out_a5);
            if (charsAabb.minX != charsAabb.maxX || charsAabb.minY != charsAabb.maxY) {
                if (commonAabb_.c) {
                    AABB *Outer = commonAabb_.bb.getOuter(&commonAabb, &charsAabb);
                    commonAabb_.constructor(Outer);
                } else {
                    commonAabb_.constructor(&charsAabb);
                }
            }
        }
    } else {
        v8 = aabb;
    }
    // i == 4  // isSpaceChar

    AABB res;
    if (i != 4) {
        res = commonAabb_.bb;
    } else {
        res.minY = v8->minY;
        res.maxX = v8->minX;
        res.maxY = v8->minY + c2->activeCtx.activeCtx.activeCtx.pMyTextFont->v_getMaxHeight();
        commonAabb.minX = v8->minX;
        commonAabb.maxX = v8->minX;

        commonAabb.minY = res.minY;
        commonAabb.maxY = res.maxY;
        if (res.minY == res.maxY) {
            res = commonAabb_.bb;
        } else if (commonAabb_.c) {
            AABB v21;
            AABB *v14 = commonAabb_.bb.getOuter(&v21, &commonAabb);
            res = *v14;
            commonAabb_.bb.minX = v14->minX;
            commonAabb_.bb.minY = v14->minY;
            commonAabb_.bb.maxX = v14->maxX;
        } else {
            res.minX = res.maxX;
        }
    }
    *out_aabb = res;
    // i == 3  // isEndOfString
    if (i == 3) {
        ++c2->linesCount;
    } else {
        if (i) return 1;
    }
    return i;
}

int dk2::charsOneTypeEx_doCalcAabbAndDraw(AABB *aabb, MyTRCtx *ctx, AABB *out_aabb, AABBc *a4) {
    int v4; // eax

    v4 = charsOneTypeEx_doCalcAabb(aabb, ctx, out_aabb);
    if ( v4 != 1 && v4 != 3 )
        return 1;
    ctx->activeCtx = ctx->renderCtx;
    charsOneTypeEx_doDrawOrCalcAabb(1, aabb, ctx, out_aabb, a4);
    return 1;
}

int dk2::charsOneTypeEx_doDrawOrCalcAabb(int isDraw, AABB *aabb, MyTRCtx *ctx, AABB *out_aabb, AABBc *a5_out) {
    AABB charsAabb;
    memset(&charsAabb, 0, sizeof(charsAabb));
    MyCRCtx *p_f60_activeCtx = &ctx->activeCtx;
    AABB cur_aabb = *aabb;
    ctx->renderCtx = ctx->activeCtx;
    // 0 - unknown
    // 1 - regular char
    // 2 - invalid char
    // 3 - end of string '\0'
    // 4 - space char
    int chrType = charsOneType_doCalcAabb(&cur_aabb, &ctx->activeCtx, &charsAabb);
    *out_aabb = charsAabb;
    switch (chrType) {
        case 1:
            if (ctx->activeCtx.chrType == 2) {  // (MBChar) 11, 12
                int __maxX = charsAabb.maxX;
                int __maxY = charsAabb.maxY;
                AABB res {0, 0, 0, 0};
                char v19 = 0;
                if (charsAabb.minX != __maxX || charsAabb.minY != __maxY) {
                    if (v19) {
                        AABB v22;
                        res = *res.getOuter(&v22, &charsAabb);
                        __maxX = charsAabb.maxX;
                    } else {
                        res = charsAabb;
                    }
                    v19 = 1;
                }
                cur_aabb.minX = __maxX;
                MyCRCtx ctx_cpy = *p_f60_activeCtx;
                int result = charsOneType_doCalcAabb(&cur_aabb, p_f60_activeCtx, &charsAabb);
                if (result == 1) {
                    if (isDraw) {
                        cur_aabb = *aabb;
                        charsOneType_doCalcAabbAndDraw(&cur_aabb, &ctx->renderCtx, &charsAabb, a5_out);
                        res = charsAabb;
                        cur_aabb.minX = charsAabb.maxX;
                        v19 = 1;
                        result = charsOneType_doCalcAabbAndDraw(&cur_aabb, &ctx_cpy, &charsAabb, a5_out);
                    }
                    if (charsAabb.minX != charsAabb.maxX || charsAabb.minY != charsAabb.maxY) {
                        if (v19) {
                            AABB v22;
                            AABB *Outer = res.getOuter(&v22, &charsAabb);
                            res = *Outer;
                        } else {
                            res = charsAabb;
                        }
                    }
                } else if (result != 3) {
                    *p_f60_activeCtx = ctx_cpy;
                }
                *out_aabb = res;
                return result;
            }
            if (isDraw) {
                charsOneType_doCalcAabbAndDraw(&cur_aabb, &ctx->renderCtx, &charsAabb, a5_out);
            }
            *out_aabb = charsAabb;
            return 1;
        case 2:
            return 2;
        case 3:
            return 3;
        case 4:
            return 4;
        default:
            return 0;
    }
}

int dk2::charsOneType_doCalcAabbAndDraw(AABB *aabb, MyCRCtx *ctx, AABB *out_aabb, AABBc *a4) {
    int v4 = charsOneType_doCalcAabb(aabb, ctx, out_aabb);
    if ( v4 != 1 && v4 != 3 )
        return 1;
    ctx->activeCtx = ctx->saved;
    charsOneType_doDrawOrCalcAabb(1, aabb, ctx, out_aabb, a4);
    return 1;
}

int dk2::charsOneType_doDrawOrCalcAabb(int isDraw, AABB *aabb, MyCRCtx *ctx, AABB *out_aabb, AABBc *a5_out) {
    AABB commonAabb;
    memset(&commonAabb, 0, sizeof(commonAabb));
    char isFirstChar = 0;

    AABB charAabb;
    memset(&charAabb, 0, sizeof(charAabb));

    AABB aabb_cpy;
    aabb_cpy = *aabb;

    MyCharRenderCtx *p_activeCtx = &ctx->activeCtx;
    MyCharRenderCtx *savedCtx = &ctx->saved;
    *savedCtx = *&ctx->activeCtx;

    int result;
    switch (ctx->myDR->v_doCalcAabbOrRender_0((Pos2i *) &aabb_cpy, p_activeCtx, &charAabb)) {
        case 1: {  // regular char
            int f4_chrType = ctx->activeCtx.chrType;
            ctx->visitedChars = 0;
            ctx->chrType = f4_chrType;
            MyCharRenderCtx lastRegularTypeCtx;
            do {
                if (isDraw)
                    ctx->myDR->v_doRender(&aabb_cpy, savedCtx, &charAabb, a5_out);
                int maxX = charAabb.maxX;
                if (charAabb.minX != charAabb.maxX || charAabb.minY != charAabb.maxY) {
                    if (isFirstChar) {
                        AABB tmpAabb;
                        commonAabb = *commonAabb.getOuter(&tmpAabb, &charAabb);
                        maxX = charAabb.maxX;
                    } else {
                        commonAabb = charAabb;
                    }
                    isFirstChar = 1;
                }
                ++ctx->visitedChars;
                lastRegularTypeCtx = *p_activeCtx;
                aabb_cpy.minX = maxX;
                ctx->myDR->v_doCalcAabbOrRender_0((Pos2i *) &aabb_cpy, p_activeCtx, &charAabb);
            } while (ctx->activeCtx.chrType == ctx->chrType);
            *p_activeCtx = lastRegularTypeCtx;
            *out_aabb = commonAabb;
            if (
                    aabb->minX <= commonAabb.minX &&
                    aabb->minY <= commonAabb.minY &&
                    aabb->maxX >= commonAabb.maxX &&
                    aabb->maxY >= commonAabb.maxY) {
                result = 1;
            } else {
                result = 2;
                if (ctx->chrType != 2) {
                    *p_activeCtx = *savedCtx;
                }
            }
        } break;
        case 2:  // invalid char
            result = 2;
            break;
        case 3: {  // end of string '\0'
            *out_aabb = charAabb;
            result = 3;
        } break;
        case 4:  // space char
            result = 4;
            break;
        default:
            result = 0;
            break;
    }
    return result;
}

int dk2::MyDR0::doRender(Pos2i *pos, MyCharRenderCtx *ctx, AABB *out_aabb, AABBc *a5_out) {
    return this->v_doCalcAabbOrRender(1, pos, ctx, out_aabb, a5_out);
}

int dk2::MyDR0::doCalcAabbOrRender(
        int isRender,
        Pos2i *pos,
        MyCharRenderCtx *c2_ctx,
        AABB *out_aabb,
        AABBc *a6_out) {
    int status;
    AABB cur_aabb;
    Pos2i *f24_pChrStart = (Pos2i *) c2_ctx->pChrStart;

    Pos2i chrPos;
    chrPos.x = pos->x;
    chrPos.y = pos->y;
    *f24_pChrStart = chrPos;
    char **p_f8_strPos = &c2_ctx->strPos;
    if (!*c2_ctx->strPos) {
        c2_ctx->chrType = 4;
        out_aabb->minX = pos->x;
        out_aabb->minY = pos->y;
        out_aabb->maxX = pos->x;
        out_aabb->maxY = pos->y + c2_ctx->pMyTextFont->v_getMaxHeight();
        return 3;
    }
    if (Pos2i *f20_pPos2i = c2_ctx->pPos2i) {
        f20_pPos2i[c2_ctx->index] = chrPos;
    }
    int fontChrIdx = c2_ctx->pMyTextFont->v_readMBCharToFontIdx(&c2_ctx->strPos);
    int fontChrIdx_ = fontChrIdx;
    ++c2_ctx->index;
    if ((WORD) fontChrIdx == 0xD) {  // space char
        c2_ctx->chrType = 3;
        return 4;
    }
    if ((WORD) fontChrIdx != 0x13) {
        c2_ctx->fontChrIdx = fontChrIdx;
        c2_ctx->chrType = get_chr_type(fontChrIdx);
        if (isRender) {
            memset(&cur_aabb, 0, sizeof(cur_aabb));
            c2_ctx->pFontObjWr->renderChar(&status, &chrPos, c2_ctx->fontChrIdx, &cur_aabb);
            if (cur_aabb.minX != cur_aabb.maxX || cur_aabb.minY != cur_aabb.maxY) {
                if (a6_out->c) {
                    AABB v39;
                    a6_out->bb = *a6_out->bb.getOuter(&v39, &cur_aabb);
                } else {
                    a6_out->bb = cur_aabb;
                }
                a6_out->c = 1;
            }
        }
        Pos2i *chrSize = c2_ctx->pMyTextFont->v_getCharSize((Pos2i *) &cur_aabb, fontChrIdx_);
        out_aabb->minX = chrPos.x;
        out_aabb->minY = chrPos.y;
        out_aabb->maxX = chrPos.x + chrSize->x;
        out_aabb->maxY = chrPos.y + chrSize->y;
        return 1;
    }
    int v20_ch = (unsigned __int8) *(*p_f8_strPos)++;
    c2_ctx->fontChrIdx = 19;
    int v21_chTy = get_chr_type(19);
    TbFontRenderCallback *f14_pTbFontRenderCallback = c2_ctx->pTbFontRenderCallback;
    c2_ctx->chrType = v21_chTy;
    if (!f14_pTbFontRenderCallback)
        return 1;
    if (!isRender) {
        f14_pTbFontRenderCallback->v_fun_42D1C0(
                &status, v20_ch,
                g_MyNBitTexture_myRenderSurface,
                pos, out_aabb);
        return 1;
    }
    memset(&cur_aabb, 0, sizeof(cur_aabb));
    f14_pTbFontRenderCallback->v_fun_42D090(
            &status, v20_ch,
            g_MyNBitTexture_myRenderSurface,
            pos, out_aabb, &cur_aabb);
    if (cur_aabb.minX == cur_aabb.maxX && cur_aabb.minY == cur_aabb.maxY) return 1;
    if (a6_out->c) {
        AABB v39;
        a6_out->bb = *a6_out->bb.getOuter(&v39, &cur_aabb);
        a6_out->c = 1;
    } else {
        a6_out->constructor(&cur_aabb);
    }
    return 1;
}

int *dk2::FontObjWr::renderChar(int *pstatus, Pos2i *chrPos, int fontChrIdx, AABB *out_aabb) {
    if (MyFontRendererBase *f54_tobj = this->tobj) {
        f54_tobj->v_renderChar(pstatus, &chrPos->x, fontChrIdx, out_aabb, &this->fontObj);
        return pstatus;
    }
    return *pstatus = -1, pstatus;
}



int *dk2::MyFontRendererBase::renderChar(
        int *pstatus,
        Pos2i *chrPos,
        int fontChrIdx,
        AABB *out_aabb,
        FontObj *fontObj) {
    int status;
    MySurface *mySurface = g_MyNBitTexture_myRenderSurface;
    MyTextFont *textFont = fontObj->getFont_addRef();
    if (!textFont) {
        textFont->v_release();  // programmer mistake
        return *pstatus = -1, pstatus;
    }
    if (mySurface->desc.isBytePerPixel) {
        textFont->v_release();
        return *pstatus = -1, pstatus;
    }
    MyFontEntryHeader *charDesc = textFont->getCharDesc(fontChrIdx);
    uint8_t *charBuf = textFont->getCharBuffer(fontChrIdx);
    uint8_t *charBuf_ = charBuf;
    if (!charBuf) {
        textFont->v_release();
        return *pstatus = -1, pstatus;
    }
    // flag 1 - repetitives is compressed
    if ((charDesc->flags & 1) != 0) {
        if ((g_lazyInitFlags2 & 1) == 0) {
            g_charBufferSize = 0x800;
            g_lazyInitFlags2 |= 1u;
            g_charBuffer = dk2::operator_new(0x800u);
            atexit(gCharBuffer_static_destructor);
        }
        if (charDesc->dataSize > (signed int) g_charBufferSize) {
            g_charBufferSize = charDesc->dataSize;
            dk2::operator_delete(g_charBuffer);
            g_charBuffer = dk2::operator_new(g_charBufferSize);
        }
        CharImageReader reader;
        reader.isLowByte = 0;
        reader.charBuf = charBuf;

        CharImageWriter writer;
        writer.buf = g_charBuffer;
        writer.isLowByte = 0;
        writer.calcOnly = 0;
        writer.pixCount = 0;

        CharImageReader v51;
        CharImageReader v50;
        CharImageReader v49;

        char isExit = 0;
        do {
            CharImageReader *pCharImage = reader.next(&v51, 0);
            uint8_t pix = pCharImage->read();
            if (pix) {
                writer.write(pix);
            } else {  // zero - means custom handle
                CharImageReader *pCharImage_ = reader.next(&v50, 0);
                pix = pCharImage_->read();
                if (pix) {
                    int pix_1 = pix;
                    CharImageReader *_pCharImage = reader.next(&v49, 0);
                    pix = _pCharImage->read();
                    for (int i = 0; i < pix_1; ++i) {
                        writer.write(pix);
                    }
                } else {  // double zero means exit
                    isExit = 1;
                }
            }
        } while (!isExit);
    }
    // flags2 is double size and bit per pixel
    if ((charDesc->flags & 2) != 0) {
        if ((g_lazyInitFlags2 & 1) == 0) {
            g_lazyInitFlags2 |= 1u;
            g_charBufferSize = 2048;
            g_charBuffer = dk2::operator_new(0x800u);
            atexit(gCharBuffer_static_destructor);
        }
        if (charDesc->dataSize > (signed int) g_charBufferSize) {
            g_charBufferSize = charDesc->dataSize;
            dk2::operator_delete(g_charBuffer);
            g_charBuffer = dk2::operator_new(g_charBufferSize);
        }

        CharImageReader reader;
        reader.isLowByte = 0x80;
        reader.charBuf = (uint8_t *) charBuf_;
        CharImageWriter writer;
        writer.constructor(g_charBuffer, 0);
        CharImageReader v50;
        CharImageReader v49;
        for (int i = 0; i < 2 * charDesc->dataSize; ++i) {
            CharImageReader *v21 = reader.next2(&v50, 0);
            CharImageReader *v22 = v21->copy(&v49);
            writer.write((v22->isLowByte & *v22->charBuf) != 0 ? 0xF : 0);
        }
    }

    AABB charAabb;
    charAabb.maxX = (uint16_t) charDesc->width;
    charAabb.maxY = (uint16_t) charDesc->height;
    charAabb.minX = 0;
    charAabb.minY = 0;

    int x = chrPos->x;
    int y = chrPos->y;

    Pos2i pos;
    pos.x = x;
    pos.y = y;
    if (charDesc->chr == ' ') {
        out_aabb->minX = x;
        out_aabb->minY = y;
        out_aabb->maxX = x;
        out_aabb->maxY = y;
        textFont->v_release();
        return *pstatus = 0, pstatus;
    }
    pos.x = charDesc->offsX + x;
    pos.y = charDesc->offsY + y;

    AABB renderPlace;
    AABB_probably_alignToSurface(&renderPlace, &charAabb, &pos, mySurface);
    if (renderPlace.minX == renderPlace.maxX || renderPlace.minY == renderPlace.maxY) {
        textFont->v_release();
        return *pstatus = -1, pstatus;
    }
    AABB *CharRenderSurfAabb = getCharRenderSurfAabb();

    int minX = CharRenderSurfAabb->minX;
    int minY = CharRenderSurfAabb->minY;
    MySurfDesc desc__;
    desc__.dwBBitMask = CharRenderSurfAabb->maxX;
    int pos_x = pos.x;
    desc__.dwRGBAlphaBitMask = CharRenderSurfAabb->maxY;
    if (pos.x < minX) {
        pos_x = minX;
        pos.x = minX;
    }
    int pos_y = pos.y;
    if (pos.y < minY) {
        pos_y = minY;
        pos.y = minY;
    }

    out_aabb->minX = pos_x;
    out_aabb->minY = pos_y;
    out_aabb->maxX = pos_x + renderPlace.maxX - renderPlace.minX;
    out_aabb->maxY = pos_y + renderPlace.maxY - renderPlace.minY;

    CharRenderCtx rctx;
    rctx.fontObj = fontObj;
    rctx.pos = &pos;
    rctx.area = &renderPlace;

    // flag3 is raw char buf
    uint8_t *char_buf;
    if ((charDesc->flags & 3) != 0) {
        if ((g_lazyInitFlags2 & 1) == 0) {
            g_lazyInitFlags2 |= 1u;
            g_charBufferSize = 2048;
            g_charBuffer = dk2::operator_new(0x800u);
            atexit(gCharBuffer_static_destructor);
        }
        char_buf = (uint8_t *) g_charBuffer;
    } else {
        char_buf = (uint8_t *) charBuf_;
    }
    rctx.buf = char_buf;
    rctx.half_width = ((uint16_t) charDesc->width + 1) / 2;
    rctx.width = charDesc->width;

    int isRendered = 0;
    int retStatus = 0;

    char kindStr[64] {0};
    {  // patch
        if(this->getVtbl() == MyFontRenderer0::vftable) {
            snprintf(kindStr, 64, "MyFontRenderer0");
        } else if(this->getVtbl() == MyFontRenderer2::vftable) {
            snprintf(kindStr, 64, "MyFontRenderer2");
        } else if(this->getVtbl() == MyFontRenderer3::vftable) {
            snprintf(kindStr, 64, "MyFontRenderer3");
        } else if(this->getVtbl() == MyFontRenderer4::vftable) {
            snprintf(kindStr, 64, "MyFontRenderer4");
        }
    }

    desc__.constructor(0x7C00, 0x3E0, 0x1F, 0x8000, 16, 0);
    if (mySurface->desc.eq(&desc__)) {
        retStatus = *this->v_render_r5g5b5a1(&status, mySurface, &rctx);
        isRendered = 1;
    } else {
        desc__.constructor(0x7C00, 0x3E0, 0x1F, 0, 16, 0);
        if (mySurface->desc.eq(&desc__)) {
            retStatus = *this->v_render_r5g5b5a1(&status, mySurface, &rctx);
            isRendered = 1;
        }
    }
    desc__.constructor(0xF800, 0x7E0, 0x1F, 0, 16, 0);
    if (mySurface->desc.eq(&desc__)) {
        retStatus = *this->v_render_r5g6b5(&status, mySurface, &rctx);
        isRendered = 1;
    }
    desc__.constructor(0xF00, 0xF0, 0xF, 0xF000, 16, 0);
    if (mySurface->desc.eq(&desc__)) {
        retStatus = *this->v_render_r4g4b4a4(&status, mySurface, &rctx);
        isRendered = 1;
    }
    desc__.constructor(0xFF0000, 0xFF00, 0xFF, 0xFF000000, 32, 0);
    if (mySurface->desc.eq(&desc__)) {
        retStatus = *this->v_render_r8g8b8a8(&status, mySurface, &rctx);
        isRendered = 1;
    } else {
        desc__.constructor(0xFF0000, 0xFF00, 0xFF, 0, 32, 0);
        if (mySurface->desc.eq(&desc__)) {
            retStatus = *this->v_render_r8g8b8a8(&status, mySurface, &rctx);
            isRendered = 1;
        }
    }
    if (!isRendered) {
        retStatus = *this->v_render_6319F0(&status, mySurface, &rctx);
    }
    textFont->v_release();
    return *pstatus = retStatus, pstatus;
}

int *dk2::MyFontRenderer4::render_r8g8b8a8(
        int *pstatus,
        MySurface *dst,
        CharRenderCtx *a4_ctx) {
    CharRenderCtx *v4_ctx = a4_ctx;
    int f14_width = (uint8_t) a4_ctx->width;
    Bgra v25_color = *(Bgra * ) & a4_ctx->fontObj->color;
    char *lineDst = (char *) dst->lpSurface + 4 * a4_ctx->pos->x + dst->lPitch * a4_ctx->pos->y;
    AABB *fC_area = a4_ctx->area;
    unsigned int v7 = fC_area->minX + f14_width * fC_area->minY;
    BYTE *posSrcAlpha = &a4_ctx->buf[v7 >> 1];
    bool v8 = (v7 & 1) != 0;
    int v21_red_shl16 = v25_color.red << 16;
    int f0_blue = v25_color.blue;
    int v22_green_shl8 = v25_color.green << 8;
    int v9 = f14_width + fC_area->minX - fC_area->maxX;
    int v26 = v9;
    int v10_height = fC_area->maxY - fC_area->minY;
    if (v10_height) {
        int v20_y = v10_height;
        do {
            int *posDst = (int *) lineDst;
            if (v4_ctx->area->maxX != v4_ctx->area->minX) {
                int v18_width = v4_ctx->area->maxX - v4_ctx->area->minX;
                bool v27;
                while (true) {
                    uint32_t pix = *posDst;
                    BYTE *pAlphaSrc = posSrcAlpha;
                    if (v8)
                        ++posSrcAlpha;
                    v27 = !v8;

                    uint8_t alphaSrc = *pAlphaSrc;
                    uint8_t v17 = v8 ? alphaSrc & 0xF : alphaSrc >> 4;
                    uint32_t blue = ((pix & 0xFF) + v17 * (f0_blue - (pix & 0xFFu)) / 0xF) & 0xFF;
                    uint32_t green_shl8 = ((pix & 0xFF00) + v17 * (v22_green_shl8 - (pix & 0xFF00u)) / 0xF) & 0xFF00;
                    uint32_t red_shl16 = ((pix & 0xFFFF0000) + v17 * (v21_red_shl16 - (pix & 0xFF0000u)) / 0xF) & 0xFF0000;
                    uint32_t alpha_shl24 = pix & 0xFF000000;

                    if(patch::opengl_patch::enabled) {
                        // I am always using alpha textures. Don't preserve alpha on full alpha
                        if(alpha_shl24 == 0) alpha_shl24 = alphaSrc << 24;
                    }

                    *posDst = blue | green_shl8 | red_shl16 | alpha_shl24;
                    posDst++;
                    if (!--v18_width)
                        break;
                    v8 = v27;
                }
                v4_ctx = a4_ctx;
                v9 = v26;
                v8 = v27;
            }
            lineDst += dst->lPitch;
            if (v9) {
                if ((v9 & 1) != 0) {
                    if (v8) {
                        posSrcAlpha += (unsigned int) (v9 + 1) >> 1;
                        v8 = !v8;
                    } else {
                        posSrcAlpha += (unsigned int) v9 >> 1;
                        v8 = 1;
                    }
                } else {
                    posSrcAlpha += (unsigned int) v9 >> 1;
                }
            }
            --v20_y;
        } while (v20_y);
    }
    return *pstatus = 0, pstatus;
}


