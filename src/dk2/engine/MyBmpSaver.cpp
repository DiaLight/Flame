//
// Created by DiaLight on 4/26/2026.
//
#include "dk2/MyBmpSaver.h"
#include "dk2/MySurfDesc.h"
#include "dk2/MySurface.h"
#include "dk2/resources/file/MyFile.h"
#include "dk2/resources/file/MyFile_Disc.h"
#include "dk2_functions.h"
#include "dk2_globals.h"

namespace dk2 {

    // its probably 5 separate arrays
    MySurfDesc *g_confSurfDescArr[] = {
            &g_confSurfDesc3_bpp,
            &g_confSurfDesc2_bgr24,
            NULL,
            NULL,

            &g_confSurfDesc3_bpp,
            &g_confSurfDesc2_bgr24,
            NULL,
            NULL,

            &g_confSurfDesc3_bpp,
            NULL,

            &g_confSurfDesc3_bpp,
            &g_confSurfDesc4_bgr16,
            &g_confSurfDesc2_bgr24,
            &g_confSurfDesc_bgra32,
            NULL,
            NULL,

            &g_confSurfDesc3_bpp,
            &g_confSurfDesc5_rgb16,
            &g_confSurfDesc6_rgb24,
            NULL,
    };

};

dk2::MyBmpSaver *dk2::MyBmpSaver::constructor() {
  MyBmpSaver *result = this;
  *(void **) this = &MyBmpSaver::vftable;
  this->confSurfDescArr = g_confSurfDescArr;
  return result;
}

int dk2::MyBmpSaver::isCompatibleDesc(MySurfDesc *desc) {
  for (MySurfDesc **pCur = this->confSurfDescArr; *pCur; ++pCur) {
    MySurfDesc *cur = *pCur;
    if (desc->dwRBitMask == cur->dwRBitMask &&
        desc->dwGBitMask == cur->dwGBitMask &&
        desc->dwBBitMask == cur->dwBBitMask &&
        desc->dwRGBAlphaBitMask == cur->dwRGBAlphaBitMask &&
        desc->dwRGBBitCount == cur->dwRGBBitCount &&
        (desc->isBytePerPixel == 0) == (cur->isBytePerPixel == 0)) return 1;
  }
  return 0;
}

dk2::MySurfDesc *dk2::MyBmpSaver::selectDesc(MySurface *a2) {
  MySurfDesc *result = NULL;
  for (MySurfDesc **pCur = this->confSurfDescArr; *pCur; ++pCur) {
    MySurfDesc *cur = *pCur;
    result = cur;
    if (cur->dwRGBBitCount >= a2->desc.dwRGBBitCount) break;
  }
  if (!result) return NULL;
  if (result->dwRGBBitCount == 8) return NULL;
  return result;
}

int *dk2::MyBmpSaver::save(
        int *pstatus,
        char *filePath,
        MySurface *a4_desc,
        BYTE *a5_colorTable) {
  char fileBuf[sizeof(MyFile_Disc)];
  MyFile_Disc &v9_file = *(MyFile_Disc *) fileBuf;
  v9_file.constructor_empty();
  *(void **) &v9_file = &MyFile_Disc::vftable;

  int try_level = 0;
  int status;
  if (*v9_file.openStream(&status, filePath, 0xC0000010) >= 0) {
    this->trySave(&status, &v9_file, a4_desc, a5_colorTable);
    v9_file.releaseStream();
  } else {
    status = -1;
  }
  try_level = -1;
  v9_file.destructor();
  return *pstatus = status, pstatus;
}

int *dk2::MyBmpSaver::trySave(
        int *pstatus,
        MyFile *a3_file,
        MySurface *pSurf,
        BYTE *a5_colorTable) {
  MyFile *v5_file = a3_file;
  if ( a3_file->v_seek(0, 0) ) return *pstatus = -1, pstatus;

  MySurface *pSurf_ = pSurf;
  if ( this->isCompatibleDesc(&pSurf->desc) ) {
    int status;
    this->v_MyBmpSaver_serializeBmp(&status, v5_file, pSurf_, a5_colorTable);
    return *pstatus = 0, pstatus;
  }

  MySurfDesc *selDesc = this->selectDesc(pSurf_);
  if (!selDesc) return *pstatus = -1, pstatus;

  MySurface saveSurf;
  saveSurf.constructor(&pSurf_->size, selDesc, NULL, 0);

  int status;
  if ( *saveSurf.allocSurfaceIfNot(&status) ) return *pstatus = -1, pstatus;
  int try_level = 0;
  int retStatus = -1;
  if (*MySurface_static_convertPixelType(&status, &saveSurf, pSurf_, 0) == 0) {
    this->v_MyBmpSaver_serializeBmp(&status, v5_file, &saveSurf, a5_colorTable);
    saveSurf.reset();
    retStatus = 0;
  }
  try_level = -1;
//  ret_void_0args_0(&a3_file);
  return *pstatus = retStatus, pstatus;
}
