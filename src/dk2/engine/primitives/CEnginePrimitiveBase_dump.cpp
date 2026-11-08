//
// Created by DiaLight on 6/9/2026.
//

#include "CEnginePrimitiveBase_dump.h"
#include "dk2/engine/primitive/CEngine2DPrimitive.h"
#include "dk2/engine/primitive/CEngine2DMeshSurface.h"
#include "dk2/engine/primitive/CEngineStaticHeightField.h"
#include "dk2/engine/primitive/CEngineStaticMesh.h"
#include "dk2/engine/primitive/CEngineUnlitProceduralMesh.h"
#include "dk2/engine/primitive/2d/CEngine2DAnimMesh.h"
#include "dk2/engine/primitive/2d/CEngine2DRotatableSprite.h"
#include "dk2/engine/primitive/2d/CEngine2DSprite.h"
#include "dk2/engine/primitive/2d/CEngine2DStaticMesh.h"
#include "dk2/engine/primitive/2d/CEngineQuadPlane.h"
#include "dk2/engine/primitive/2d/CEngineSprite.h"
#include "dk2/engine/primitive/2d/CEngineVirtualPerspective2DAnimMesh.h"
#include "dk2/engine/primitive/2d/world/CEngineWorldPrimitive.h"
#include "dk2/engine/primitive/2d/world/CEngineAnimMesh.h"
#include "dk2/engine/primitive/2d/world/CEngineDynamicHeightField.h"
#include "dk2/engine/primitive/2d/world/CEngineDynamicMesh.h"
#include "dk2/MyMeshResourceHolder.h"
#include <exception>


void CEnginePrimitiveBase_format(dk2::CEnginePrimitiveBase *mesh, char *buf, size_t size) {
    if(mesh->getVtbl() == dk2::CEnginePrimitiveBase::vftable) {
        throw std::exception("unexpected");
    } else if(mesh->getVtbl() == dk2::CEngine2DMeshSurface::vftable) {
        auto *mesh1 = (dk2::CEngine2DMeshSurface *) mesh;
        snprintf(buf, size, "2dMeshSurf");
    } else if(mesh->getVtbl() == dk2::CEngine2DPrimitive::vftable) {
        throw std::exception("unexpected");
    } else if(mesh->getVtbl() == dk2::CEngine2DAnimMesh::vftable) {
        auto *mesh1 = (dk2::CEngine2DAnimMesh *) mesh;
        snprintf(buf, size, "2d/AnimMesh");
    } else if(mesh->getVtbl() == dk2::CEngine2DRotatableSprite::vftable) {
        auto *mesh1 = (dk2::CEngine2DRotatableSprite *) mesh;
        snprintf(buf, size, "2d/RotatableSprite");
    } else if(mesh->getVtbl() == dk2::CEngine2DSprite::vftable) {
        auto *mesh1 = (dk2::CEngine2DSprite *) mesh;
        snprintf(buf, size, "2d/2DSprite");
    } else if(mesh->getVtbl() == dk2::CEngine2DStaticMesh::vftable) {
        auto *mesh1 = (dk2::CEngine2DStaticMesh *) mesh;
        snprintf(buf, size, "2d/StaticMesh");
    } else if(mesh->getVtbl() == dk2::CEngineQuadPlane::vftable) {
        auto *mesh1 = (dk2::CEngineQuadPlane *) mesh;
        snprintf(buf, size, "2d/QuadPlane");
    } else if(mesh->getVtbl() == dk2::CEngineSprite::vftable) {
        auto *mesh1 = (dk2::CEngineSprite *) mesh;
        snprintf(buf, size, "2d/Sprite");
    } else if(mesh->getVtbl() == dk2::CEngineVirtualPerspective2DAnimMesh::vftable) {
        auto *mesh1 = (dk2::CEngineVirtualPerspective2DAnimMesh *) mesh;
        snprintf(buf, size, "2d/VirtualPerspective2DAnimMesh");
    } else if(mesh->getVtbl() == dk2::CEngineWorldPrimitive::vftable) {
        throw std::exception("unexpected");
    } else if(mesh->getVtbl() == dk2::CEngineAnimMesh::vftable) {
        auto *mesh1 = (dk2::CEngineAnimMesh *) mesh;
        snprintf(buf, size, "2d/world/AnimMesh");
    } else if(mesh->getVtbl() == dk2::CEngineDynamicHeightField::vftable) {
        auto *mesh1 = (dk2::CEngineDynamicHeightField *) mesh;
        snprintf(buf, size, "2d/world/DynamicHeightField");
    } else if(mesh->getVtbl() == dk2::CEngineDynamicMesh::vftable) {
        auto *mesh1 = (dk2::CEngineDynamicMesh *) mesh;
        snprintf(buf, size, "2d/world/DynamicMesh");
    } else if(mesh->getVtbl() == dk2::CEngineStaticHeightField::vftable) {
        auto *mesh1 = (dk2::CEngineStaticHeightField *) mesh;
        snprintf(buf, size, "StaticHeightField");
    } else if(mesh->getVtbl() == dk2::CEngineStaticMesh::vftable) {
        auto *mesh1 = (dk2::CEngineStaticMesh *) mesh;
        snprintf(buf, size, "StaticMesh");
    } else if(mesh->getVtbl() == dk2::CEngineUnlitProceduralMesh::vftable) {
        auto *mesh1 = (dk2::CEngineUnlitProceduralMesh *) mesh;
        snprintf(buf, size, "UnlitProceduralMesh");
    } else {
        throw std::exception("unexpected");
    }
}

namespace dk2 {

    void CEnginePrimitiveBase_hierarchy() {
        if(CEnginePrimitiveBase::vftable) {
            CEngine2DMeshSurface::vftable;  // g_Meshes2D_byConstructor_last
            CEngineStaticHeightField::vftable;  // f2C_Meshes3dStatic_byConstructor_last
            CEngineStaticMesh::vftable;  // f2C_Meshes3dStatic_byConstructor_last
            CEngineUnlitProceduralMesh::vftable;  // f30_Meshes3dDynamic_byConstructor_last
            if(CEngine2DPrimitive::vftable) {
                CEngine2DAnimMesh::vftable;  // g_Meshes2D_byConstructor_last
                CEngine2DRotatableSprite::vftable;  // g_Meshes2D_byConstructor_last
                CEngine2DSprite::vftable;  // g_Meshes2D_byConstructor_last
                CEngine2DStaticMesh::vftable;  // g_Meshes2D_byConstructor_last
                CEngineQuadPlane::vftable;  // f30_Meshes3dDynamic_byConstructor_last
                CEngineSprite::vftable;  // f2C_Meshes3dStatic_byConstructor_last f30_Meshes3dDynamic_byConstructor_last
                CEngineVirtualPerspective2DAnimMesh::vftable;  // g_Meshes2D_byConstructor_last
                if(CEngineWorldPrimitive::vftable) {
                    CEngineAnimMesh::vftable;  // f30_Meshes3dDynamic_byConstructor_last
                    CEngineDynamicHeightField::vftable;  // f30_Meshes3dDynamic_byConstructor_last
                    CEngineDynamicMesh::vftable;  // f30_Meshes3dDynamic_byConstructor_last
                }
            }
        }
    }
}


