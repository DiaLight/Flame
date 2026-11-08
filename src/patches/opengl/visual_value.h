//
// Created by DiaLight on 11/8/2026.
//

#ifndef FLAME_VISUAL_VALUE_H
#define FLAME_VISUAL_VALUE_H

#include "dk2/utils/Vec3f.h"
#include <string>

struct VisualValue {
    std::string name;
    virtual void render() = 0;
};
struct VisualBool : VisualValue {
    bool value = false;
    explicit VisualBool(const char *name, bool def = false);

    inline explicit operator bool() const { return value; }
    inline bool operator !() const { return !value; }

    void render() override;
};
struct VisualInt : VisualValue {
    int value = false;
    explicit VisualInt(const char *name, int def);

    void render() override;
};
struct VisualFloat : VisualValue {
    float value = false;
    explicit VisualFloat(const char *name, float def);
    void render() override;
};
struct VisualVec3f : VisualValue {
    dk2::Vec3f value;
    explicit VisualVec3f(const char *name);
    void render() override;
};

void visual_values_render_imgui();


#endif //FLAME_VISUAL_VALUE_H
