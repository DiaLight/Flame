//
// Created by DiaLight on 11/8/2026.
//

#include "visual_value.h"
#include "imgui.h"
#include <map>
#include <vector>
#include <memory>
#include <sstream>


struct VisualNode {
    std::map<std::string, std::unique_ptr<VisualNode>> map;
    std::vector<VisualValue *> leafs;

    void render() {
        for(auto &e : map) {
            if (ImGui::TreeNode(e.first.c_str())) {
                e.second->render();
                ImGui::TreePop();
            }
        }
        for(auto *pl : leafs) {
            pl->render();
        }
    }

};

VisualNode *g_debugRoot = nullptr;

std::vector<std::string> split(const std::string &str, char separator) {
    std::vector<std::string> parts;
    std::istringstream f(str);
    std::string s;
    while (getline(f, s, separator)) parts.push_back(s);
    return parts;
}

void insertTree(const char *name, VisualValue *v) {
    if(!g_debugRoot) g_debugRoot = new VisualNode();
    VisualNode *cur = g_debugRoot;
    std::vector<std::string> parts = split(name, '.');

    for (int i = 0; i < parts.size(); ++i) {
        auto &part = parts[i];
        if(i == (parts.size() - 1)) {
            v->name = part;
            cur->leafs.push_back(v);
        } else {
            auto it = cur->map.find(part);
            if(it == cur->map.end()) {
                auto it2 = cur->map.insert(std::make_pair(part, std::make_unique<VisualNode>()));
                it = it2.first;
            }
            cur = it->second.get();
        }
    }
}

namespace ImGui {
    static bool Toggle(const char* label, bool &v) {
        if(ImGui::RadioButton(label, v)) {
            v = !v;
            return true;
        }
        return false;
    }
}

VisualBool::VisualBool(const char *name, bool def) : value(def) { insertTree(name, this); }
VisualInt::VisualInt(const char *name, int def) : value(def) { insertTree(name, this); }
VisualFloat::VisualFloat(const char *name, float def) : value(def) { insertTree(name, this); }
VisualVec3f::VisualVec3f(const char *name) : value() { insertTree(name, this); }
void VisualBool::render() { ImGui::Toggle(name.c_str(), value); }
void VisualInt::render() { ImGui::InputInt(name.c_str(), &value, 1, 2); }
void VisualFloat::render() { ImGui::DragFloat(name.c_str(), &value, 0.01f); }
void VisualVec3f::render() { ImGui::DragFloat3(name.c_str(), &value.x, 0.01f); }

void visual_values_render_imgui() {
    if(g_debugRoot)g_debugRoot->render();
}
