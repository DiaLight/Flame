//
// Created by DiaLight on 10/12/2025.
//

#include <lodepng.h>
#include <map>
#include <thread>
#include <tools/flame_config.h>
#include <xutility>
#include "patches/welcome_window/resources/resources.h"
#include "tools/bug_hunter/MyVersionInfo.h"
#include "tools/last_error.h"
#include "welcome_window_imgui.h"

static ImVec2 operator -(const ImVec2& l, const ImVec2& r) { return {l.x - r.x, l.y - r.y}; }
static ImVec2 operator +(const ImVec2& l, const ImVec2& r) { return {l.x + r.x, l.y + r.y}; }
static ImVec2 operator /(const ImVec2& l, float v) { return {l.x / v, l.y / v}; }
static ImVec2 operator *(const ImVec2& l, float v) { return {l.x * v, l.y * v}; }


struct MyTimer {

    LARGE_INTEGER s_frequency{};
    BOOL s_use_qpc = FALSE;
    HANDLE hTimer;
    MyTimer() {
        s_use_qpc = QueryPerformanceFrequency(&s_frequency);
//        timeBeginPeriod(1);
//        SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_HIGHEST);

        // Create a high resolution timer
        hTimer = CreateWaitableTimerEx(nullptr, nullptr, CREATE_WAITABLE_TIMER_HIGH_RESOLUTION, TIMER_ALL_ACCESS);
        // Then configure it
        LARGE_INTEGER dueTime;
        dueTime.QuadPart = 0; // Start timer immediately
        SetWaitableTimer(hTimer, &dueTime, 1 /*every 1ms*/, nullptr, nullptr, FALSE);
    }
    ~MyTimer() {
        CloseHandle(hTimer);
    }

    [[nodiscard]] time_t now_ms() const {
        if (s_use_qpc) {
            LARGE_INTEGER now;
            QueryPerformanceCounter(&now);
            return (1000LL * now.QuadPart) / s_frequency.QuadPart;
        } else {
            return GetTickCount();
        }
    }

    void sleep(time_t ms) const {
        // I have no idea how to wait precise amount of time
        time_t end = now_ms() + ms;
        time_t left = ms;
        while(left > 0) {
//            time_t s = now_ms();
            if(left > 5) {  // trying to save cpu time
                if(hTimer) {
                    LARGE_INTEGER dueTime;
                    dueTime.QuadPart = -10000;  // 1ms
//                    dueTime.QuadPart = -1;
                    SetWaitableTimer(hTimer, &dueTime, 0, nullptr, nullptr, FALSE);
                    WaitForSingleObject(hTimer, INFINITE);
                } else {
                    Sleep(1);
                }
            } else if(left > 3) {
                SwitchToThread();
            }
//            time_t e = now_ms();
//            if((e - s) > left) printf("[warn] oversleep %lld > %lld\n", e-s, left);
            left = end - now_ms();
        }
    }

};

int countCores(DWORD_PTR value) {
    int count = 0;
    while (value) {
        count += value & 1;
        value >>= 1;
    }
    return count;
}

DWORD_PTR selectNCores(DWORD_PTR systemMask, int n) {
    DWORD_PTR result = 0;
    for (int i = 0, c = 0; i < (sizeof(result) * 8) && c < n; ++i) {
        if((systemMask & (1 << i)) == 0) continue;
        result |= 1 << i;
        ++c;
    }
    return result;
}

extern flame_config::define_flame_option<bool> o_console;
extern flame_config::define_flame_option<bool> o_windowed;
extern flame_config::define_flame_option<bool> o_single_core;
extern flame_config::define_flame_option<std::string> o_menuRes;
extern flame_config::define_flame_option<std::string> o_gameRes;
extern flame_config::define_flame_option<bool> o_gog_enabled;
extern flame_config::define_flame_option<bool> o_gog_Video_HighRes;
extern flame_config::define_flame_option<bool> o_gog_Misc_SingleCore;
extern flame_config::define_flame_option<int> o_autosave;
extern flame_config::define_flame_option<bool> o_external_textures;
const char *op_Screen_Width = "registry:configuration:video:Screen_Width";
const char *op_Screen_Height = "registry:configuration:video:Screen_Height";
const char *op_Res_1024_768_Enabled = "registry:configuration:video:Res_1024_768_Enabled";
const char *op_Res_1280_1024_Enable = "registry:configuration:video:Res_1280_1024_Enable";
const char *op_Res_1600_1200_Enable = "registry:configuration:video:Res_1600_1200_Enable";
const char *op_Screen_Mode_Type = "registry:configuration:video:Screen_Mode_Type";

struct WelcomeWindow {
    ImGuiIO& io;
    ImVec4 &clear_color;
    bool &done;
    patch::welcome_window::welcome_data_t& _data;

    bool is_settings = false;

    SIZE _bg_size{};
    ImTextureID _bg = ImTextureID_Invalid;

    struct option_t {
        std::string name;
        flame_config::defined_flame_option *opt;
        flame_config::flame_value value;
        std::function<void()> changed;
    };
    struct category_t {
        std::string name;
        std::vector<option_t> options;
    };
    struct root_t {
        std::string name;
        std::vector<category_t> categories;
        bool isChanged = false;
    };

    std::vector<root_t> _roots;
    std::map<std::string, option_t*> _options;

    std::vector<std::string> _data_modes;
    int _menuRes_current_data_mode = 0;
    int _gameRes_current_data_mode = 0;
    bool DDrawCompat_detected = false;

    WelcomeWindow(ImGuiIO& io, ImVec4 &clear_color, bool &done, patch::welcome_window::welcome_data_t& data) :
        io(io), clear_color(clear_color), done(done), _data(data) {
        // disable imgui creating files
        io.IniFilename = NULL;
        io.LogFilename = NULL;

        HMODULE mod = GetModuleHandle("flame.dll");
        if(mod) {
            HRSRC myResource = ::FindResource(mod, MAKEINTRESOURCE(IDR_WELCOME__MAIN_BACKGROUND), RT_RCDATA);
            if(HGLOBAL myResourceData = ::LoadResource(mod, myResource)) {
                DWORD size = SizeofResource(mod, myResource);
                if(void *data = ::LockResource(myResourceData)) {
                    _bg = patch::welcome_window::LoadTextureFromBuffer(data, size, _bg_size);
                    UnlockResource(data);
                }
                FreeResource(myResourceData);
            }
        }

        if(HMODULE ddraw = GetModuleHandleA("ddraw.dll")) {
            MyVersionInfo ver(ddraw);
            if(ver.open()) {
                auto desc = ver.queryValue("FileDescription");
                DDrawCompat_detected = desc.contains("DDrawCompat");
            }
        }
    }

    void load_options() {
        _roots.clear();
        _options.clear();
        struct root_idx_t {
            int idx;
            std::map<std::string, int> byCategories;
        };
        std::map<std::string, root_idx_t> byRoots;
        flame_config::iterateDefinedOptions([&](flame_config::defined_flame_option& opt) {
            if(opt.group == flame_config::OG_HiddenState) return;
            if(opt.group == flame_config::OG_GameProgress) return;
            std::string path(opt.path);

            root_idx_t *pRoot = nullptr;
            {
                auto pos = path.find(':');
                std::string root;
                if(pos != std::string::npos) {
                    root = path.substr(0, pos);
                    path = path.substr(pos + 1);
                }
                auto root_it = byRoots.find(root);
                if(root_it == byRoots.end()) {
                    auto &r = _roots.emplace_back();
                    r.name = root;
                    auto it2 = byRoots.insert(std::make_pair(
                        root,
                        root_idx_t {(int) _roots.size() - 1}
                        ));
                    root_it = it2.first;
                }
                pRoot = &root_it->second;
            }
            auto& categories = _roots[pRoot->idx].categories;

            int categoryIdx = -1;
            {
                std::string category;
                auto pos = path.rfind(':');
                if(pos != std::string::npos) {
                    category = path.substr(0, pos);
                    path = path.substr(pos + 1);
                }

                auto it = pRoot->byCategories.find(category);
                if(it == pRoot->byCategories.end()) {
                    auto &cat = categories.emplace_back();
                    cat.name = category;
                    auto it2 = pRoot->byCategories.insert(std::make_pair(category, categories.size() - 1));
                    it = it2.first;
                }
                categoryIdx = it->second;
            }
            auto& options = categories[categoryIdx].options;
            options.emplace_back(path, &opt, opt.value);
        });
        for(auto& root : _roots) {
            for(auto& cat : root.categories) {
                for(auto& o : cat.options) {
                    _options.insert(std::make_pair(o.opt->path, &o));
                }
            }
        }
        {
            _data_modes.emplace_back("unset");
            for(auto& mode : _data.modes) {
                auto& str = _data_modes.emplace_back();
                str.append(std::to_string(mode.width));
                str.append("x");
                str.append(std::to_string(mode.height));
            }

            menuRes_updateDisplayMode();
            _options[o_menuRes.path]->changed = [this] { menuRes_updateDisplayMode();};

            gameRes_updateDisplayMode();
            _options[o_gameRes.path]->changed = [this] { gameRes_updateDisplayMode();};
            _options[op_Screen_Width]->changed = [this] { gameRes_updateDisplayMode();};
            _options[op_Screen_Height]->changed = [this] { gameRes_updateDisplayMode();};
        }
    }
    void menuRes_updateDisplayMode() {
        _menuRes_current_data_mode = 0;
        auto &menuRes = _options[o_menuRes.path]->value.str_value;
        if(!menuRes.empty()) {
            for (int i = 0; i < _data_modes.size(); ++i) {
                if(i == 0) continue;  // skip unset
                if(_data_modes[i] == menuRes) {
                    _gameRes_current_data_mode = i;
                    break;
                }
            }
            return;
        }
    }
    void gameRes_autoConfigureDk2Options(size_t width, size_t height) {
        {  // dk2 enabled options
            if(width >= 1024 && height >= 768) _options[op_Res_1024_768_Enabled]->value.bool_value = true;
            if(width >= 1280 && height >= 1024) _options[op_Res_1280_1024_Enable]->value.bool_value = true;
            if(width >= 1600 && height >= 1200) _options[op_Res_1600_1200_Enable]->value.bool_value = true;
        }
        {  // dk2 screen mode
            // 0: 400x300
            // 1: 512x384
            // 2: 640x480 if VRAM > 2mb
            // 3: 800x600 if VRAM > 3mb
            // 4: 1024x768 if VRAM > 6mb  (most stable)
            // 5: 1280x1024 if VRAM > 10mb  (crashes the game)
            // 6: 1600x1200 if VRAM > 14mb  (fonts not loading)
            int dk2ScreenMode = 0;
            if(width >= 400 && height >= 300) dk2ScreenMode = 0;
            if(width >= 512 && height >= 384) dk2ScreenMode = 1;
            if(width >= 640 && height >= 480) dk2ScreenMode = 2;
            if(width >= 800 && height >= 600) dk2ScreenMode = 3;
            if(width >= 1024 && height >= 768) dk2ScreenMode = 4;
            if(width >= 1280 && height >= 1024) dk2ScreenMode = 5;
            if(width >= 1600 && height >= 1200) dk2ScreenMode = 6;
            _options[op_Screen_Mode_Type]->value.int_value = dk2ScreenMode;
        }
        {  // gog disable if not supported
            _options[o_gog_enabled.path]->value.bool_value = false;
            // only resolutions supported by gog patch:
            if (width == 640 && height == 480
                || width == 800 && height == 600
                || width == 1024 && height == 768
                || width == 1280 && height == 1024
                || width == 1600 && height == 1200
            ) {  // gog high resolution
                _options[o_gog_enabled.path]->value.bool_value = true;
                _options[o_gog_Video_HighRes.path]->value.bool_value = width > 1024 && height > 768;
            }
            if(_options[o_windowed.path]->value.bool_value) _options[o_gog_enabled.path]->value.bool_value = false;
        }
    }
    void gameRes_updateDisplayMode() {
        _gameRes_current_data_mode = 0;
        auto &gameRes = _options[o_gameRes.path]->value.str_value;
        if(!gameRes.empty()) {
            for (int i = 0; i < _data_modes.size(); ++i) {
                if(i == 0) continue;  // skip unset
                if(_data_modes[i] == gameRes) {
                    _gameRes_current_data_mode = i;
                    break;
                }
            }
            return;
        }
        auto width = _options[op_Screen_Width]->value.int_value;
        auto height = _options[op_Screen_Height]->value.int_value;
        for (int i = 0; i < _data_modes.size(); ++i) {
            if(i == 0) continue;  // skip unset
            auto& mode = _data.modes[i - 1];
            if(mode.width == width && mode.height == height) {
                _gameRes_current_data_mode = i;
                break;
            }
        }
    }
    void save_options() {
        for(auto& root : _roots) {
            if(!root.isChanged) continue;
            for(auto& cat : root.categories) {
                for(auto& o : cat.options) {
                    if(o.value == o.opt->value) continue;
                    flame_config::set_option(o.opt->path, o.value);
                }
            }
        }
        if(flame_config::changed()) flame_config::save();
    }

    static void Tooltip(const char* desc) {
        if (ImGui::BeginItemTooltip()) {
            ImGui::PushTextWrapPos(ImGui::GetFontSize() * 25.0f);
            ImGui::TextUnformatted(desc);
            ImGui::PopTextWrapPos();
            ImGui::EndTooltip();
        }
    }
    // Helper to display a little (?) mark which shows a tooltip when hovered.
    // In your own code you may want to display an actual icon if you are using a merged icon fonts (see docs/FONTS.md)
    static void HelpMarker(const char* desc) {
        ImGui::TextDisabled("(?)");
        Tooltip(desc);
    }

    static char *formatStrId(const std::string &name, bool isChanged) {
        static char str_id[256];
        str_id[0] = '\0';
        char *p = str_id;
        p = strcat(p, name.c_str());
        if(isChanged) p = strcat(p, "*");
        strcat(p, "###");
        p = strcat(p, name.c_str());
        return str_id;
    }
    void all_options_tick() {
        if (ImGui::BeginTabBar("AllOptions", ImGuiTabBarFlags_None)) {
            for(auto &root : _roots) {
                if (ImGui::BeginTabItem(formatStrId(root.name, root.isChanged))) {
                    root.isChanged = false;
                    for(auto &cat : root.categories) {
                        bool open = true;
                        if(!cat.name.empty()) {
                            ImGui::SetNextItemOpen(true, ImGuiCond_Once);
                            open = ImGui::TreeNode(cat.name.c_str());
                        }
                        if (open) {
                            int i = 0;
                            for(auto &o : cat.options) {
                                ImGui::PushID(i++);
                                auto& opt = *o.opt;
                                bool isDefault = o.value == opt.defaultValue;
                                if(isDefault) ImGui::PushStyleColor(ImGuiCol_FrameBg, ImVec4(64./255, 64./255, 72./255, 138./255));
                                bool isChanged = o.value == opt.value;
                                if(isChanged) ImGui::PushStyleColor(ImGuiCol_FrameBg, ImVec4(33./255, 79./255, 102./255, 138./255));
                                switch (o.value.ty) {
                                case flame_config::VT_None: break;
                                case flame_config::VT_String: {
                                    ImGui::SetNextItemWidth(200);
                                    if(ImGui::InputText(o.name.c_str(), o.value.str_value.data(), o.value.str_value.capacity() + 1, ImGuiInputTextFlags_CallbackResize, [](ImGuiInputTextCallbackData* data) -> int {
                                            auto& str = *(std::string *)data->UserData;
                                            if (data->EventFlag == ImGuiInputTextFlags_CallbackResize) {
                                                // Resize string callback
                                                // If for some reason we refuse the new length (BufTextLen) and/or capacity (BufSize) we need to set them back to what we want.
                                                IM_ASSERT(data->Buf == str.c_str());
                                                str.resize(data->BufTextLen);
                                                data->Buf = (char*) str.c_str();
                                            }
                                            return 0;
                                        }, &o.value.str_value)) {
//                                        printf("changed str %s: \"%s\" %d/%d\n", opt.path, o.value.str_value.data(), o.value.str_value.size(), o.value.str_value.capacity());
                                        if(o.changed) o.changed();
                                    }
                                    if(opt.help && *opt.help) {ImGui::SameLine(); HelpMarker(opt.help);}
                                    break;
                                }
                                case flame_config::VT_Boolean: {
                                    ImGui::SetNextItemWidth(200);
                                    if(ImGui::Checkbox(o.name.c_str(), &o.value.bool_value)) {
//                                        printf("changed bool %s\n", opt.path);
                                        if(o.changed) o.changed();
                                    }
                                    if(opt.help && *opt.help) {ImGui::SameLine(); HelpMarker(opt.help);}
                                    break;
                                }
                                case flame_config::VT_Int: {
                                    ImGui::SetNextItemWidth(200);
                                    if(ImGui::DragInt(o.name.c_str(), &o.value.int_value, 1)) {
//                                        printf("changed int %s: %d\n", opt.path, o.value.int_value);
                                        if(o.changed) o.changed();
                                    }
                                    if(opt.help && *opt.help) {ImGui::SameLine(); HelpMarker(opt.help);}
                                    break;
                                }
                                case flame_config::VT_Float: {
                                    ImGui::SetNextItemWidth(200);
                                    if(ImGui::DragFloat(o.name.c_str(), &o.value.float_value, 0.1)) {
//                                        printf("changed float %s: %.2f\n", opt.path, o.value.float_value);
                                        if(o.changed) o.changed();
                                    }
                                    if(opt.help && *opt.help) {ImGui::SameLine(); HelpMarker(opt.help);}
                                    break;
                                }
                                }
                                if(isChanged) ImGui::PopStyleColor(1);
                                if(isDefault) ImGui::PopStyleColor(1);

                                if(!isChanged) {
                                    root.isChanged = true;
                                    ImGui::SameLine(0, 0);
                                    ImGui::PushStyleColor(ImGuiCol_Button, 0);
                                    if (ImGui::Button("*")) {
                                        o.value = opt.value;
                                    }
                                    ImGui::PopStyleColor(1);
                                    Tooltip("Changed. Click: reset changes");
                                }
                                if(!isDefault) {
                                    ImGui::SameLine();
                                    if (ImGui::Button("D")) {
                                        o.value = opt.defaultValue;
                                    }
                                    Tooltip("Click: reset to default");
                                }
                                ImGui::PopID();
                            }
                            if(!cat.name.empty()) ImGui::TreePop();
                        }
                    }
                    ImGui::EndTabItem();
                }
            }
            ImGui::EndTabBar();
        }

    }

    void update_changes() {
        for(auto &root : _roots) {
            root.isChanged = false;
            for(auto &cat : root.categories) {
                for(auto &o : cat.options) {
                    auto& opt = *o.opt;
//                    bool isDefault = o.value == opt.defaultValue;
                    bool isChanged = o.value == opt.value;
                    if(!isChanged) {
                        root.isChanged = true;
                        break;
                    }
                }
                if(root.isChanged) break;
            }
        }
    }
    void simple_settings() {
        ImGui::SetNextItemWidth(200);
        if(ImGui::Combo("Menu Display mode", &_menuRes_current_data_mode, [](void *ctx, int idx) -> const char * {
                return ((WelcomeWindow *) ctx)->_data_modes[idx].c_str();
        }, this, _data_modes.size())) {
            auto &menuRes = _options[o_menuRes.path]->value.str_value;
            if(_menuRes_current_data_mode) {
                size_t width = _data.modes[_menuRes_current_data_mode - 1].width;
                size_t height = _data.modes[_menuRes_current_data_mode - 1].height;
//                printf("manu selected mode: %dx%d\n", width, height);
                menuRes = std::to_string(width) + "x" + std::to_string(height);
            } else {
//                printf("manu selected mode: reset\n");
                menuRes.clear();
            }
            update_changes();
        }

        ImGui::SetNextItemWidth(200);
        if(ImGui::Combo("Game Display mode", &_gameRes_current_data_mode, [](void *ctx, int idx) -> const char * {
                return ((WelcomeWindow *) ctx)->_data_modes[idx].c_str();
        }, this, _data_modes.size())) {
            auto &gameRes = _options[o_gameRes.path]->value.str_value;
            if(_gameRes_current_data_mode) {
                size_t width = _data.modes[_gameRes_current_data_mode - 1].width;
                size_t height = _data.modes[_gameRes_current_data_mode - 1].height;
//                printf("manu selected mode: %dx%d\n", width, height);
                _options[op_Screen_Width]->value.int_value = width;
                _options[op_Screen_Height]->value.int_value = height;
                gameRes_autoConfigureDk2Options(width, height);
            } else {
//                printf("manu selected mode: reset\n");
                gameRes.clear();
            }
            update_changes();
        }

        ImGui::SetNextItemWidth(200);
        if(ImGui::Checkbox("Windowed mode", &_options[o_windowed.path]->value.bool_value)) {
//            printf("changed bool %s\n", o_windowed.path);
            if(_gameRes_current_data_mode) {
                size_t width = _data.modes[_gameRes_current_data_mode - 1].width;
                size_t height = _data.modes[_gameRes_current_data_mode - 1].height;
                gameRes_autoConfigureDk2Options(width, height);
            }
            update_changes();
        }
        ImGui::Text("Gog patch enabled: %s", _options[o_gog_enabled.path]->value.bool_value ? "true" : "false");

        if (ImGui::CollapsingHeader("I need multithreading", ImGuiTreeNodeFlags_None)) {
            bool isSingleCore = false;
            if(_options[o_single_core.path]->value.bool_value) {
                isSingleCore = true;
            } else if(_options[o_gog_enabled.path]->value.bool_value && _options[o_gog_Misc_SingleCore.path]->value.bool_value) {
                isSingleCore = true;
            } else {
                DWORD_PTR affinity = 0;
                DWORD_PTR sysAffinity = 0;
                if(GetProcessAffinityMask(GetCurrentProcess(), &affinity, &sysAffinity)) {
                    int processCores = countCores(affinity);
                    int systemCores = countCores(sysAffinity);
                    ImGui::Text("Affinity process: %d, system: %d", processCores, systemCores);
                    if(processCores <= 1) isSingleCore = true;
                    if(ImGui::SliderInt("affinity", &processCores, 1, systemCores)) {
                        if(processCores != countCores(affinity)) {  // changed
                            DWORD_PTR mask = selectNCores(sysAffinity, processCores);
                            SetProcessAffinityMask(GetCurrentProcess(), mask);
                        }
                    }
                    if(DDrawCompat_detected) {
                        ImGui::TextWrapped("DDrawCompat detected! Use its config to control affinity or remove ddraw.dll from \"Dungeon Keeper 2\" directory");
                    }
                }
            }
            ImGui::Text("Single core: %s", isSingleCore ? "true" : "false");
            {ImGui::SameLine(); HelpMarker("The Flame and Gog patches separately limit the number of cores. To try multithreading, disable single-core in both patches. The pre-configured Affinity mask also affects multithreading");}
        }
    }

    bool isChanged() {
        for(auto &root : _roots) {
            if(!root.isChanged) continue;
            return true;
        }
        return false;
    }
    void settings_tick() {
//        ImGui::Text("Application average %.3f ms/frame (%.1f FPS)", 1000.0f / io.Framerate, io.Framerate);
        if (ImGui::BeginTabBar("Settings", ImGuiTabBarFlags_None)) {
            if (ImGui::BeginTabItem("Simple settings")) {
                simple_settings();
                ImGui::EndTabItem();
            }
            if (ImGui::BeginTabItem(isChanged() ? "All options*###all_changes" : "All options###all_changes")) {
                all_options_tick();
                ImGui::EndTabItem();
            }
            ImGui::EndTabBar();
        }
    }

    void settings_bottom_tick() {
        ImGui::PushStyleVar(ImGuiStyleVar_FramePadding, ImVec2(12.f, 8.f));
        static float MaxWidth = 0;
        float NewMaxWidth = 10.0f;
        {
            if(ImGui::Button(isChanged() ? "Ok*###ok" : "Ok###ok", {MaxWidth, 0})) {
                // save changes
                save_options();
                is_settings = false;
            }
            NewMaxWidth = std::max(NewMaxWidth, ImGui::GetItemRectSize().x);
        }
        {
            ImGui::SameLine((ImGui::GetWindowWidth() - MaxWidth) / 2);
            if(ImGui::Button("Default", {MaxWidth, 0})) {
                for(auto& root : _roots) {
                    for(auto& cat : root.categories) {
                        for(auto& o : cat.options) {
                            if(o.value == o.opt->defaultValue) continue;
                            o.value = o.opt->defaultValue;
                        }
                    }
                }
                update_changes();
                gameRes_updateDisplayMode();
                menuRes_updateDisplayMode();
            }
            NewMaxWidth = std::max(NewMaxWidth, ImGui::GetItemRectSize().x);
        }
        {
            static float LocalButtonWidth = 100.0f;
            const float ItemSpacing = ImGui::GetStyle().ItemSpacing.x;
            ImGui::SameLine(ImGui::GetWindowWidth() - ItemSpacing - LocalButtonWidth);
            if(ImGui::Button("Cancel", {MaxWidth, 0})) {
                is_settings = false;
            }
            LocalButtonWidth = ImGui::GetItemRectSize().x;  // Get the actual width for next frame.
            NewMaxWidth = std::max(NewMaxWidth, ImGui::GetItemRectSize().x);
        }
        MaxWidth = NewMaxWidth;
        ImGui::PopStyleVar();
    }

    void main_tick() {
        float btn_height = 60;
        static ImVec2 LocalButtonSize = {100.0f, 40.0f};
        ImGui::SetCursorPos(ImVec2{
            (ImGui::GetWindowSize().x - LocalButtonSize.x) / 2,
            ImGui::GetWindowSize().y - btn_height - 20
        });
        {
            ImGui::BeginGroup();
            if(ImGui::Button("S", {btn_height, btn_height})) {
                load_options();
                is_settings = true;
            }
            Tooltip("Settings");
            ImGui::SameLine();
            if(ImGui::Button("Play", {300, btn_height})) {
                _data.play = true;
                done = true;
            }
            ImGui::EndGroup();
        }
        LocalButtonSize = ImGui::GetItemRectSize();
    }

    void draw() {
        {
            auto& style = ImGui::GetStyle();
            style.Colors[ImGuiCol_WindowBg] = ImVec4(0.1, 0.1, 0.1, 0.5);
        }
        if(is_settings) {
            if(_bg != ImTextureID_Invalid) {
                ImGui::SetNextWindowPos(ImVec2(0, 0), ImGuiCond_Always);
                ImGui::SetNextWindowSize(io.DisplaySize, ImGuiCond_Always);
                ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(0.0f, 0.0f));
                if (ImGui::Begin("bg", NULL, ImGuiWindowFlags_NoDecoration |
                                     ImGuiWindowFlags_NoMove |
                                     ImGuiWindowFlags_NoBringToFrontOnFocus |
                                     ImGuiWindowFlags_NoInputs)) {
                    ImGui::Image(_bg, io.DisplaySize);
                    ImGui::End();
                }
                ImGui::PopStyleVar();
            }

            float bt_h = 40;

            ImVec2 pz(0.0f, 0.0f);
            ImVec2 sz(io.DisplaySize.x, io.DisplaySize.y - bt_h);
            ImGui::SetNextWindowPos(pz);
            ImGui::SetNextWindowSize(sz);
            if(ImGui::Begin("settings_win", NULL, ImGuiWindowFlags_NoDecoration & ~ImGuiWindowFlags_NoScrollbar | ImGuiWindowFlags_HorizontalScrollbar)) {
                settings_tick();
                ImGui::End();
            }

            ImGui::SetNextWindowPos(ImVec2(0.0f, 0.0f));
            ImVec2 bt_pz(0.0f, io.DisplaySize.y - bt_h);
            ImVec2 bt_sz(io.DisplaySize.x, bt_h);
            ImGui::SetNextWindowPos(bt_pz);
            ImGui::SetNextWindowSize(bt_sz);
            ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(4.f, 3.f));
            if(ImGui::Begin("bottom_win", NULL, ImGuiWindowFlags_NoDecoration)) {
                settings_bottom_tick();
                ImGui::End();
            }
            ImGui::PopStyleVar();
        } else {
            ImGui::SetNextWindowPos(ImVec2(0, 0), ImGuiCond_Always);
            ImGui::SetNextWindowSize(io.DisplaySize, ImGuiCond_Always);
            ImGui::PushStyleVar(ImGuiStyleVar_WindowBorderSize, 0.f);
            ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2());
            if(ImGui::Begin("main_win", NULL, ImGuiWindowFlags_NoDecoration)) {
                if(_bg != ImTextureID_Invalid) {
                    ImGui::Image(_bg, io.DisplaySize);
                }
                main_tick();
                ImGui::End();
            }
            ImGui::PopStyleVar();
            ImGui::PopStyleVar();
        }
    }
    MyTimer timer;
    time_t lastTime = 0;

    void tick() {
        time_t tick_start = timer.now_ms();
        if(lastTime) {
            int fps = 45;
            int mspf = 1000 / fps;
            time_t delta = mspf - (tick_start - lastTime);
//            printf("%d\n", delta);
            timer.sleep(delta);
        }
        lastTime = timer.now_ms();
        draw();
    }

};

void *patch::welcome_window::create(ImGuiIO& io, ImVec4 &clear_color, bool &done, welcome_data_t& data) {
    return new WelcomeWindow(io, clear_color, done, data);
}
void patch::welcome_window::tick(void *ptr) {
    ((WelcomeWindow *) ptr)->tick();
}
void patch::welcome_window::destroy(void *ptr) {
    delete (WelcomeWindow *) ptr;
}

