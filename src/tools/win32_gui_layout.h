//
// Created by DiaLight on 12.09.2022.
//

#ifndef EMBER_WIN32_GUI_LAYOUT_H
#define EMBER_WIN32_GUI_LAYOUT_H

#include <ShellScalingApi.h>
#include <functional>
#include <cstdint>
#include <CommCtrl.h>

namespace gui {

    extern HINSTANCE g_hInst;

    struct pos2i_t {
        int x = 0;
        int y = 0;
    };
    struct size2i_t {
        int w = 0;
        int h = 0;
    };

    extern int g_dpi;

    bool initDPI();
    int getDpi();
    int applyDpi(int size);
    int revertDpi(int size);
    void applyDpi(size2i_t &size);
    void applyDpi(pos2i_t &pos);

    struct gui_elem_t {
        static HMENU nextId;
        LPCWSTR className;
        LPCWSTR windowName;
        DWORD style;

        pos2i_t pos;
        size2i_t size = {CW_USEDEFAULT, CW_USEDEFAULT};
        HWND hwnd = nullptr;
        HMENU id = nullptr;
        WNDPROC origProc = NULL;

        gui_elem_t(LPCWSTR className, LPCWSTR windowName, DWORD style) :
                className(className), windowName(windowName), style(style) {
        }

        void create(HWND parent, bool forceCreate) {
            pos2i_t lpos = pos;
            size2i_t lsize = size;
            applyDpi(lpos);
            applyDpi(lsize);
            if (hwnd != nullptr) {
                if (forceCreate) {
                    // close handles
                } else {
                    SetWindowPos(
                            hwnd, parent,
                            lpos.x, lpos.y, lsize.w, lsize.h,
                            SWP_NOCOPYBITS | SWP_NOACTIVATE | SWP_NOZORDER
                    );
                    return;
                }
            }
            id = nextId;
            nextId = (HMENU) (((uint8_t *) nextId) + 1);
            if (parent != nullptr) style |= WS_CHILD;
            hwnd = CreateWindowW(
                    className, windowName,
                    style,
                    lpos.x, lpos.y, lsize.w, lsize.h,
                    parent, id, g_hInst, NULL
            );
            created();
        }

        virtual void created() {}

        int getText(wchar_t *lpch, int cchMax) { return GetWindowTextW(hwnd, lpch, cchMax); }
        int getTextLength() { return GetWindowTextLengthW(hwnd); }
        bool setText(const wchar_t *lpsz) { return SetWindowTextW(hwnd, lpsz); }
        bool setText(const char *lpsz) { return SetWindowTextA(hwnd, lpsz); }

        bool enable(bool fEnable) { return EnableWindow(hwnd, fEnable); }
        void setWndProc(WNDPROC proc) {
            if (!origProc) {
                origProc = (WNDPROC) SetWindowLongPtrW(hwnd, GWLP_WNDPROC, (LONG_PTR) proc);
            } else {
                SetWindowLongPtrW(hwnd, GWLP_WNDPROC, (LONG_PTR) proc);
            }
        }

    };


    struct edit_elem_t : public gui_elem_t {

        explicit edit_elem_t(const wchar_t *text, DWORD style) : gui_elem_t(L"EDIT", text, style) {}

        int getLineCount() { return (int) (DWORD) SendMessageW(hwnd, EM_GETLINECOUNT, 0L, 0L); }
        int getLine(int line, wchar_t *lpch, int cchMax) {
            *((int *) lpch) = cchMax;
            return (int) (DWORD) SendMessageW(hwnd, EM_GETLINE, (WPARAM) (int) (line), (LPARAM) (LPTSTR) (lpch));
        }

        void limitText(int cchMax) { SendMessageW(hwnd, EM_LIMITTEXT, (WPARAM) (cchMax), 0L); }

        bool setReadOnly(bool fReadOnly) {
            return (BOOL) (DWORD) SendMessageW(hwnd, EM_SETREADONLY, (WPARAM) (BOOL) (fReadOnly), 0L);
        }

        void setWordBreakProc(EDITWORDBREAKPROCW lpfn) { SendMessageW(hwnd, EM_SETWORDBREAKPROC, 0L, (LPARAM) lpfn); }

        EDITWORDBREAKPROCW getWordBreakProc() {
            return (EDITWORDBREAKPROCW) SendMessageW(hwnd, EM_GETWORDBREAKPROC, 0L, 0L);
        }

        void lineScroll(int hor, int ver) {
            SendMessageW(hwnd, EM_LINESCROLL, (WPARAM) hor, (LPARAM) ver);
        }

    };


    struct combobox_elem_t : public gui_elem_t {

        explicit combobox_elem_t(const wchar_t *text, DWORD style) : gui_elem_t(WC_COMBOBOXW, text, style) {}

        void limitText(int cchMax) { SendMessageW(hwnd, CB_LIMITTEXT, (WPARAM) (cchMax), 0L); }

        DWORD getEditSel() { return (DWORD) SendMessageW(hwnd, CB_GETEDITSEL, 0L, 0L); }

        void setEditSel(int ichStart, int ichEnd) {
            (int) (DWORD) SendMessageW(hwnd, CB_SETEDITSEL, 0L, MAKELPARAM((ichStart), (ichEnd)));
        }

        void addString(LPCWSTR lpsz) {
            (int) (DWORD) SendMessageW(hwnd, (UINT) CB_ADDSTRING, (WPARAM) 0, (LPARAM) lpsz);
        }

        void insertString(int index, LPCTSTR lpsz) {
            (int) (DWORD) SendMessageW(hwnd, CB_INSERTSTRING, (WPARAM) (int) (index), (LPARAM) (lpsz));
        }

        void addItemData(LRESULT data) { (int) (DWORD) SendMessageW(hwnd, CB_ADDSTRING, 0L, (LPARAM) (data)); }

        void insertItemData(int index, LRESULT data) {
            (int) (DWORD) SendMessageW(hwnd, CB_INSERTSTRING, (WPARAM) (int) (index), (LPARAM) (data));
        }

        LRESULT getItemData(int index) {
            return (LRESULT) (ULONG_PTR) SendMessageW(hwnd, CB_GETITEMDATA, (WPARAM) (int) (index), 0L);
        }
        void setItemData(int index, LRESULT data) {
            (int) (DWORD) SendMessageW(hwnd, CB_SETITEMDATA, (WPARAM) (int) (index), (LPARAM) (data));
        }

        int getCurSel() { return (int) (DWORD) SendMessageW(hwnd, CB_GETCURSEL, 0L, 0L); }
        void setCurSel(int index) { (int) (DWORD) SendMessageW(hwnd, CB_SETCURSEL, (WPARAM) (int) (index), 0L); }

        void selectString(int indexStart, LPCWSTR lpszSelect) {
            (int) (DWORD) SendMessageW(hwnd, CB_SELECTSTRING, (WPARAM) (int) (indexStart), (LPARAM) (lpszSelect));
        }

        void selectItemData(int indexStart, LPARAM data) {
            (int) (DWORD) SendMessageW(hwnd, CB_SELECTSTRING, (WPARAM) (int) (indexStart), (LPARAM) (data));
        }

    };


    struct label_elem_t : public gui_elem_t {

        explicit label_elem_t(const wchar_t *text, DWORD style) : gui_elem_t(L"STATIC", text, style) {}

    };


    struct button_elem_t : public gui_elem_t {

        explicit button_elem_t(const wchar_t *text, DWORD style) : gui_elem_t(L"BUTTON", text, style) {}

        int getCheck() { return (int) (DWORD) SendMessageW(hwnd, BM_GETCHECK, 0L, 0L); }
        void setCheck(int check) { (void) SendMessageW(hwnd, BM_SETCHECK, (WPARAM) (int) (check), 0L); }

        int getState() { return (int) (DWORD) SendMessageW(hwnd, BM_GETSTATE, 0L, 0L); }
        UINT setState(int state) { return (UINT) (DWORD) SendMessageW(hwnd, BM_SETSTATE, (WPARAM) (int) (state), 0L); }

    };


    struct layout_t {
        enum mode_t : uint8_t {
            LM_Hor,
            LM_Ver,
        };
        HWND parent = nullptr;
        bool forceCreate = false;
        mode_t mode = LM_Ver;
        pos2i_t cursor;
        size2i_t size;
        size2i_t static_size;
        size2i_t dynamic_scale;
        size2i_t dynamic_size;
        int depth = 0;
        bool collect_static_mode = false;

#if 0
        void layout_dbg(const char *fmt, ...) {
        va_list ap;
        va_start(ap, fmt);
        char tmp[1024];
        for (int i = 0; i < depth; ++i) {
          tmp[i] = ' ';
        }
        char *pos = tmp + depth;
        int len = vsnprintf(pos, 1024, fmt, ap);
        pos[len++] = '\n';
        pos[len] = '\0';
        WriteConsoleA(GetStdHandle(STD_OUTPUT_HANDLE), tmp, len + depth, NULL, NULL);
        va_end(ap);
      }
#else
#define layout_dbg(fmt, ...)
#endif

        void update(HWND hwnd, int width, int height, bool reset = false) {
            parent = hwnd;
            forceCreate = reset;
            cursor = {0, 0};
            static_size = {0, 0};
            dynamic_scale = {0, 0};
            dynamic_size = {width, height};
            size = dynamic_size;
            layout_dbg("size=[%d %d]", width, height);
        }
        void operator()(HWND hwnd, int width, int height, bool reset = false) {
            update(hwnd, width, height, reset);
        }

        void add_size(size2i_t &size) {
            if (size.w >= 0) {
                static_size.w += size.w;
            } else {
                dynamic_scale.w += -size.w;
            }
            if (size.h >= 0) {
                static_size.h += size.h;
            } else {
                dynamic_scale.h += -size.h;
            }
        }

        void add_size(int width, int height) {
            size2i_t sz = {width, height};
            add_size(sz);
        }

        size2i_t get_size(int width, int height) {
            return {
                    width >= 0 ? width : dynamic_size.w * -width,
                    height >= 0 ? height : dynamic_size.h * -height
            };
        }

        void visit(gui_elem_t &e, int width, int height) {
            if (collect_static_mode) {
                if (mode == LM_Hor) {
                    add_size(width, 0);
                } else if (mode == LM_Ver) {
                    add_size(0, height);
                }
                return;
            }
            pos2i_t ocursor = this->cursor;
            e.pos = cursor;
            e.size = get_size(width, height);
            if (mode == LM_Hor) {
                cursor.x += e.size.w;
            } else if (mode == LM_Ver) {
                cursor.y += e.size.h;
            }
            layout_dbg("- visit cursor=[%d %d] + elem(pos=[%d %d] size=[%d %d]) -> cursor[%d %d]  size=[%d %d]",
                       ocursor.x, ocursor.y,
                       e.pos.x, e.pos.y, e.size.w, e.size.h,
                       cursor.x, cursor.y,
                       dynamic_size.w, dynamic_size.h
            );
            e.create(parent, forceCreate);
        }

        void hor(int width, int height, const std::function<void()> &f) {
            if (collect_static_mode) {
                add_size(width, height);
                return;
            }
            // save state
            auto lmode = mode;
            pos2i_t lcursor = cursor;
            size2i_t ldynamic_size = dynamic_size;
            size2i_t lstatic_size = static_size;
            size2i_t ldynamic_scale = dynamic_scale;
            // update state
            depth++;
            mode = LM_Hor;
            size = get_size(width, height);
            layout_dbg("enter hor cursor=[%d %d]  size=[%d %d]  max=[%d %d]",
                       cursor.x, cursor.y,
                       dynamic_size.w, dynamic_size.h,
                       size.w, size.h
            );
            // process
            static_size = {0, 0};
            dynamic_scale = {0, 0};
            collect_static_mode = true;
            f();
            dynamic_size = {
                    dynamic_scale.w != 0 ? (size.w - static_size.w) / dynamic_scale.w : 0,
                    dynamic_scale.h != 0 ? (size.h - static_size.h) : 0
            };
            collect_static_mode = false;
            f();
            // update state
            if (lmode == LM_Ver) {
                pos2i_t ocursor = this->cursor;
                cursor.x = lcursor.x;
                cursor.y += size.h;
                layout_dbg("exit hor to ver cursor=[%d %d] -> cursor=[%d %d]  max=[%d %d]",
                           ocursor.x, ocursor.y,
                           cursor.x, cursor.y,
                           size.w, size.h
                );
            } else {
                layout_dbg("exit hor cursor=[%d %d]  max=[%d %d]", cursor.x, cursor.y, size.w, size.h);
            }
            // restore state
            dynamic_size = ldynamic_size;
            static_size = lstatic_size;
            dynamic_scale = ldynamic_scale;
            mode = lmode;
            depth--;
        }

        void ver(const std::function<void()> &f, int width = -1, int height = -1) {
            if (collect_static_mode) {
                add_size(width, height);
                return;
            }
            // save state
            auto lmode = mode;
            pos2i_t lcursor = cursor;
            size2i_t ldynamic_size = dynamic_size;
            size2i_t lstatic_size = static_size;
            size2i_t ldynamic_scale = dynamic_scale;
            // update state
            depth++;
            mode = LM_Ver;
            size = get_size(width, height);
            layout_dbg("enter ver cursor=[%d %d]  size=[%d %d]  max=[%d %d]",
                       cursor.x, cursor.y,
                       dynamic_size.w, dynamic_size.h,
                       size.w, size.h
            );
            static_size = {0, 0};
            dynamic_scale = {0, 0};
            static_size = {0, 0};
            dynamic_scale = {0, 0};
            // process
            collect_static_mode = true;
            f();
            dynamic_size = {
                    dynamic_scale.w != 0 ? (size.w - static_size.w) : 0,
                    dynamic_scale.h != 0 ? (size.h - static_size.h) / dynamic_scale.h : 0
            };
            collect_static_mode = false;
            f();
            // update state
            if (lmode == LM_Hor) {
                pos2i_t scursor = this->cursor;
                cursor.x += size.w;
                cursor.y = lcursor.y;
                layout_dbg("exit ver to hor cursor=[%d %d] -> cursor=[%d %d]  max=[%d %d]",
                           scursor.x, scursor.y,
                           cursor.x, cursor.y,
                           size.w, size.h
                );
            } else {
                layout_dbg("exit ver cursor=[%d %d]  max=[%d %d]", cursor.x, cursor.y, size.w, size.h);
            }
            depth--;
            // restore state
            dynamic_size = ldynamic_size;
            static_size = lstatic_size;
            dynamic_scale = ldynamic_scale;
            mode = lmode;
        }

        void gap(int size) {
            if (collect_static_mode) {
                if (mode == LM_Hor) {
                    if (size >= 0) {
                        static_size.w += size;
                    } else {
                        dynamic_scale.w += -size;
                    }
                } else if (mode == LM_Ver) {
                    if (size >= 0) {
                        static_size.h += size;
                    } else {
                        dynamic_scale.h += -size;
                    }
                }
                return;
            }
            pos2i_t ocursor = cursor;
            size2i_t sz = get_size(mode == LM_Hor ? size : 0, mode == LM_Ver ? size : 0);
            cursor.x += sz.w;
            cursor.y += sz.h;
            layout_dbg("- gap cursor[%d %d] + %d -> cursor=[%d %d]",
                       ocursor.x, ocursor.y, size,
                       cursor.x, cursor.y
            );
        }
    };

#define     GetWindowStyle(hwnd)    ((DWORD)GetWindowLong(hwnd, GWL_STYLE))
#define     GetWindowExStyle(hwnd)  ((DWORD)GetWindowLong(hwnd, GWL_EXSTYLE))

    void resizeWin(HWND hwnd, int width, int height);

    void initLayout(HINSTANCE hInstance);

}


#endif //EMBER_WIN32_GUI_LAYOUT_H
