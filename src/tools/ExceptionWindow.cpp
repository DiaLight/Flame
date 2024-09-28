//
// Created by DiaLight on 26.09.2024.
//

#include "ExceptionWindow.h"
#include <WinUser.h>
#include <tchar.h>
#include <cstdio>
#include <sstream>
#include <iostream>
#include "win32_gui_layout.h"

#define FlameException_title _T("DK2-Flame exception")
#define FlameException_class _T("DK2-Flame-ExceptionWindow")


gui::edit_elem_t TextField(
        L"",
        WS_VISIBLE | WS_BORDER |
        ES_READONLY |
        WS_HSCROLL | WS_VSCROLL | ES_LEFT |
        ES_MULTILINE | ES_AUTOVSCROLL | ES_AUTOHSCROLL
);
gui::button_elem_t RethrowBtn(L"rethrow", WS_VISIBLE | WS_BORDER);
gui::button_elem_t ExitBtn(L"exit process", WS_VISIBLE | WS_BORDER);
gui::button_elem_t ContinueBtn(L"continue crashing", WS_VISIBLE | WS_BORDER);
gui::label_elem_t Label0(L"The Dungeon Keeper 2 has crashed", WS_VISIBLE | WS_TABSTOP);
gui::label_elem_t Label1(L"Crash info:", WS_VISIBLE | WS_TABSTOP);
gui::label_elem_t Label2(L"You can attach debugger to game process and rethrow exception for reason investigation",
                         WS_VISIBLE | WS_TABSTOP | SS_CENTER);
gui::label_elem_t Label3(
        L"or you can copy the crash info and open the issue if it hasn't already been opened before",
        WS_VISIBLE | WS_TABSTOP | SS_CENTER);
gui::edit_elem_t Label4(L"https://github.com/DiaLight/Flame/issues",
                        WS_VISIBLE | WS_TABSTOP | ES_READONLY | ES_CENTER);

struct : gui::layout_t {
    void update(HWND hwnd, int width, int height, bool reset = false) {
        layout_t::update(hwnd, width, height, reset);
        hor(-1, -1, [this] {
            gap(10);
            ver([this] {
                gap(10);

                // header
                visit(Label0, -1, 20);
                // header end

                gap(10);

                // body start
                visit(Label1, -1, 20);
                visit(TextField, -1, -1);
                visit(Label2, -1, 20);
                visit(Label3, -1, 20);
                visit(Label4, -1, 20);
                // body end

                gap(10);

                // footer
                hor(-1, 30, [this] {
                    gap(-1);
                    visit(RethrowBtn, 130, size.h);
                    gap(15);
                    visit(ExitBtn, 130, size.h);
                    gap(15);
                    visit(ContinueBtn, 130, size.h);
                    gap(-1);
                });
                // footer end

                gap(10);
            });
            gap(10);
        });
    }

    void wndProc(HWND hwnd, UINT message, WPARAM wParam, LPARAM lParam) {
        switch(message) {
            case WM_CREATE: {
                auto *create = (CREATESTRUCT *) lParam;
                gui::size2i_t size = {create->cx, create->cy};
                update(hwnd, size.w, size.h, true);
                gui::resizeWin(hwnd, size.w, size.h);
                break;
            }
            case WM_SIZE: {
                UINT width = LOWORD(lParam);
                UINT height = HIWORD(lParam);
                update(hwnd, gui::revertDpi(width), gui::revertDpi(height));
                break;
            }
            case WM_DPICHANGED: {
                gui::g_dpi = HIWORD(wParam);
                auto *rect = (RECT *) lParam;
                update(hwnd, rect->right - rect->left, rect->bottom - rect->top);
                break;
            }
        }
    }
} ExceptionWindow_layout;

LRESULT CALLBACK ExceptionWindow::WndProc(HWND hwnd, UINT message, WPARAM wParam, LPARAM lParam) {
    switch (message) {
        case WM_CREATE: {
            auto *create = (CREATESTRUCT *) lParam;
            SetWindowLongPtr(hwnd, GWLP_USERDATA, (LONG_PTR) create->lpCreateParams);
            break;
        }
    }
    ExceptionWindow_layout.wndProc(hwnd, message, wParam, lParam);
    if(auto _this = (ExceptionWindow *) GetWindowLongPtr(hwnd, GWLP_USERDATA)) {
        return _this->wndProc(hwnd, message, wParam, lParam);
    }
    return DefWindowProc(hwnd, message, wParam, lParam);
}
LRESULT ExceptionWindow::wndProc(HWND hwnd, UINT message, WPARAM wParam, LPARAM lParam) {
    switch (message) {
        case WM_CREATE: {
            SendMessage(TextField.hwnd, WM_SETFONT, WPARAM(CreateFont(
                    -MulDiv(11, GetDeviceCaps(GetDC(hwnd), LOGPIXELSY), 72),
                    0, 0, 0,
                    FW_NORMAL,
                    FALSE, FALSE, FALSE,
                    ANSI_CHARSET,
                    OUT_STROKE_PRECIS, CLIP_DEFAULT_PRECIS, DRAFT_QUALITY, FIXED_PITCH | FF_MODERN,
                    TEXT("Courier New")
            )), TRUE);

            std::stringstream ss;

            for(auto &fr : frames) {
                ss << fr << std::endl;
            }
//            if(err) {
//                ss << "[StackWalker ERROR]: " << err.str() << std::endl;
//            }

            std::string line;
            std::stringstream out;
            int lines = 0;
            while (std::getline(ss, line, '\n')) {
                out << line << "\r\n";
                lines++;
            }
            std::string trace = out.str();
            TextField.setText(trace.c_str());
            TextField.lineScroll(0, lines);
            break;
        }
        case WM_COMMAND: {
            HMENU hm = (HMENU) LOWORD(wParam);
            if (hm == RethrowBtn.id) {
                printf("user decided to rethrow\n\n");
                _throwAgain = true;
                PostQuitMessage(0);
            } else if (hm == ExitBtn.id) {
                printf("user decided to exit process\n");
                ExitProcess(-1);
            } else if (hm == ContinueBtn.id) {
                printf("user decided to continue crashing\n\n");
                _throwAgain = false;
                PostQuitMessage(0);
            }
            break;
        }
        case WM_CTLCOLORSTATIC: {
            HDC hdcStatic = (HDC) wParam;
            HBRUSH BGColorBrush = CreateSolidBrush(RGB(255, 255, 255));
//        SetBkMode(hdcStatic, TRANSPARENT);
            return (INT_PTR) (HBRUSH) BGColorBrush;
        }
        case WM_DESTROY:
            printf("user decided to continue crashing\n\n");
            PostQuitMessage(0);
            break;
        default:
            return DefWindowProc(hwnd, message, wParam, lParam);
            break;
    }
    return 0;
}

void showError(const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    char tmp[1024];
    int len = wvsprintfA(tmp, fmt, ap);
#if 0
    tmp[len++] = '\n';
    tmp[len] = '\0';
    WriteConsoleA(GetStdHandle(STD_OUTPUT_HANDLE), tmp, len, NULL, NULL);
#else
    tmp[len] = '\0';
    MessageBox(NULL, tmp, FlameException_title, MB_ICONERROR | MB_DEFAULT_DESKTOP_ONLY | MB_TASKMODAL);
#endif
    va_end(ap);
}

bool ExceptionWindow::registered = false;

BOOL ExceptionWindow::init(HINSTANCE hInstance) {
    if (registered) return TRUE;
    gui::initLayout(hInstance);

    WNDCLASSEX wcex;
    wcex.cbSize = sizeof(WNDCLASSEX);
    wcex.style = CS_HREDRAW | CS_VREDRAW;
    wcex.lpfnWndProc = ExceptionWindow::WndProc;
    wcex.cbClsExtra = 0;
    wcex.cbWndExtra = 0;
    wcex.hInstance = hInstance;
    wcex.hIcon = LoadIcon(wcex.hInstance, IDI_APPLICATION);
    wcex.hCursor = LoadCursor(NULL, IDC_ARROW);
    wcex.hbrBackground = (HBRUSH) (COLOR_WINDOW + 1);
    wcex.lpszMenuName = NULL;
    wcex.lpszClassName = FlameException_class;
    wcex.hIconSm = LoadIcon(wcex.hInstance, IDI_APPLICATION);

    if (!RegisterClassEx(&wcex)) {
        showError("RegisterClassEx failed: %08X", GetLastError());
        return FALSE;
    }
    registered = true;
    return TRUE;
}

BOOL ExceptionWindow::show(HINSTANCE hInstance) {
    if (!init(hInstance)) return FALSE;

    HWND hWnd = CreateWindowEx(
            WS_EX_OVERLAPPEDWINDOW | WS_EX_TOPMOST,
            FlameException_class,
            FlameException_title,
            WS_OVERLAPPEDWINDOW,
            CW_USEDEFAULT, CW_USEDEFAULT, 640, 480,
            NULL,
            NULL,
            hInstance,
            this
    );

    if (!hWnd) {
        showError("CreateWindowEx failed: %08X", GetLastError());
        return FALSE;
    }

    std::cout << "show window " << std::endl;
    ShowWindow(hWnd, SW_NORMAL);
    std::cout << "update window " << std::endl;
    UpdateWindow(hWnd);

    SetForegroundWindow(hWnd);

    std::cout << "start get messages" << std::endl;
    MSG msg;
    while (GetMessage(&msg, hWnd, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }
    ShowWindow(hWnd, SW_HIDE);
    return TRUE;
}
