//
// Created by DiaLight on 16.08.2024.
//

#include "console.h"
#include <Windows.h>
#include <ios>
#include <io.h>
#include <fcntl.h>


void RedirectStandardIo() {
    /* This clever code have been found at:
    Adding Console I/O to a Win32 GUI App
    Windows Developer Journal, December 1997
    http://dslweb.nwnexus.com/~ast/dload/guicon.htm
    Andrew Tucker's Home Page */

    // redirect unbuffered STDOUT to the console
    long lStdHandle = (long)GetStdHandle(STD_OUTPUT_HANDLE);
    int hConHandle = _open_osfhandle(lStdHandle, _O_TEXT);
    if(hConHandle > 0) {
        FILE *fp = _fdopen(hConHandle, "w");
        *stdout = *fp;
        setvbuf(stdout, NULL, _IONBF, 0);
    }

    // redirect unbuffered STDIN to the console
    lStdHandle = (long)GetStdHandle(STD_INPUT_HANDLE);
    hConHandle = _open_osfhandle(lStdHandle, _O_TEXT);
    if(hConHandle > 0) {
        FILE *fp = _fdopen( hConHandle, "r" );
        *stdin = *fp;
        setvbuf(stdin, NULL, _IONBF, 0);
    }

    // redirect unbuffered STDERR to the console
    lStdHandle = (long)GetStdHandle(STD_ERROR_HANDLE);
    hConHandle = _open_osfhandle(lStdHandle, _O_TEXT);
    if(hConHandle > 0) {
        FILE *fp = _fdopen(hConHandle, "w");
        *stderr = *fp;
        setvbuf(stderr, NULL, _IONBF, 0 );
    }

    // make cout, wcout, cin, wcin, wcerr, cerr, wclog and clog point to console as well
    std::ios::sync_with_stdio();
}


bool initConsole() {
    AllocConsole();
    freopen_s((FILE**)stdout, "CONOUT$", "w", stdout);
    freopen_s((FILE**)stderr, "CONOUT$", "w", stderr);

    RedirectStandardIo();
    return true;
}
