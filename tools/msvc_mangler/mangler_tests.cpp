//
// Created by DiaLight on 04.07.2024.
//
#include <sstream>
#include "msvc_mangler.h"
#include "SGMap.h"
#include <Windows.h>

bool assert_mangle(const char *sgmap, const char *mangled, const char *demangled) {
    SGMapArena sgArena;
    std::vector<Struct *> structs;
    std::vector<Global *> globals;
    std::stringstream ss(sgmap);
    {
        if(!SGMap_deserialize(ss, structs, globals, sgArena)) throw std::exception("parse failed");
        if(!SGMap_link(structs, globals)) throw std::exception("link failed");
    }
    if(globals.size() != 1) throw std::exception("invalid globals count");
    std::string mname = msvcMangleName(globals[0]);
    if(mname != mangled) {
        printf("\n");
        printf("[-] mangle mismatch\n");
        printf("result: %s\n", mname.c_str());
        printf("expect: %s\n", mangled);
        printf("demangled: %s\n", demangled);
        return false;
    }
    return true;
}

void tests() {
    // simple
    assert_mangle(R"(
global: va=00638440,name=dk2_start,size=424
  type: kind=function,declspec=stdcall
    ret: kind=void
)", "?dk2_start@dk2@@YGXXZ", "void __stdcall dk2::dk2_start(void)");
    // ptr
    assert_mangle(R"(
global: va=005A5DA0,name=dk2_main,size=1544
  type: kind=function,declspec=cdecl
    ret: kind=int,size=4,signed=True
    arg: kind=int,size=4,signed=True
    arg: kind=ptr
      type: kind=ptr,is_const=True
        type: kind=int,size=1,signed=True,winapi=CHAR
)", "?dk2_main@dk2@@YAHHPAPBD@Z", "int __cdecl dk2::dk2_main(int,char const * *)");
    // name repeat
    assert_mangle(R"(
global: va=005B2DA0,name=setHInstance,size=10
  type: kind=function,declspec=cdecl
    ret: kind=ptr,winapi=HINSTANCE
      type: kind=winapi,name=HINSTANCE__,size=4
    arg: kind=ptr,winapi=HINSTANCE
      type: kind=winapi,name=HINSTANCE__,size=4
)", "?setHInstance@dk2@@YAPAUHINSTANCE__@@PAU2@@Z", "struct HINSTANCE__ * __cdecl dk2::setHInstance(struct HINSTANCE__ *)");
    // arg repeat
    assert_mangle(R"(
global: va=006477F0,name=WinMain,size=38
  type: kind=function,declspec=stdcall
    ret: kind=int,size=4,signed=True
    arg: kind=ptr,winapi=HINSTANCE
      type: kind=winapi,name=HINSTANCE__,size=4
    arg: kind=ptr,winapi=HINSTANCE
      type: kind=winapi,name=HINSTANCE__,size=4
    arg: kind=ptr
      type: kind=int,size=1,signed=True,winapi=CHAR
    arg: kind=int,size=4,signed=True
)", "?WinMain@dk2@@YGHPAUHINSTANCE__@@0PADH@Z", "int __stdcall WinMain(struct HINSTANCE__ *,struct HINSTANCE__ *,char *,int)");
    // global 1
    assert_mangle(R"(
global: va=007A5698,name=g_argc,size=4
  type: kind=int,size=4,signed=True
)", "?g_argc@dk2@@3HA", "int dk2::g_argc");
    // global 2
    assert_mangle(R"(
global: va=007A569C,name=g_argv,size=4
  type: kind=ptr
    type: kind=ptr,is_const=True
      type: kind=int,size=1,signed=True,winapi=CHAR
)", "?g_argv@dk2@@3PAPBDA", "char const * * dk2::g_argv");
    // ignore one char arg repeat
    assert_mangle(R"(
global: va=00557FD0,name=isOsVersionGE,size=265
  type: kind=function,declspec=stdcall
    ret: kind=int,size=4,signed=True,winapi=BOOL
    arg: kind=int,size=4,signed=True
    arg: kind=int,size=4,signed=True
    arg: kind=int,size=2
)", "?isOsVersionGE@dk2@@YGHHHG@Z", "int __stdcall dk2::isOsVersionGE(int,int,unsigned short)");
    // wchar_t
    assert_mangle(R"(
global: va=00553B90,name=MBToUni_convert,size=109
  type: kind=function,declspec=cdecl
    ret: kind=int,size=4,signed=True,winapi=BOOL
    arg: kind=ptr
      type: kind=int,size=1
    arg: kind=ptr
      type: kind=int,size=2,winapi=wchar_t
    arg: kind=int,size=2,signed=True
)", "?MBToUni_convert@dk2@@YAHPAEPA_WF@Z", "int __cdecl dk2::MBToUni_convert(unsigned char *,wchar_t *,short)");
    // WCHAR
    assert_mangle(R"(
global: va=005557E0,name=unicodeToUtf8,size=99
  type: kind=function,declspec=cdecl
    ret: kind=int,size=4,signed=True
    arg: kind=ptr,is_const=True
      type: kind=int,size=2,winapi=WCHAR,fname=wchar_t
    arg: kind=ptr
      type: kind=int,size=1,signed=True,winapi=CHAR,fname=CHAR
    arg: kind=int,size=4,signed=True
)", "?unicodeToUtf8@dk2@@YAHPB_WPADH@Z", "int __cdecl dk2::unicodeToUtf8(wchar_t const *,char *,int)");
    // struct
    assert_mangle(R"(
struct: id=instance_0066F24C,name=TbDiscFile_vtbl,size=0
struct: id=vtbl_0066F24C,name=TbDiscFile,size=4,vtable=instance_0066F24C
global: va=005B3980,name=MyDiscFile_create,size=162
  type: kind=function,declspec=cdecl
    ret: kind=ptr
      type: kind=int,size=4,signed=True
    arg: kind=ptr
      type: kind=int,size=4,signed=True
    arg: kind=ptr
      type: kind=ptr
        type: kind=struct,id=vtbl_0066F24C
    arg: kind=ptr
      type: kind=int,size=1,signed=True,winapi=char
    arg: kind=int,size=4,signed=True
)", "?MyDiscFile_create@dk2@@YAPAHPAHPAPAUTbDiscFile@1@PADH@Z", "int * __cdecl dk2::MyDiscFile_create(int *,struct dk2::TbDiscFile * *,char *,int)");
    // vararg
    assert_mangle(R"(
global: va=00634E90,name=_swprintf,size=148
  type: kind=function,declspec=cdecl_varargs
    ret: kind=int,size=4,signed=True
    arg: kind=ptr
      type: kind=int,size=2,winapi=wchar_t
    arg: kind=ptr,is_const=True
      type: kind=int,size=2,winapi=wchar_t
)", "?_swprintf@dk2@@YAHPA_WPB_WZZ", "int __cdecl dk2::_swprintf(wchar_t *,wchar_t const *,...)");
    // float
    assert_mangle(R"(
struct: id=constructor_00557B70,name=MyGame,size=0
global: va=00559790,name=sub_559790,size=92,member_of=constructor_00557B70
  type: kind=function,declspec=thiscall
    ret: kind=float,size=8
    arg: kind=ptr
      type: kind=struct,id=constructor_00557B70
)", "?sub_559790@MyGame@dk2@@QAENXZ", "public: double __thiscall dk2::MyGame::sub_559790(void)");
    // double arg repeat
    assert_mangle(R"(
struct: id=constructor_005BAE70,name=MyMutex,size=0
global: va=005BAE70,name=constructor,size=61,member_of=constructor_005BAE70
  type: kind=function,declspec=thiscall
    ret: kind=ptr
      type: kind=struct,id=constructor_005BAE70
    arg: kind=ptr
      type: kind=struct,id=constructor_005BAE70
    arg: kind=ptr,is_const=True
      type: kind=int,size=1,signed=True,winapi=CHAR
)", "?constructor@MyMutex@dk2@@QAEPAU12@PBD@Z", "public: struct dk2::MyMutex * __thiscall dk2::MyMutex::constructor(char const *)");
    // global extern array is just ptr
    assert_mangle(R"(
global: va=00740780,name=g_wchar_buf,size=1024
  type: kind=array,count=512
    type: kind=int,size=2,winapi=wchar_t
)", "?g_wchar_buf@dk2@@3PA_WA", "wchar_t * dk2::g_wchar_buf");
    // function arg
    assert_mangle(R"(
global: va=005BA4E0,name=setDebugStringFun,size=10
  type: kind=function,declspec=cdecl
    ret: kind=int,size=4,signed=True
    arg: kind=ptr
      type: kind=function,declspec=cdecl
        ret: kind=int,size=4,signed=True
        arg: kind=ptr
          type: kind=int,size=1,signed=True,winapi=char
)", "?setDebugStringFun@dk2@@YAHP6AHPAD@Z@Z", "int __cdecl dk2::setDebugStringFun(int (__cdecl*)(char *))");
    // ULONG_PTR
    assert_mangle(R"(
global: va=00556650,name=CWindowTest_proc,size=180
  type: kind=function,declspec=stdcall
    ret: kind=int,size=4,signed=True,winapi=LRESULT,fname=LONG_PTR
    arg: kind=ptr,winapi=HWND
      type: kind=winapi,name=HWND__,size=4
    arg: kind=int,size=4,fname=UINT
    arg: kind=int,size=4,winapi=WPARAM,fname=UINT_PTR
    arg: kind=int,size=4
)", "?CWindowTest_proc@dk2@@YGJPAUHWND__@@III@Z", "long __stdcall dk2::CWindowTest_proc(struct HWND__ *,unsigned int,unsigned int,unsigned int)");
    // HRESULT
}

void lasty_test() {
    assert_mangle(R"(
struct: id=vtbl_00673048,name=MyDirectInput,size=4
global: va=005DDBC0,name=initDevice_0,size=25,member_of=vtbl_00673048
  type: kind=function,declspec=thiscall
    ret: kind=ptr
      type: kind=int,size=4,signed=True,winapi=HRESULT,fname=HRESULT
    arg: kind=ptr
      type: kind=struct,id=vtbl_00673048
    arg: kind=ptr
      type: kind=int,size=4,signed=True,winapi=HRESULT,fname=HRESULT
)", "?initDevice_0@MyDirectInput@dk2@@QAEPAJPAJ@Z", "public: long * __thiscall dk2::MyDirectInput::initDevice_0(long *)");
}

int main() {
    try {
//        tests();
        lasty_test();
    } catch (std::exception &e) {
        printf("[e] %s\n", e.what());
    }
    return 0;
}
