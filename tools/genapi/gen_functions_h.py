import pathlib
from gen_utils import *
from dk2cxx import *


def format_functions_h(globals: list[sgmap.Global]):
  define_name = f"DK2_FUNCTIONS_H"

  def format_h_head():
    yield format_middle(f"warning: file is generated by {pathlib.Path(__file__).name}")
    yield empty_line
    yield f"#ifndef {define_name}"
    yield f"#define {define_name}"
    yield empty_line
    yield f"#include <cstdint>"
    yield f"#include <cstdio>"
    yield f"#include <dinput.h>"
    yield f"#include <ddraw.h>"
    yield f"#include <dsound.h>"
    yield f"#include <d3d.h>"
    yield f"#include <xmmintrin.h>"
    yield f"#include <ehdata.h>"
    yield f"#ifndef VLC_H"
    yield f"#define VLC_H"
    yield f"#include <vlc.h>"
    yield f"#endif //VLC_H"
    yield f"#include <ctime>"
    yield f"#define _TBYTE long double  // assembly type. msvc does not have 10-byte floating point (x87 extended precision 80-bit value)"
    yield empty_line
    complete_types = set()
    ref_types = set()
    for glob in filter(filter_function_var, globals):
      collect_types(glob.type, complete_types, ref_types, False)
    for complete_struct in sorted(complete_types, key=lambda s: s.name):
      yield f"#include <{build_struct_path(complete_struct, 'h')}>"
      if complete_struct.name in ref_types:
        ref_types.remove(complete_struct.name)
    if ref_types:
      yield empty_line
      yield f"namespace dk2 {{"
      for name in sorted(ref_types):
        yield f"  struct {name};"
      yield f"}}  // namespace dk2"
    yield empty_line
  yield from map(format_autogen_line, format_h_head())

  def format_h_body():
    yield f"namespace dk2 {{"
    for glob in filter(filter_function_var, globals):
      fun_t = glob.type  # type: sgmap.FunctionType
      suffix = "  // assembly" if fun_t.declspec is sgmap.Declspec.Assembly else ''
      name = format_function_name(glob.name)
      yield f"/*{glob.va:08X}*/ {format_function(fun_t, name)};{suffix}"
    yield f"}}  // namespace dk2"
  yield from map(format_autogen_line, format_h_body())

  def format_h_tail():
    yield f"#endif //{define_name}"
    yield empty_line
  yield from map(format_autogen_line, format_h_tail())

