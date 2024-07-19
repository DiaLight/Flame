import enum
import os
import idaapi
import idc
import idautils
import typing
import bisect
from .relocs import Relocs, Reloc
from .flags import Flags, get_desc
from .kind import Kind
from . import PATHS
from . import RANGES


def dump_flags(flags):
  if idaapi.is_code(flags):
    yield 'code'
  if idaapi.is_data(flags):
    yield 'data'
  if idaapi.is_tail(flags):
    yield 'tail'
  if idaapi.is_unknown(flags):
    yield 'unk'
  if idaapi.is_head(flags):
    yield 'head'
  if idaapi.is_byte(flags):
    yield 'byte'
  if idaapi.is_word(flags):
    yield 'word'
  if idaapi.is_dword(flags):
    yield 'dword'
  if idaapi.is_qword(flags):
    yield 'qword'
  if idaapi.is_float(flags):
    yield 'float'
  if idaapi.is_double(flags):
    yield 'double'
  if idaapi.is_strlit(flags):
    yield 'strlit'
  if idaapi.is_struct(flags):
    yield 'struct'
  if idaapi.is_align(flags):
    yield 'align'
  if idaapi.is_custom(flags):
    yield 'custom'

def test_part_of(ea, size, flags, src, dst):
  if src == ea and size == 4:
    test_dword(src, dst, flags)
    return
  if idaapi.is_code(flags):
    return
  if idaapi.is_struct(flags):
    return
  name = idc.get_name(ea, idaapi.GN_VISIBLE)
  if name is not None and name.startswith('jpt_'):
    return

  # ti = idaapi.opinfo_t()
  # if idaapi.get_opinfo(ti, ea, 0, flags):
  #   sname = idaapi.get_struc_name(ti.tid)
    # idc.Arra()
  # if idaapi.is_dword(flags) and idaapi.is_off0(flags):
  #   return
  print("%08X partof %08X+%02X(%08X) -> %08X  %08X %s" % (
    ea - RANGES.img_base, ea, src - ea, src, dst, flags, ' '.join(dump_flags(flags))
  ))
  return True

def test_undefined(src, dst, flags):
  print("undef %08X -> %08X  %08X" % (src, dst, flags))
  return True

def test_dword(src, dst, flags):
  if idaapi.is_float(flags):
    print("float %08X -> %08X  %08X" % (src, dst, flags))
    return True
  if idaapi.is_dword(flags):
    return
  print("dword %08X -> %08X  %08X" % (src, dst, flags))
  return True

def test_ea(src, dst):
  flags = idaapi.get_flags(src)
  if idaapi.is_head(flags):
    size = idaapi.get_item_size(src)
    return test_part_of(src, size, flags, src, dst)
  ea = idaapi.prev_head(src, RANGES.img_base + 0x1000)
  size = idaapi.get_item_size(ea)
  if ea < src < (ea + size):
    flags = idaapi.get_flags(ea)
    return test_part_of(ea, size, flags, src, dst)
  return test_undefined(src, dst, flags)


def do_inspect(relocs: Relocs):
  count = 0
  for rel in relocs.relocs:
    if rel.kind.is_ignore():
      continue
    src = rel.src_va
    dst = rel.dst_va
    if test_ea(src, dst):
      count += 1
      if count > 16:
        print('threshold break')
        break


def test():
  relocs = Relocs(PATHS.OUT)
  relocs.read()
  do_inspect(relocs)
  # relocs.write()
