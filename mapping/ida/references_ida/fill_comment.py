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



def get_struc_start(src):
  flags = idaapi.get_flags(src)
  if idaapi.is_struct(flags):
    return src
  ea = idaapi.prev_head(src, RANGES.img_base)
  if ea != idaapi.BADADDR:
    size = idaapi.get_item_size(ea)
    if ea < src < (ea + size):
      flags = idaapi.get_flags(ea)
      if idaapi.is_struct(flags):
        return ea
  return idaapi.BADADDR


def do_fill_text_context(relocs: Relocs):
  count = 0
  for rel in relocs.relocs:
    if rel.kind.is_ignore():
      continue
    if rel.context:
      continue
    src = rel.src_va
    dst = rel.dst_va
    if not RANGES.in_code(src):
      continue
    fun = idaapi.get_func(src)  # type: idaapi.func_t
    src_desc = None
    if fun is not None:
      fun_name = idaapi.get_func_name(fun.start_ea)
      src_desc = '%s+%02X' % (fun_name, src - fun.start_ea)
    if not src_desc:
      ea = get_struc_start(src)
      if ea != idaapi.BADADDR:
        ti = idaapi.opinfo_t()
        if idaapi.get_opinfo(ti, ea, 0, idaapi.get_flags(ea)):
          sname = idaapi.get_struc_name(ti.tid)
          src_desc = '%s+%02X' % (sname, src - ea)
    if not src_desc:
      if 0x00647830 <= src < 0x006478A0:
        src_desc = 'c_dfDIMouseFormat+%02X' % (src - 0x00647830)
      if 0x006478A0 <= src < 0x006488A0:
        src_desc = 'c_dfDIKeyboardFormat+%02X' % (src - 0x006478A0)
      if 0x006551C0 <= src < 0x006552B0:  # cseg
        continue
      if 0x00664AA8 <= src < 0x00665EB0:  # cseg
        continue

    if not src_desc:
      print("%08X -> %08X no src function" % (src, dst), src_desc, rel.context)
      assert False

    dst_name = idc.get_name(dst, idaapi.GN_VISIBLE)
    if not dst_name:
      ea = idaapi.prev_head(dst, RANGES.img_base)
      if ea != idaapi.BADADDR:
        size = idaapi.get_item_size(ea)
        if ea < dst < (ea + size):
          struc_name = idc.get_name(ea, idaapi.GN_VISIBLE)
          if not struc_name:
            print("%08X -> %08X %08X" % (src, dst, ea), rel.kind)
            assert False
          dst_name = '%s+%02X' % (struc_name, dst - ea)
    if not dst_name:
      fun = idaapi.get_func(dst)  # type: idaapi.func_t
      if fun is not None and fun.start_ea == dst:
        dst_name = idaapi.get_func_name(fun.start_ea)
      else:
        print("!%08X %08X" % (fun.start_ea if fun is not None else 0, dst))
    if not dst_name:
      dst_name = idc.get_name(dst, idaapi.GN_LOCAL)
      print("%08X -> %08X no dst name" % (src, dst))
      assert False

    print('%08X %08X %s -> %s' % (src, dst, src_desc, dst_name))
    # size = idaapi.get_item_size(src)
    rel.context = '%s -> %s' % (src_desc, dst_name)
    # print(name, rel.context)
    count += 1
    # if count > 564:
    #   print('threshold break')
    #   break


def do_fill_jpt_context(relocs: Relocs):
  count = 0
  for jpt_ea, name in idautils.Names():
    if not name.startswith('jpt_'):
      continue
    size = idaapi.get_item_size(jpt_ea)
    for offs in range(size // 4):
      ea = jpt_ea + offs * 4
      rel = relocs.get(ea)
      rel.context = '%s+%02X' % (name, offs * 4)
      # print(rel.context)
    count += 1
    # if count > 16:
    #   print('threshold break')
    #   break
    # print(name, rel.context)


def fill_jpt_context():
  relocs = Relocs(PATHS.OUT)
  relocs.read()
  do_fill_jpt_context(relocs)
  # relocs.write()


def fill_text_context():
  relocs = Relocs(PATHS.OUT)
  relocs.read()
  do_fill_text_context(relocs)
  # relocs.write()

