import enum
import os
import idaapi
import idc
import idautils
import typing
import bisect
from .relocs import Relocs, Reloc
from .flags import Flags
from .kind import Kind
from . import PATHS
from . import RANGES
from . import FIXUPS


def is_jpt_start(ea):
  name = idaapi.get_name(ea)
  return name and name.startswith('jpt_')


def is_code_block_start(ea):
  name = idaapi.get_name(ea)
  return name and name.startswith('loc_')


def is_string_start(ea):
  flags = idaapi.get_flags(ea)
  return idaapi.is_strlit(flags)


def is_jpt_default_case(ea, dst):
  dst_name = idaapi.get_name(dst)
  if dst_name and dst_name.startswith('def_'):
    prev_ea = idaapi.prev_head(ea, RANGES.img_base + RANGES.code_min_rva)
    if prev_ea != idaapi.BADADDR:
      return is_jpt_start(prev_ea)
  return False


def is_prob_function_start(dst):
  flags = idaapi.get_flags(dst)
  if not idaapi.is_code(flags):
    return False
  prev_ea = idaapi.prev_head(dst, RANGES.img_base + RANGES.code_min_rva)
  if prev_ea == idaapi.BADADDR:
    return False
  if (prev_ea + idaapi.get_item_size(prev_ea)) != dst:
    return False
  prev_flags = idaapi.get_flags(prev_ea)
  return idaapi.is_align(prev_flags)


def is_require_review(src, dst, src_offs) -> tuple[bool, str]:
  if (dst & 0xFFF) == 0:
    if src in FIXUPS.trusted_suspicious_data_ref:
      return False, 'dst.is_trusted_susp'
    return True, '*000'
  dst_flags = idaapi.get_flags(dst)
  if idaapi.is_func(dst_flags):
    return False, 'dst.is_func'
  if idaapi.is_struct(dst_flags):
    return False, 'dst.is_struct'
  src_flags = idaapi.get_flags(src - src_offs)
  if idaapi.is_struct(src_flags):
    ti = idaapi.opinfo_t()
    if idaapi.get_opinfo(ti, src - src_offs, 0, src_flags):
      sname = idaapi.get_struc_name(ti.tid)
      if sname == '_SCOPETABLE_ENTRY':
        loff = src_offs % 12
        if loff == 4 or loff == 8:
          return False, '_SCOPETABLE_ENTRY.ptr1'
      elif sname == 'FuncInfoV1':
        loff = src_offs
        if loff == 8 or loff == 0x10:
          return False, 'FuncInfoV1.ptr1'
      elif sname == 'WindowCfg':
        loff = src_offs
        if loff == 0x3E:
          return False, 'WindowCfg.ptr1'
      elif sname == 'GameObj6A0B00':
        loff = src_offs % 0xA
        if loff == 0x2:
          return False, 'GameObj6A0B00.ptr1'
      elif sname == 'DIDATAFORMAT':
        print("hello %08X" % src)
        loff = src_offs
        if loff == 0x14:
          return False, 'DIDATAFORMAT.ptr1'
      elif sname == 'ButtonCfg':
        if src_offs in [0x48, 0x44]:
          print("ButtonCfg %08X+%02X -> %08X" % (src - src_offs, src_offs, dst))
          return False, 'ButtonCfg.ptr1'
        if src_offs in [0x34, 0x38, 0x3C]:
          print("ButtonCfg %08X+%02X -> %08X" % (src - src_offs, src_offs, dst))
        pass
  if is_jpt_start(src - src_offs):
    return False, 'jpt'
  if is_jpt_default_case(src, dst):
    return False, 'jpt_default'
  if is_string_start(dst):
    return False, 'string_start'
  # if not idaapi.is_head(dst_flags):
  #   print(f"{src:08X} review by head")
  #   return True
  dst_name = idaapi.get_ea_name(dst)
  if dst_name.startswith("??"):
    return False, 'dst.name==??*'
  if dst_name.startswith("__CT"):
    return False, 'dst.name==__CT*'
  if src in FIXUPS.TRUSTED_REFS:
    return False, 'trusted'
  if src_offs != 0:
    return True, 'src_offs'
  if is_prob_function_start(dst):
    return False, 'prob_fun_start'
  if is_code_block_start(dst):
    return False, 'codeblock_start'
  return True, 'unk'


class DataRelocsCollector:
  # ButtonCfg check

  min_rva = RANGES.code_min_rva
  max_rva = RANGES.data_max_rva
  min_va = RANGES.img_base + min_rva
  max_va = RANGES.img_base + max_rva
  # min_search = img_base + RANGES.code_max_rva
  # min_search = 0x006ADEF0
  # min_search = 0x006B2AA2
  # min_search = 0x006B3860
  min_search = RANGES.img_base + min_rva
  max_search = RANGES.img_base + max_rva
  # min_search = 0x0067CB48
  # max_search = min_search + 0x40

  # 0069FF5B - 006A0EE7

  def __init__(self, relocs: Relocs):
    self.relocs = relocs
    self.limit = 160000

  def is_rva(self, val):
    return self.min_rva <= val < self.max_rva

  def is_va(self, val):
    return self.min_va <= val < self.max_va

  def visit_va(self, ea, offs, force=False):
    val = idaapi.get_32bit(ea)
    if self.is_va(val) and self.relocs.get(ea) is None:
      if ea in FIXUPS.NOT_RELOCS:
        self.relocs.add(Reloc(ea, 0, val, Kind.NOT_VA32))
        return True
      is_bad, reason = is_require_review(ea, val, offs)
      if is_bad and not force:
        print("va->va %08X->%08X offs:%02X bad va %s %d" % (ea, val, offs, reason, self.limit,))
        self.limit -= 1
      else:
        print("va->va %08X->%08X offs:%02X ok va %s" % (ea, val, offs, reason))
        self.relocs.add(Reloc(ea, 0, val, Kind.VA32))
      return True
    # if self.is_rva(val):
    #   print("hit rva %08X->%08X" % (ea, val))
    #   return True
    return False

  def visit_data(self, ea, size, flags):
    has_va = False
    if size <= 4:
      has_va = self.visit_va(ea, 0)
    else:
      if not idaapi.is_strlit(flags):
        for i in range(size - 3):
          if self.visit_va(ea + i, i):
            has_va = True
    # if has_va:
    return has_va

  def visit_head0(self, ea, flags):
    size = idaapi.get_item_size(ea)
    next_ea = ea + size
    if idaapi.is_code(flags):
      if next_ea >= self.max_search:
        print("exit max0 %08X" % next_ea)
        return idaapi.BADADDR, False
      return next_ea, False
    has_va = self.visit_data(ea, size, flags)
    if next_ea >= self.max_search:
      print("exit max1 %08X" % next_ea)
      return idaapi.BADADDR, has_va
    return next_ea, has_va

  def visit_ea(self, ea):
    # if ea >= 0x0067CB48:
    #   print("visit %08X" % ea)
    #   return idaapi.BADADDR, False

    flags = idaapi.get_flags(ea)
    if idaapi.is_head(flags):
      next_ea, has_va = self.visit_head0(ea, flags)
      return next_ea, has_va
    next_ea = idaapi.next_head(ea, self.max_search)
    if next_ea == idaapi.BADADDR:
      print("exit max2 %08X" % ea)
      return next_ea, False
    head_size = next_ea - ea
    has_va = self.visit_data(ea, head_size, flags)
    return next_ea, has_va

  def collect(self):
    ea = self.min_search
    while True:
      if self.limit <= 0:
        break
      ea, has_va = self.visit_ea(ea)
      if ea == idaapi.BADADDR:
        break

def collect_data_relocs():
  relocs = Relocs(PATHS.OUT)
  relocs.read()
  col = DataRelocsCollector(relocs)
  col.collect()
  # relocs.write()

def collect_force():
  relocs = Relocs(PATHS.OUT)
  relocs.read()
  col = DataRelocsCollector(relocs)
  if col.visit_va(idaapi.get_screen_ea(), 0, True):
    print("OK")
  # relocs.write()

def collect_force_sel():
  value, fr, to = idaapi.read_range_selection(idaapi.get_current_viewer())
  if not value:
    print("select region")
    return
  relocs = Relocs(PATHS.OUT)
  relocs.read()
  col = DataRelocsCollector(relocs)
  visited = 0
  for ea in range(fr, to, 4):
    if col.visit_va(ea, 0, True):
      visited += 1
  # relocs.write()
  print("%d" % visited)


def visit_jumptables(relocs: Relocs):
  for jpt_ea, name in idautils.Names():
    if not name.startswith('jpt_'):
      continue
    size = idaapi.get_item_size(jpt_ea)
    print(f'jpt {jpt_ea:08X} {jpt_ea+size:08X}')

