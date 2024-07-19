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
from .code_collector import collect_code_relocs
from .data_collector import collect_data_relocs, collect_force, collect_force_sel
from . import PATHS
from . import RANGES
from . import all_in_one


def utf16_list():
  start = idaapi.get_screen_ea()
  max_va = RANGES.img_base + RANGES.data_max_rva
  end = idaapi.next_head(start, max_va)
  assert end != idaapi.BADADDR
  ea = start

  while ea < end:
    v0 = idaapi.get_byte(ea)
    if v0 == 0:
      ea += 1
      continue
    v1 = idaapi.get_byte(ea + 1)
    if v1 != 0:
      return
    assert idaapi.create_strlit(ea, 0, idaapi.STRTYPE_C_16)
    size = idaapi.get_item_size(ea)
    ea += size



def rw():
  relocs = Relocs(PATHS.OUT)
  relocs.read()
  relocs.write()


def gen():
  all_in_one.collect()

