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
from .code_collector import CodeRelocsCollector
from .data_collector import DataRelocsCollector, visit_jumptables
from . import RANGES
from . import PATHS
from . import fill_comment


def collect():
  relocs = Relocs(PATHS.OUT)
  # relocs.read()
  col = CodeRelocsCollector(relocs)
  col.collect()

  col = DataRelocsCollector(relocs)
  col.collect()

  # comments
  # fill_comment.do_fill_jpt_context(relocs)
  # fill_comment.do_fill_text_context(relocs)

  for rel in relocs.relocs:
    rel.context = ""
    rel.flags = []

  relocs.write()


def rmcmt():
  relocs = Relocs(PATHS.OUT)
  relocs.read()
  for rel in relocs.relocs:
    rel.context = ""
    rel.flags = []
  relocs.write()



def manual_test():
  relocs = Relocs(PATHS.OUT)
  col = DataRelocsCollector(relocs)
  ea = 0x0053B704
  ea, has_va = col.visit_ea(ea)
  print(f'{ea:08X}')
  ea, has_va = col.visit_ea(ea)
  # for rel in relocs.relocs:
  #   print(f'{RANGES.img_base + rel.src_va:08X} -> {RANGES.img_base + rel.dst_va:08X} {rel.kind.name}')
  print(f'{ea:08X}')
  # visit_jumptables(relocs)

