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


class CodeRelocsCollector:
  # ButtonCfg check

  min_rva = RANGES.code_min_rva
  # min_rva = RANGES.code_max_rva
  # max_rva = RANGES.code_max_rva
  max_rva = RANGES.data_max_rva
  min_va = RANGES.img_base + min_rva
  max_va = RANGES.img_base + max_rva
  min_search = RANGES.img_base + min_rva
  max_search = RANGES.img_base + max_rva
  # min_search = 0x00640C28
  # max_search = min_search + 0x8

  def __init__(self, relocs: Relocs):
    self.relocs = relocs

  def is_rva(self, val):
    return self.min_rva <= val < self.max_rva

  def is_va(self, val):
    return self.min_va <= val < self.max_va

  def visit_va(self, ea, offs):
    print("  VA32 %08X" % (ea))
    val = idaapi.get_32bit(ea)
    self.relocs.add(Reloc(ea, 0, val, Kind.VA32))

  def visit_rel32(self, ea, end, fr, value, to):
    assert ((end + value) & 0xFFFFFFFF) == to
    assert (end - fr) == 4
    print("  REL32 %08X: %08X->%08X  # %08X - (%08X + %d) == %08X" % (ea, fr, to, to, fr, end - fr, (to - end) & 0xFFFFFFFF))
    self.relocs.add(Reloc(fr, ((to - end) - value) & 0xFFFFFFFF, to, Kind.REL32))

  def get_fixup_ops(self, ins: idaapi.insn_t, ins_size):
    for i in range(idaapi.UA_MAXOP):
      op = ins.ops[i]  # type: idaapi.op_t
      if op.type == idaapi.o_void:  # No Operand
        continue
      if op.type not in [
        # idaapi.o_reg,       #  1  // General Register (al, ax, es, ds...) reg
        idaapi.o_mem,       #  2  // Direct Memory Reference  (DATA)      addr
        # idaapi.o_phrase,    #  3  // Memory Ref [Base Reg + Index Reg]    phrase
        idaapi.o_displ,     #  4  // Memory Reg [Base Reg + Index Reg + Displacement] phrase+addr
        idaapi.o_imm,       #  5  // Immediate Value                      value
        idaapi.o_far,       #  6  // Immediate Far Address  (CODE)        addr
        idaapi.o_near,      #  7  // Immediate Near Address (CODE)        addr

        # x86
        # idaapi.o_idpspec0,  #  8 o_trreg    # trace register
        # idaapi.o_idpspec1,  #  9 o_dbreg    # debug register
        # idaapi.o_idpspec2,  # 10 o_crreg    # control register
        # idaapi.o_idpspec3,  # 11 o_fpreg    # floating point register
        # idaapi.o_idpspec4,  # 12 o_mmxreg   # mmx register
        # idaapi.o_idpspec5,  # 13 o_xmmreg   # xmm register

      ]: continue
      opsize = ins_size - op.offb
      if opsize < 4:
        continue
      yield i, op


  def visit_fixup(self, ea, flags, ins: idaapi.insn_t, ins_size, i, op: idaapi.op_t):
    src = ea + op.offb
    value = idaapi.get_32bit(src)
    dst = op.value if op.value else op.addr
    if dst == value == 0:
      return False
    if not self.is_va(dst):
      # if dst == 0xFF7818A0:
      #   print("%08X: hit" % ea)
      if (dst & 0xFF000000) == 0xFF000000 and RANGES.in_data(dst & 0x00FFFFFF):
        fixed_dst = dst & 0x00FFFFFF
        fixed_flags = idaapi.get_flags(fixed_dst)
        if idaapi.is_head(fixed_flags):
          self.relocs.add(Reloc(src, (value - fixed_dst) & 0xFFFFFFFF, fixed_dst, Kind.VA32))
          return True
        print("not a head")
      if FIXUPS.is_known_custom_code(src, dst):
        print("!!%08X: %d ty:%d dty:%d dst:%08X offb:%d offo:%d" % (
          ea, i, op.type, op.dtype, dst, op.offb, op.offo
        ))
        return False
      return False
    if self.relocs.get(src) is not None:
      return False
    if src in FIXUPS.NOT_RELOCS:
      self.relocs.add(Reloc(src, (value - dst) & 0xFFFFFFFF, dst, Kind.NOT_VA32))
      return True
    print("%08X %s" % (ea, ins.get_canon_mnem()), end='')
    print(" %d ty:%d dty:%d dst:%08X offb:%d offo:%d" % (
      i, op.type, op.dtype, dst, op.offb, op.offo
    ))
    if value != dst:
      if value != ((dst - (ea + ins_size)) & 0xFFFFFFFF):
        raise Exception("%08X -> %08X != %08X" % (src, value, dst))
      self.visit_rel32(ea, ea + ins_size, src, value, dst)
    else:
      self.visit_va(src, op.offb)
    return True

  def visit_code(self, ea, flags, size):
    ins = idaapi.insn_t()
    ins_size = idaapi.decode_insn(ins, ea)
    if not ins_size == size:
      raise Exception("%08X %d %d" % (ea, ins_size, size))
    fixups = list(self.get_fixup_ops(ins, ins_size))
    if len(fixups) == 0:
      return False
    # assert len(fixups) == 1
    for i, op in fixups:
      self.visit_fixup(ea, flags, ins, ins_size, i, op)

  def collect(self):
    ea = self.min_search
    while True:
      flags = idaapi.get_flags(ea)
      while idaapi.is_code(flags):
        size = idaapi.get_item_size(ea)
        self.visit_code(ea, flags, size)
        ea += size
        if ea >= self.max_search:
          break
        flags = idaapi.get_flags(ea)
      ea = idaapi.next_head(ea, self.max_search)
      if ea == idaapi.BADADDR:
        break
    print("last: %08X" % ea)

def collect_code_relocs():
  relocs = Relocs(PATHS.OUT)
  relocs.read()
  col = CodeRelocsCollector(relocs)
  col.collect()
  # relocs.write()

