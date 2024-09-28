import enum
import pathlib
import re
import sys

import my_pe
import ctypes
import capstone
from capstone import *
import pe_types
import bisect


class FboReg(enum.Enum):
  ESP = enum.auto()
  EBP = enum.auto()


class FboOpTy(enum.Enum):
  CALL = enum.auto()
  JMP = enum.auto()
  TAKE_FROM = enum.auto()
  CHANGE = enum.auto()
  CHANGE_ASSIGN = enum.auto()
  FRAME_END = enum.auto()
  ASSIGN = enum.auto()
  ASSIGN_REG = enum.auto()


class FboOp:  # frame base offset operation

  def __init__(self, va, ins_str: str, reg: FboReg, op: FboOpTy, args=tuple()):
    self.va = va
    self.ins_str = ins_str
    self.reg = reg
    self.op = op
    self.args = args

  def dump_ins(self):
    if self.op is FboOpTy.JMP:
      return
    if self.op in [FboOpTy.TAKE_FROM]:
      args = ' '.join([f'{v:08X}' for v in self.args])
    else:
      args = ' '.join([str(v) for v in self.args])
    print(f'{self.va:08X} {self.ins_str:<36s} {self.reg.name.lower()} {self.op.name.lower():<12s} {args}')


def to_str(ins):
  return f'{ins.mnemonic:<4s} {ins.op_str}'


class CodeRangeFinder:

  def __init__(self, exe: my_pe.MyPe, md: capstone.Cs, rva_start, rva_end):
    self.exe = exe
    self.image_base = exe.nt.OptionalHeader.ImageBase
    self.md = md

    self.rva_start = rva_start
    self.rva_end = rva_end
    self.va_start, self.va_end = self.image_base + rva_start, self.image_base + rva_end
    print(f'range {self.va_start:08X}-{self.va_end:08X}')
    self.range_size = rva_end - rva_start

    self.range_offs = 0
    self.jump_tables = {}
    self.indirect_tables = {}
    self.last_cmp_eax_val = None

    self.fbo_ops: list[FboOp] = []
    self.fun_starts: set[int] = set()

  def is_data_start(self, va):
    return va in self.jump_tables or va in self.indirect_tables

  def process_code(self):
    part_start_rva = self.rva_start + self.range_offs
    code = (ctypes.c_ubyte * (self.rva_end - part_start_rva)).from_address(
      self.exe.base + self.exe.rva2raw(part_start_rva))
    for ins in self.md.disasm(code, part_start_rva):  # type: capstone.CsInsn
      va = self.image_base + ins.address
      # print(f'{va:08X} {ins.mnemonic}\t{ins.op_str}')
      next_va = va + ins.size
      self.range_offs = next_va - self.va_start
      assert ins.id not in [capstone.x86.X86_INS_RETF, capstone.x86.X86_INS_RETFQ]
      if ins.id in [capstone.x86.X86_INS_RET]:
        self.fbo_ops.append(FboOp(va, to_str(ins), FboReg.ESP, FboOpTy.FRAME_END, (-4,)))
      elif ins.id in [capstone.x86.X86_INS_PUSH, capstone.x86.X86_INS_POP]:
        sign = -1 if ins.id == capstone.x86.X86_INS_PUSH else 1
        fbo_op = FboOp(va, to_str(ins), FboReg.ESP, FboOpTy.CHANGE, (4 * sign,))
        op: capstone.x86.X86Op = ins.operands[0]
        if op.type == capstone.x86.X86_OP_REG:
          if op.reg in [capstone.x86.X86_REG_ESP, capstone.x86.X86_REG_EBP]:
            reg = FboReg.ESP if op.reg == capstone.x86.X86_REG_ESP else FboReg.EBP
            fbo_op = FboOp(va, to_str(ins), reg, FboOpTy.CHANGE_ASSIGN, (4 * sign, reg))
        self.fbo_ops.append(fbo_op)
      elif ins.id == capstone.x86.X86_INS_MOV:
        op: capstone.x86.X86Op = ins.operands[0]
        op1: capstone.x86.X86Op = ins.operands[1]
        if op.type == capstone.x86.X86_OP_REG:
          if op.reg in [capstone.x86.X86_REG_ESP, capstone.x86.X86_REG_EBP]:
            reg = FboReg.ESP if op.reg == capstone.x86.X86_REG_ESP else FboReg.EBP
            fbo_op = FboOp(va, to_str(ins), reg, FboOpTy.ASSIGN, (None,))
            if op1.type == capstone.x86.X86_OP_IMM:
              fbo_op = FboOp(va, to_str(ins), reg, FboOpTy.ASSIGN, (op1.imm,))
            elif op1.type == capstone.x86.X86_OP_REG:
              if op1.reg in [capstone.x86.X86_REG_ESP, capstone.x86.X86_REG_EBP]:
                reg1 = FboReg.ESP if op1.reg == capstone.x86.X86_REG_ESP else FboReg.EBP
                fbo_op = FboOp(va, to_str(ins), reg, FboOpTy.ASSIGN_REG, (reg1,))
            else:
              pass
              # print(f'{va:08X} {ins.mnemonic}\t{ins.op_str}')
              # have ponential in   mov ebp, dword ptr [esp + 0x44]
            self.fbo_ops.append(fbo_op)
      elif ins.id in [capstone.x86.X86_INS_ADD, capstone.x86.X86_INS_SUB]:
        sign = -1 if ins.id == capstone.x86.X86_INS_ADD else 1
        op: capstone.x86.X86Op = ins.operands[0]
        op1: capstone.x86.X86Op = ins.operands[1]
        if op.type == capstone.x86.X86_OP_REG:
          if op.reg in [capstone.x86.X86_REG_ESP, capstone.x86.X86_REG_EBP]:
            reg = FboReg.ESP if op.reg == capstone.x86.X86_REG_ESP else FboReg.EBP
            if op1.type == capstone.x86.X86_OP_IMM:
              self.fbo_ops.append(FboOp(va, to_str(ins), reg, FboOpTy.CHANGE, (op1.imm * sign,)))
            else:
              self.fbo_ops.append(FboOp(va, to_str(ins), reg, FboOpTy.CHANGE, (None,)))
      elif ins.id == capstone.x86.X86_INS_CALL:
        op: capstone.x86.X86Op = ins.operands[0]
        if op.type == capstone.x86.X86_OP_IMM:
          dst_va = self.image_base + op.imm
          self.fbo_ops.append(FboOp(va, to_str(ins), FboReg.ESP, FboOpTy.CALL, (dst_va,)))
          if dst_va not in self.fun_starts:
            self.fun_starts.add(dst_va)
        else:
          self.fbo_ops.append(FboOp(va, to_str(ins), FboReg.ESP, FboOpTy.CALL, (None,)))
      elif ins.id == capstone.x86.X86_INS_JMP:  # id direct jump
        op: capstone.x86.X86Op = ins.operands[0]
        if op.type == capstone.x86.X86_OP_IMM:
          dst_va = self.image_base + op.imm
          self.fbo_ops.append(FboOp(va, to_str(ins), FboReg.ESP, FboOpTy.JMP, (dst_va,)))
          self.fbo_ops.append(FboOp(dst_va, f'direct jump from {va:08X}', FboReg.ESP, FboOpTy.TAKE_FROM, (va,)))
        else:
          self.fbo_ops.append(FboOp(va, to_str(ins), FboReg.ESP, FboOpTy.JMP, (None,)))
      elif ins.id in [  # is conditional jump
        capstone.x86.X86_INS_JA, capstone.x86.X86_INS_JAE,
        capstone.x86.X86_INS_JB, capstone.x86.X86_INS_JBE,
        capstone.x86.X86_INS_JE, capstone.x86.X86_INS_JNE,
        capstone.x86.X86_INS_JS, capstone.x86.X86_INS_JNS,
        capstone.x86.X86_INS_JG, capstone.x86.X86_INS_JGE,
        capstone.x86.X86_INS_JL, capstone.x86.X86_INS_JLE,
        capstone.x86.X86_INS_JP, capstone.x86.X86_INS_JNP,
        capstone.x86.X86_INS_JO, capstone.x86.X86_INS_JNO,
        capstone.x86.X86_INS_JCXZ, capstone.x86.X86_INS_JECXZ,
      ]:
        op: capstone.x86.X86Op = ins.operands[0]
        if op.type == capstone.x86.X86_OP_IMM:
          dst_va = self.image_base + op.imm
          self.fbo_ops.append(FboOp(dst_va, f'condition jump from {va:08X}', FboReg.ESP, FboOpTy.TAKE_FROM, (va,)))
      if ins.id == capstone.x86.X86_INS_CMP:
        op: capstone.x86.X86Op = ins.operands[0]
        op1: capstone.x86.X86Op = ins.operands[1]
        if op.type == capstone.x86.X86_OP_REG and op1.type == capstone.x86.X86_OP_IMM:
          self.last_cmp_eax_val = op1.imm
      if ins.disp != 0:
        op: capstone.x86.X86Op = ins.operands[0]
        op1: capstone.x86.X86Op = ins.operands[1] if len(ins.operands) > 1 else None
        if ins.id == capstone.x86.X86_INS_JMP and op.type == capstone.x86.X86_OP_MEM and op.mem.scale == 4:
          self.jump_tables[op.mem.disp] = (True,)
        elif (ins.id == capstone.x86.X86_INS_MOVZX and
              op1.type == capstone.x86.X86_OP_MEM and
              (self.va_start <= op1.mem.disp < self.va_end) and
              op1.mem.scale in [1, 2]):
          if not self.last_cmp_eax_val:
            print(f'{va:08X} no cmp')
            sys.exit(-1)
          self.indirect_tables[op1.mem.disp] = (self.last_cmp_eax_val, op1.mem.scale)
          self.last_cmp_eax_val = None
      if self.is_data_start(next_va):
        return
    va = self.image_base + self.rva_start + self.range_offs
    if va < self.va_end:
      print(f'{va:08X} unk data')
      sys.exit(-1)
      # raise Exception()

  def process_jump_table(self):
    va_jpt_start = self.image_base + self.rva_start + self.range_offs
    jp_vals = []
    while True:
      va = self.image_base + self.rva_start + self.range_offs
      dst_va = ctypes.c_uint32.from_address(self.exe.base + self.exe.rva2raw(self.rva_start + self.range_offs)).value
      if not (self.va_start <= dst_va < self.va_end):  # end of jumptable
        if va == va_jpt_start:
          print(f"{va:08X}: invalid jpt")
          del self.jump_tables[va_jpt_start]
          return
        break
      jp_vals.append(dst_va)

      self.range_offs += 4
      va = self.image_base + self.rva_start + self.range_offs
      if self.is_data_start(va):
        break
    suff = [f'{v:08X}' for v in jp_vals]
    # print(f"{va_jpt_start:08X}-{va:08X}: jpt {suff}")

  def process_indirect_table(self, count, elem_sz):
    va_ind_start = self.image_base + self.rva_start + self.range_offs
    ind_vals = []
    for i in range(count):
      val = ctypes.c_uint8.from_address(self.exe.base + self.exe.rva2raw(self.rva_start + self.range_offs)).value
      ind_vals.append(val)
      self.range_offs += 1
    # print(f"{va_ind_start:08X}-{va_ind_start + count * elem_sz:08X}: indir {ind_vals}")

  def process(self):
    while self.range_offs < self.range_size:
      va = self.image_base + self.rva_start + self.range_offs
      if va in self.jump_tables:
        self.process_jump_table()
      elif va in self.indirect_tables:
        tup = self.indirect_tables[va]
        count, elem_sz = tup
        self.process_indirect_table(count, elem_sz)
      else:
        self.process_code()


class FboFun:

  def __init__(self, va_start, va_end, fbo_ops: list[FboOp]):
    self.va_start = va_start
    self.va_end = va_end
    self.fbo_ops: list[FboOp] = fbo_ops

  def split(self, va):  # type: (int) -> FboFun
    idx = bisect.bisect_left(self.fbo_ops, va, key=lambda op: op.va)  # find ge

    fbo_ops = self.fbo_ops
    right_fbo_ops = []
    if idx < len(self.fbo_ops):
      self.fbo_ops = fbo_ops[:idx]
      right_fbo_ops = fbo_ops[idx:]
    self.va_end = va
    return FboFun(va, self.va_end, right_fbo_ops)


def parse_map_file(flame_msvcmap_file: pathlib.Path, image_base):
  with open(flame_msvcmap_file, 'r') as f:
    map_lines = f.readlines()

  flame_map = {}
  msvc_map_line = re.compile(' \\d{4}:[\\da-f]{8}\\s+(\\S+)\\s+([\\da-f]{8}) .{3} (\\S+)')
  for line in map_lines:
    line = line.rstrip()
    m = msvc_map_line.match(line)
    if m is None:
      continue
    flame_va = int(m.group(2), 16)
    name = m.group(1)
    obj_file = m.group(3)
    if flame_va == 0:
      continue
    flame_rva = flame_va - image_base
    if flame_rva == 0:
      continue
    if not obj_file.endswith('.cpp.obj'):
      name = obj_file + ':' + name
    flame_map[flame_va] = name
  return flame_map


def main(exe_file: pathlib.Path, map_file: pathlib.Path):
  exe = my_pe.MyPe(exe_file.read_bytes())
  flame_map = parse_map_file(map_file, exe.nt.OptionalHeader.ImageBase)

  code_ranges = []
  for sec in exe.sections:
    if not sec.Characteristics & pe_types.IMAGE_SCN_CNT_CODE:
      continue
    code_ranges.append((sec.VirtualAddress, sec.VirtualAddress + sec.VirtualSize))

  ffns: list[FboFun] = []

  md = Cs(CS_ARCH_X86, CS_MODE_32)
  md.detail = True
  for rva_start, rva_end in code_ranges:
    cri = CodeRangeFinder(exe, md, rva_start, rva_end)
    cri.process()

    for exp_name, rva in exe.exports():
      if rva_start <= rva < rva_end:
        cri.fun_starts.add(exe.nt.OptionalHeader.ImageBase + rva)
    for va, name in flame_map.items():
      rva = va - exe.nt.OptionalHeader.ImageBase
      if rva_start <= rva < rva_end:
        cri.fun_starts.add(va)
    fun_starts_ = list(cri.fun_starts)
    fun_starts_.sort()

    # split ops by functions
    cri.fbo_ops.sort(key=lambda op: op.va)
    ffn = FboFun(rva_start, rva_end, cri.fbo_ops)
    for va in reversed(fun_starts_):
      ffns.append(ffn.split(va))
    ffns.append(ffn)

  for ffn in reversed(ffns):
    print()
    print(f"fun start {ffn.va_start:08X}")
    for fbo_op in ffn.fbo_ops:
      fbo_op.dump_ins()
      if fbo_op.op in [FboOpTy.FRAME_END] and fbo_op is not ffn.fbo_ops[-1]:
        print()
    print(f"fun end   {ffn.va_end:08X}")


if __name__ == '__main__':
  main(
    pathlib.Path(r'Flame-1.7.0_code.exe'),
    pathlib.Path(r'Flame-1.7.0_code.map')
  )
