import idaapi
import idc
import idautils
import pathlib


regnames = idaapi.ph_get_regnames()


def get_o_reg_name(op: idaapi.op_t):
  reg_num = op.reg
  reg_name = regnames[reg_num]
  if reg_num < 8:
    if op.dtype == idaapi.dt_dword:
      reg_name = 'e' + reg_name
    elif op.dtype == idaapi.dt_qword:
      reg_name = 'r' + reg_name
  return reg_name


def manual_sp(ins: idaapi.insn_t, esp: int):
  if ins.itype == idaapi.NN_push:
    print("%08X +4" % ins.ea)
    esp += 4
  elif ins.itype == idaapi.NN_pop:
    print("%08X -4" % ins.ea)
    esp -= 4
  elif ins.itype == idaapi.NN_add or ins.itype == idaapi.NN_sub:
    op0 = ins.ops[0]  # type: idaapi.op_t
    op1 = ins.ops[1]  # type: idaapi.op_t
    if op0.type == idaapi.o_reg and op1.type == idaapi.o_imm and regnames[op0.reg] == 'sp':
      if ins.itype == idaapi.NN_add:
        print("%08X +%d" % (ins.ea, op1.value))
        esp += op1.value
      else:
        print("%08X -%d" % (ins.ea, op1.value))
        esp -= op1.value
  elif ins.itype == idaapi.NN_pusha:
    print("%08X" % ins.ea)
    assert False
  elif ins.itype == idaapi.NN_popa:
    print("%08X" % ins.ea)
    assert False
  elif ins.itype == idaapi.NN_retn:
    print("%08X visit ret" % ins.ea)
    return None
  return esp


class StackItem:

  def __init__(self, ea, name, spd, kind, args):
    self.ea = ea  # type: int
    self.rva = ea - idaapi.get_imagebase()
    self.name = name  # type: str
    if spd < 0:
      print(f'{ea:08X} {spd:08X} neg spd')
    self.spd = spd  # type: int
    self.kind = kind  # type: str
    self.args = args  # type: list

  def calc_next_spd(self):
    if self.kind == 'ret':
      spc, = self.args
      return self.spd + spc
    if self.kind == 'sp':
      spc, side_args = self.args
      return self.spd + spc
    return self.spd


class StackCollector:

  def __init__(self):
    self.stack_items = []
    self.fun = None  # type: idaapi.func_t
    self.fun_name = None  # type: str

  def visit_ins(self, last_ins: idaapi.insn_t, ins: idaapi.insn_t, next_ins: idaapi.insn_t):
    spd = -idaapi.get_spd(self.fun, ins.ea)
    next_spd = -idaapi.get_spd(self.fun, next_ins.ea)
    if ins.itype == idaapi.NN_retn:
      # print("%08X ret %d" % (ins.ea, ins.Op1.value))
      self.stack_items.append(StackItem(ins.ea, self.fun_name, spd, 'ret', (ins.Op1.value,)))
      return
    if ins.itype == idaapi.NN_jmp:
      # print("%08X jmp %d %08X" % (ins.ea, ins.Op1.value, ins.Op1.addr))
      assert ins.Op1.addr > idaapi.get_imagebase()
      self.stack_items.append(StackItem(ins.ea, self.fun_name, spd, 'jmp', (ins.Op1.addr, '')))
      return
    if ins.itype == idaapi.NN_jmpshort:  # all jmpshort are function local
      # print("%08X jmp %d %08X (short)" % (ins.ea, ins.Op1.value, ins.Op1.addr))
      assert ins.Op1.addr > idaapi.get_imagebase()
      self.stack_items.append(StackItem(ins.ea, self.fun_name, spd, 'jmp', (ins.Op1.addr, 'sh')))
      return
    if ins.itype == idaapi.NN_jmpni:
      # print("%08X jmp %d %08X (near indirect)" % (ins.ea, ins.Op1.value, ins.Op1.addr))
      self.stack_items.append(StackItem(ins.ea, self.fun_name, spd, 'jmp', (ins.Op1.addr, 'ni')))
      return
    if spd != next_spd:
      stack_change = next_spd - spd
      # print("%08X %d" % (last_ea, spd - last_spd))
      sp_args = []
      if ins.itype == idaapi.NN_pop:
        op0 = ins.ops[0]  # type: idaapi.op_t
        if op0.type == idaapi.o_reg and regnames[op0.reg] == 'bp':
          sp_args += ['pop_bp', 0]
      elif ins.itype == idaapi.NN_mov:
        op0 = ins.ops[0]  # type: idaapi.op_t
        op1 = ins.ops[1]  # type: idaapi.op_t
        if (
            op0.type == idaapi.o_reg and regnames[op0.reg] == 'sp' and
            op1.type == idaapi.o_reg and regnames[op1.reg] == 'bp'
        ):
          sp_args += ['mov_sp_bp', 0]
      self.stack_items.append(StackItem(ins.ea, self.fun_name, spd, 'sp', (stack_change, sp_args)))
      return

    if ins.ea == self.fun.start_ea:
      self.stack_items.append(StackItem(self.fun.start_ea, self.fun_name, 0, 'sp', (0, 'head')))

  def visit_fun(self, fun: idaapi.func_t):
    self.fun = fun
    self.fun_name = idaapi.get_func_name(fun.start_ea)
    # print("%08X %s" % (fun_ea, name))


class StackWriter:

  def __init__(self, noreturn_functions):
    self.noreturn_functions = noreturn_functions

  def visit_item(self, last_si: StackItem, si: StackItem, next_si: StackItem):
    if si.name != last_si.name:
      yield f'{si.ea:08X} {si.name}'
    if si.name != next_si.name:
      if si.kind != 'ret':
        if si.ea not in self.noreturn_functions:
          if si.kind != 'jmp':
            print("%08X no ret no jmp" % (si.ea,))
            print("%08X %s" % (si.ea, si.name))
            print("%08X %s" % (next_si.ea, (next_si.ea, next_si.name, next_si.spd, next_si.kind, next_si.args)))
            assert False
    if si.kind == 'ret':
      spc, = si.args
      yield f' {si.ea:08X} {si.spd} ret {-spc}'
      return
    if si.kind == 'jmp':
      if si.name == next_si.name and si.calc_next_spd() == next_si.spd:
        return
      jmp, jt = si.args
      if jt == 'ni':
        yield f' {si.ea:08X} {si.spd} jmp 00000000 near_indirect'
      elif jt == 'sh':
        yield f' {si.ea:08X} {si.spd} jmp {jmp:08X} short'
      else:
        yield f' {si.ea:08X} {si.spd} jmp {jmp:08X}'
      return
    if si.kind == 'sp':
      spc, side_args = si.args
      if spc == 0:
        return
      if side_args:
        act, offs = side_args
        yield f' {si.ea:08X} {si.spd} sp {-spc} {act} {offs}'
      else:
        # mnem = idaapi.print_insn_mnem(si.ea)
        # op0 = idc.print_operand(si.ea, 0)
        # op1 = idc.print_operand(si.ea, 1)
        # yield f' {si.ea:08X} {-si.spd} sp {-spc} #  {mnem} {op0} {op1}'
        yield f' {si.ea:08X} {si.spd} sp {-spc}'
      return
    assert False


def collect(min_va, max_va, stack_file: pathlib.Path, noreturn_functions):
  coll = StackCollector()
  ea_visited = set()
  for fun_ea in idautils.Functions(min_va, max_va):
    fun = idaapi.get_func(fun_ea)  # type: idaapi.func_t
    assert fun.start_ea == fun_ea
    coll.visit_fun(fun)
    ins = None  # type: idaapi.insn_t
    next_ins = None  # type: idaapi.insn_t
    last_ins = None  # type: idaapi.insn_t
    for ea in idautils.FuncItems(fun_ea):
      flags = idaapi.get_flags(ea)
      if not idaapi.is_code(flags):
        continue
      if ea in ea_visited:
        continue
      ea_visited.add(ea)

      if ins is None or (next_ins is not None and next_ins.ea != ea):
        ins = idaapi.insn_t()  # type: idaapi.insn_t
        ins_size = idaapi.decode_insn(ins, ea)
        if not (0 < ins_size < 16):
          print("%08X" % ea)
          assert False
      else:
        ins = next_ins
      next_ea = ea + ins.size
      next_ins = idaapi.insn_t()  # type: idaapi.insn_t
      next_ins_size = idaapi.decode_insn(next_ins, next_ea)
      if not (0 <= next_ins_size < 16):
        print("%08X %08X" % (next_ea, next_ins_size))
        assert False

      coll.visit_ins(last_ins, ins, next_ins)
      last_ins = ins

  coll.stack_items.sort(key=lambda si: si.ea)
  with open(stack_file, "w") as f:
    f.write("## esp register delta mapping\n")
    f.write("# va name\n")
    f.write("#  va frame_base_offset type esp_delta\n")
    sw = StackWriter(noreturn_functions)
    # for ea, name, spo, kind, args in stack_items:
    last_si = StackItem(0, None, 0, 'sp', (0, 'head'))  # type: StackItem
    for i in range(len(coll.stack_items)):
      si = coll.stack_items[i]  # type: StackItem
      next_si = coll.stack_items[i + 1] if (i + 1) < len(coll.stack_items) else si  # type: StackItem
      for line in sw.visit_item(last_si, si, next_si):
        f.write(f'{line}\n')
      last_si = si


def gen():

  img_base = 0x00400000
  min_rva = 0x00001000
  # max_rva = 0x0026C000
  # min_rva = 0x0026C000
  max_rva = 0x003B3000
  min_va = img_base + min_rva
  max_va = img_base + max_rva

  file = pathlib.Path(__file__).parent.parent / 'DKII_EXE_v170.espmap'
  collect(min_va, max_va, file, noreturn_functions=[0x005AE220, 0x00636539, 0x0063CE93, 0x005258C1])


def gen2():
  min_va = 0x10001000
  max_va = 0x10017000

  file = pathlib.Path(__file__).parent.parent / 'WEANETR.espmap'
  collect(min_va, max_va, file, noreturn_functions=[0x1000E5F0])


def test():
  ea = 0x005FA8B5
  ins = idaapi.insn_t()
  ins_size = idaapi.decode_insn(ins, ea)
  print("%s" % (ins.itype == idaapi.NN_call))
  flags = idaapi.get_flags(ea + ins_size)
  print("%s" % idaapi.is_code(flags))

