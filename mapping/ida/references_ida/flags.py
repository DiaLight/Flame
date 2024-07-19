import idaapi
import enum


class Flags(enum.Enum):

  TRACE = 1
  MANUAL = 2
  STATIC_A = 4

  @staticmethod
  def parse(val):
    flags = []
    for ch in val:
      if ch == 'T':
        flags.append(Flags.TRACE)
      elif ch == 'M':
        flags.append(Flags.MANUAL)
      elif ch == 'S':
        flags.append(Flags.STATIC_A)
    return flags

  @staticmethod
  def format(val):
    return '%s%s%s' % (
      'T' if Flags.TRACE in val else '-',
      'M' if Flags.MANUAL in val else '-',
      'S' if Flags.STATIC_A in val else '-',
    )

flags_desc = [
  ('MS_CLS', 'Mask for typing'),
  ('FF_CODE', 'Code'),
  ('FF_DATA', 'Data'),
  ('FF_TAIL', 'Tail'),
  ('FF_UNK', 'Unknown'),

  ('MS_COMM', 'Mask of common bits'),
  ('FF_COMM', 'Has comment'),
  ('FF_REF', 'has references'),
  ('FF_LINE', 'Has next or prev lines'),
  ('FF_NAME', 'Has name'),
  ('FF_LABL', 'Has dummy name'),
  ('FF_FLOW', 'Exec flow from prev instruction'),
  ('FF_SIGN', 'Inverted sign of operands'),
  ('FF_BNOT', 'Bitwise negation of operands'),
  ('FF_UNUSED', 'unused bit (was used for variable bytes)'),

  ('MS_0TYPE', 'Mask for 1st arg typing'),
  ('FF_0VOID', 'Void (unknown)?'),
  ('FF_0NUMH', 'Hexadecimal number?'),
  ('FF_0NUMD', 'Decimal number?'),
  ('FF_0CHAR', 'Char (\'x\')?'),
  ('FF_0SEG', 'Segment?'),
  ('FF_0OFF', 'Offset?'),
  ('FF_0NUMB', 'Binary number?'),
  ('FF_0NUMO', 'Octal number?'),
  ('FF_0ENUM', 'Enumeration?'),
  ('FF_0FOP', 'Forced operand?'),
  ('FF_0STRO', 'Struct offset?'),
  ('FF_0STK', 'Stack variable?'),
  ('FF_0FLT', 'Floating point number?'),
  ('FF_0CUST', 'Custom representation?'),

  ('MS_1TYPE', 'Mask for the type of other operands'),
  ('FF_1VOID', 'Void (unknown)?'),
  ('FF_1NUMH', 'Hexadecimal number?'),
  ('FF_1NUMD', 'Decimal number?'),
  ('FF_1CHAR', 'Char (\'x\')?'),
  ('FF_1SEG', 'Segment?'),
  ('FF_1OFF', 'Offset?'),
  ('FF_1NUMB', 'Binary number?'),
  ('FF_1NUMO', 'Octal number?'),
  ('FF_1ENUM', 'Enumeration?'),
  ('FF_1FOP', 'Forced operand?'),
  ('FF_1STRO', 'Struct offset?'),
  ('FF_1STK', 'Stack variable?'),
  ('FF_1FLT', 'Floating point number?'),
  ('FF_1CUST', 'Custom representation?'),

  ('DT_TYPE', 'Mask for DATA typing'),
  ('FF_BYTE', 'byte'),
  ('FF_WORD', 'word'),
  ('FF_DWORD', 'double word'),
  ('FF_QWORD', 'quadro word'),
  ('FF_TBYTE', 'tbyte'),
  ('FF_STRLIT', 'string literal'),
  ('FF_STRUCT', 'struct variable'),
  ('FF_OWORD', 'octaword/xmm word (16 bytes/128 bits)'),
  ('FF_FLOAT', 'float'),
  ('FF_DOUBLE', 'double'),
  ('FF_PACKREAL', 'packed decimal real'),
  ('FF_ALIGN', 'alignment directive'),
  ('FF_CUSTOM', 'custom data type'),
  ('FF_YWORD', 'ymm word (32 bytes/256 bits)'),
  ('FF_ZWORD', 'zmm word (64 bytes/512 bits)'),

  ('MS_CODE', 'Mask for code bits'),
  ('FF_FUNC', 'function start'),
  ('FF_IMMD', 'Has Immediate value'),
  ('FF_JUMP', 'Has jump table or switch_info'),
]

all_flags = []
for name, desc in flags_desc:
  val = getattr(idaapi, name)
  all_flags.append((val, name, desc))

def get_desc(flags):
  out = []
  for val, name, desc in all_flags:
    if not name.startswith('FF'):
      continue
    if (flags & val) != 0:
      out.append(desc)
  return out

def get_name(flags):
  out = []
  for val, name, desc in all_flags:
    if not name.startswith('FF'):
      continue
    if (flags & val) != 0:
      out.append(name)
  return out

def dump():
  for val, name, desc in all_flags:
    if val < 0:
      print("%s = -0x%08X  # %s" % (name, -val, desc))
    else:
      print("%s = 0x%08X  # %s" % (name, val, desc))


MS_CLS   = 0x00000600
FF_CODE  = 0x00000600
FF_DATA  = 0x00000400
FF_TAIL  = 0x00000200
FF_UNK   = 0x00000000
MS_COMM  = 0x000FF800
FF_COMM  = 0x00000800
FF_REF   = 0x00001000
FF_LINE  = 0x00002000
FF_NAME  = 0x00004000
FF_LABL  = 0x00008000
FF_FLOW  = 0x00010000
MS_0TYPE = 0x00F00000
FF_0VOID = 0x00000000  # Void (unknown)?
FF_0NUMH = 0x00100000  # Hexadecimal number?
FF_0NUMD = 0x00200000  # Decimal number?
FF_0CHAR = 0x00300000  # Char ('x')?
FF_0SEG  = 0x00400000  # Segment?
FF_0OFF  = 0x00500000  # Offset?
FF_0NUMB = 0x00600000  # Binary number?
FF_0NUMO = 0x00700000  # Octal number?
FF_0ENUM = 0x00800000  # Enumeration?
FF_0FOP  = 0x00900000  # Forced operand?
FF_0STRO = 0x00A00000  # Struct offset?
FF_0STK  = 0x00B00000  # Stack variable?
MS_1TYPE = 0x0F000000
FF_1VOID = 0x00000000
FF_1NUMH = 0x01000000
FF_1NUMD = 0x02000000
FF_1CHAR = 0x03000000
FF_1SEG  = 0x04000000
FF_1OFF  = 0x05000000
FF_1NUMB = 0x06000000
FF_1NUMO = 0x07000000
FF_1ENUM = 0x08000000
FF_1FOP  = 0x09000000
FF_1STRO = 0x0A000000
FF_1STK  = 0x0B000000
DT_TYPE = -0x10000000
FF_BYTE  = 0x00000000
FF_WORD  = 0x10000000
FF_DWORD = 0x20000000
FF_QWORD = 0x30000000
FF_TBYTE = 0x40000000
FF_STRLIT = 0x50000000
FF_STRUCT = 0x60000000
FF_OWORD  = 0x70000000
FF_FLOAT  = -0x80000000
FF_DOUBLE = -0x70000000
FF_PACKREAL = -0x60000000
FF_ALIGN = -0x50000000
MS_CODE   = 0xF0000000
FF_FUNC   = 0x10000000
FF_IMMD   = 0x40000000
FF_JUMP   = 0x80000000
