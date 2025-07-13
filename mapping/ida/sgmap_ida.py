import idc
import idaapi
import idautils
import pathlib
import sgmap


def parse_cmt_props(cmt: str):
  result = {}
  if cmt is not None:
    for line in cmt.split('\n'):
      try:
        idx = line.index('=')
        key = line[:idx]
        value = line[idx+1:]
        result[key] = value
      except ValueError:
        pass
  return result


def format_windows_type(tname):
  if tname == "LPDIDEVICEOBJECTDATA_10":
    return "LPDIDEVICEOBJECTDATA"
  return tname


def is_windows_type(tname):
  if '*' in tname: return False
  if '[' in tname: return False
  if '::' in tname: return True
  starts_with = [
    'tag', 'std', 'D3D', 'DXGI', 'IDX', 'IDirect', 'enum ',
    'in_addr', 'midihdr_tag',
    'ID3D', 'DI', 'DD', 'MM', 'MCI', 'EXC', 'HMIDIOUT',
    '_RTL', '_ACT', '_TEB', '_PEB', '_EXC', '_ASS', '_FLS', '_D3D',
    '_CONTEXT', '_s_', '_SCOPE', '_EH3', '_OSVER', '_MEM',
    '_SYS', '_TIME', '_STAR', '_SEC', '_WIN', '_RTTI', '_DDSUR',
    '_EH4', '_NT_', '_GDI', '__crt', '__CT', '__time',
  ]
  for prefix in starts_with:
    if tname.startswith(prefix): return True
  tname_ = tname.rstrip('_')
  if tname_.endswith('Vtbl'):
    tname_ = tname_[:-len('Vtbl')]
  if tname_ in [
    'HRESULT', 'BOOL', 'SIZE_T', 'size_t', 'LCID', 'LUID', 'OLECHAR', 'DISPID',
    'LSTATUS', 'LRESULT', 'LPARAM', 'WPARAM', 'ULONG_PTR', 'DWORD_PTR', 'UINT_PTR',
    'CatchableTypeArray', 'hostent', 'type_info', 'EHRegistrationNode', 'EHExceptionRecord',
    'IUnknown', 'IDispatch', 'IMarshal', 'IStream', 'IServiceProvider',
    'IKsPropertySet', 'ITypeInfo', 'IClassFactory', 'TypeDescriptor', 'exception', 'bad_cast',
    'CLSID', 'CONTEXT', 'HKEY', 'HWND', 'HMENU', 'HDC', 'HICON', 'HINSTANCE', 'HBRUSH', 'HMMIO', 'VARIANT',
    'DS3DBUFFER', 'SECURITY_ATTRIBUTES', 'REGSAM', 'DEVMODEA', 'HIMC', 'HKL', 'LCTYPE', 'ATOM', 'MSG', 'IID', 'PMD',
    'CPPEH_RECORD', 'WNDCLASSEXA', 'WNDCLASSA', 'POINT', 'LARGE_INTEGER', 'SYSTEMTIME', 'FILE', 'GUID',
    'PEB_LDR_DATA', 'LDR_DATA_TABLE_ENTRY', 'tm', 'errno_t', 'intptr_t',
    'FuncInfoV1', 'UnwindMapEntry', 'RECT', 'FILETIME', 'TryBlockMapEntry',
    'HandlerType', 'WSAData', 'LPDIDEVICEOBJECTDATA_10', 'PALETTEENTRY',
    'VLCtable', 'sVLCtable', '_cpinfo', '_ThrowInfo', '_FILETIME', '_PMD', '_GUID', '_CLIENT_ID',
    '_UNICODE_STRING', '_LIST_ENTRY', '_PROCESSOR_NUMBER', '_LARGE_INTEGER',
    '_ULARGE_INTEGER', '_CURDIR', '_STRING', 'tWAVEFORMATEX', '_DSCAPS', 'DSCAPS',
    'DSBCAPS', '_DSBUFFERDESC', 'WAVEFORMATEX',
    'LPCSTR', 'CHAR', 'char', '_TBYTE', 'WCHAR', 'wchar_t',
    'DSBUFFERDESC',
  ]: return True
  return False


def is_int_type(tname):
  utname = tname
  if utname.startswith('unsigned '):
    utname = utname[len('unsigned '):]
  if utname.startswith('signed '):
    utname = utname[len('signed '):]
  starts_with = [
    '__int', 'uint', 'wint'
  ]
  for prefix in starts_with:
    if utname.startswith(prefix): return True
  if utname in [
    'byte', 'short', 'int', 'long',
    'UCHAR',
    'UINT64', 'INT64', 'UINT16', 'INT16', 'UINT8', 'INT8', 'UINT', 'INT',
    'ULONG', 'LONG', 'ULONGLONG', 'LONGLONG',
    'QWORD', 'DWORD', 'WORD', '_QWORD', '_DWORD', '_WORD',
    'USHORT', 'SHORT',
    'BYTE', '_BYTE', 'BOOL', 'size_t'
  ]: return True
  return False


class IdaStruct(sgmap.Struct):

  def __init__(self, sid, name, cmt_props: dict):
    super().__init__(name)
    self.instances = []  # type: list[IdaGlobal]
    self.ida = idaapi.get_struc(sid)  # type: idaapi.struc_t
    self.attribs = sgmap.parse_attribs(cmt_props.get('attribs', ''))

  def visit_body_field(self, field):  # type: (IdaField) -> None
    field = field  # type: IdaField
    stype = field.type  # type: sgmap.StructType
    assert stype.kind == sgmap.TypeKind.Struct
    if not stype.struct.name.endswith('_fields'):
      raise Exception([self.name, field.offset, field.size, f'{stype.struct.name}'])
    fields_name = stype.struct.name[:-len('_fields')]
    if fields_name != self.name and fields_name not in ['MyLList']:
      raise Exception([
        self.name, '!=', fields_name,
        field.offset, field.size, f'{stype.struct.name}'])
    assert len(self.fields) == 1
    self.fields = stype.struct.fields
    assert field.offset == 4

  def visit_super_field(self, structs, field, suffix, strip_suffix=True):  # type: (IdaStructs, IdaField, str, bool) -> None
    field = field  # type: IdaField
    stype = field.type  # type: sgmap.StructType
    if stype.kind != sgmap.TypeKind.Struct:
      raise Exception(f'{self.name} has super field which is not struct', list(stype.serialize_short()))
    if strip_suffix:
      super_name = stype.struct.name
      if stype.struct.name.endswith(suffix):
        super_name = super_name[:-len(suffix)]
      ssuper = structs.get_by_name(super_name)
    else:
      ssuper = stype.struct
    assert ssuper is not None
    self.super = ssuper
    self.fields = self.fields[1:]

  def visit_vtable_field(self, field):  # type: (IdaField) -> None
    field = field  # type: IdaField
    ptype = field.type  # type: sgmap.PtrType
    if ptype.kind != sgmap.TypeKind.Ptr:
      raise Exception([self.name, field.name, str(ptype), ptype.kind])
    stype = ptype.type  # type: sgmap.StructType
    if stype.kind != sgmap.TypeKind.Struct:
      # raise Exception([self.name, field.name, str(stype), stype.kind])
      pass
    assert field.size == 4
    self.fields = self.fields[1:]
    if not self.vtable:
      raise Exception(['has no vtable', self.name, field.offset, f'{stype.struct.name if stype.kind == sgmap.TypeKind.Struct else str(stype)}'])

  def get_id_instance(self):  # type: () -> IdaGlobal
    for glob in self.instances:
      cmt = idaapi.get_cmt(glob.va, False)
      # print(f"{glob.va:08X} {self.name} {glob.name} {cmt}")
      if cmt == 'use_as_id':
        return glob
    return None

  @staticmethod
  def build(sid, sname):
    if sname == '__m64':
      raise Exception()
    cmt_props = parse_cmt_props(idaapi.get_struc_cmt(sid, False))
    struct = IdaStruct(sid, sname, cmt_props)
    struct.size = idaapi.get_struc_size(struct.ida)
    if struct.ida.is_union():
      struct.is_union = True
      # print(idaapi.get_struc_name(sid))
      idx = 0
      end = 0
      for offset, fname, size in idautils.StructMembers(sid):
        if offset != idx:
          raise Exception([idaapi.get_struc_name(sid), fname, f'offs={offset}', f'size={size}'])
        # print('', [fname, f'offs={offset}', f'size={size}'])
        field = IdaField(struct, fname, offset, size)
        struct.fields.append(field)
        idx += 1
        if (offset + size) > end:
          end = offset + size
    else:
      pos = 0
      for offset, fname, size in idautils.StructMembers(sid):
        if offset < pos:
          raise Exception([idaapi.get_struc_name(sid), fname, f'offs={offset}', f'size={size}'])
        if offset > pos:
          field = IdaField(None, 'f%x_gap' % pos, pos, offset - pos)
          field.type = sgmap.ArrayType(sgmap.IntType(1), offset - pos)
          struct.fields.append(field)

        field = IdaField(struct, fname, offset, size)
        validate_vtbl_field(struct, field)
        struct.fields.append(field)
        pos = offset + size
      total_size = idaapi.get_struc_size(sid)
      assert pos <= total_size
      if pos < total_size:
        field = IdaField(None, 'f%x_gap' % pos, pos, total_size - pos)
        field.type = sgmap.ArrayType(sgmap.IntType(1), total_size - pos)
        struct.fields.append(field)
    return struct


class IdaField(sgmap.Field):

  def __init__(self, struct: IdaStruct or None, name, offset, size):
    super().__init__(name)
    self.offset = offset
    self.size = size

    self.tif = None  # type: idaapi.tinfo_t
    self.ida = None  # type: idaapi.member_t
    if struct is not None:
      self.ida = idaapi.get_member(struct.ida, self.offset)  # type: idaapi.member_t
      self.guess_type()

  def guess_type(self):
    self.tif = idaapi.tinfo_t()
    if not idaapi.get_or_guess_member_tinfo(self.tif, self.ida):
      self.tif = None
      assert self.size in [1, 2, 4]
      self.type = sgmap.IntType(self.size)


class IdaGlobal(sgmap.Global):

  def __init__(self, va, name):
    super().__init__(va, name)
    self.flags = idaapi.get_flags(va)


def is_vtable_name(name):
  return name.startswith('??_7') and name.endswith('@@6B@')


def get_name_by_vtable_name(name):
  cls_name = name[len('??_7'):-len('@@6B@')]
  cls_name = '_'.join(reversed(cls_name.split('@')))
  return cls_name


class IdaStructs:

  def __init__(self):
    self.struct_by_sid = {}  # type: dict[int, IdaStruct]
    self.vftable_map = {}  # type: dict[str, int]
    self.classes = []  # type: list[IdaStruct]
    self.path_by_name: dict[str, str] = collect_path_by_sname()

  def is_windows_type(self, tname):
    tpath = self.path_by_name.get(tname, '')
    is_win = tpath.startswith('win')
    return is_win or is_windows_type(tname)

  def collect(self):
    for (idx, sid, sname) in idautils.Structs():
      if self.is_windows_type(sname):
        tpath = self.path_by_name.get(sname, '')
        is_win = tpath.startswith('win')
        if not is_win:
          print(f'{sname} move to win')
        continue
      assert not sname.startswith('DK2:')
      struct = IdaStruct.build(sid, sname)
      struct.path = self.path_by_name.get(sname, '')
      self.struct_by_sid[sid] = struct

    # resolve field types
    for sid, struct in self.struct_by_sid.items():  # type: int, IdaStruct
      for field in struct.fields:  # type: IdaField
        if field.type is not None:
          continue
        cmt_props = parse_cmt_props(idaapi.get_member_cmt(field.ida.id, False))
        field.type = IdaTypeConvert(struct.name, field.name, self).accept(field.tif, cmt_props)

    # locate struct related globals
    for ea, name in idautils.Names():  # type: int, str
      if not is_vtable_name(name):
        continue
      cls_name = get_name_by_vtable_name(name)
      self.vftable_map[cls_name] = ea

  def parse_classes(self):
    # parse class format
    for sid, struct in self.struct_by_sid.items():  # type: int, IdaStruct
      if struct.name.endswith("_vtbl"):
        continue
      if struct.name.endswith('_fields'):
        continue
      vtbl = self.get_by_name(struct.name + '_vtbl')  # type: IdaStruct
      if vtbl is not None:
        vft_ea = self.vftable_map.get(struct.name)
        if vft_ea is None:
          print('no vftable ea:', struct.name)
          # raise Exception([struct.name, 'no vftable ea'])
          vft_ea = sgmap.BADADDR
        if vft_ea != sgmap.BADADDR:
          vtbl.id = 'instance_%08X' % vft_ea
          struct.id = 'vtbl_%08X' % vft_ea
          struct.vtable_values = [ idaapi.get_32bit(vft_ea + i * 4) for i in range(vtbl.size // 4)]
        struct.vtable = vtbl
        if len(vtbl.fields) > 0 and vtbl.fields[0].name == 'super':
          vtbl.visit_super_field(self, vtbl.fields[0], '_vtbl', False)
      if len(struct.fields) > 0 and struct.fields[0].name == '__vftable':
        struct.visit_vtable_field(struct.fields[0])
      if len(struct.fields) > 0 and struct.fields[0].name == '_':
        struct.visit_body_field(struct.fields[0])
      if len(struct.fields) > 0 and struct.fields[0].name == 'super':
        struct.visit_super_field(self, struct.fields[0], '_fields')
      self.classes.append(struct)

  def validate_super_vtable_match(self):
    for struct in self.classes:
      if struct.super is not None and struct.vtable is not None:
        if struct.vtable.super != struct.super.vtable:
          super_vtable_name = None
          super_vtable_name2 = None
          if struct.vtable.super is not None:
            super_vtable_name2 = struct.vtable.super.name
          lva = self.vftable_map[struct.vtable.name[:-len('_vtbl')]]
          rva = 0
          if struct.super.vtable is not None:
            super_vtable_name = struct.super.vtable.name
            print(super_vtable_name2, super_vtable_name)
            if super_vtable_name not in ['DxAction_vtbl']:
              rva = self.vftable_map[super_vtable_name[:-len('_vtbl')]]
              lmap = {}
              for lf in struct.vtable.fields:
                lida = lf.ida  # type: idaapi.member_t
                lmap[lida.soff] = lf

              for rf in struct.super.vtable.fields:
                rida = rf.ida  # type: idaapi.member_t
                lf = lmap.get(rida.soff, None)
                if lf is None:
                  continue
                lida = lf.ida  # type: idaapi.member_t
                print('f%X' % (lida.soff,))
                print('%-16s' % lf.name, '', lf.tif)
                if lva:
                  lea = idaapi.get_32bit(lva + lida.soff)
                  lname = idaapi.get_func_name(lea)
                  ltif = idaapi.tinfo_t()
                  if idaapi.get_tinfo(ltif, lea):
                    print('-%-15s' % lname, '', ltif)
                print('  %-14s' % rf.name, '', rf.tif)
                if rva:
                  rea = idaapi.get_32bit(rva + rida.soff)
                  rname = idaapi.get_func_name(rea)
                  rtif = idaapi.tinfo_t()
                  if idaapi.get_tinfo(rtif, rea):
                    print('  -%-13s' % rname, '', rtif)
          raise Exception([struct.name, struct.super.name],
                          [struct.vtable.name, super_vtable_name],
                          ["%08X" % lva, "%08X" % rva])

  def remove_field_structs(self):
    for struct in self.classes:
      # del struct_id_map[struct.ida.id]
      # sid = idaapi.get_struc_id(f"{struct.name}_vtbl")
      # if sid != -1 and sid != 0 and sid != idaapi.BADADDR:
      #   del struct_id_map[sid]
      sid = idaapi.get_struc_id(f"{struct.name}_fields")
      if sid != -1 and sid != 0 and sid != idaapi.BADADDR:
        del self.struct_by_sid[sid]

  def fill_missing_supers(self):
    # fill super
    for struct in self.classes:
      if struct.vtable is None:
        continue
      # case 1
      if struct.super is None and struct.vtable.super is not None:
        ssuper = self.get_by_name(struct.vtable.super.name[:-len('_vtbl')])
        assert ssuper is not None
        assert ssuper.size == 4
        struct.super = ssuper
      # case 2
      if struct.vtable.super is None and struct.super is not None:
        assert False

  def resolve_id(self, struct: IdaStruct):
    if struct.id is not None:
      return
    cmt_props = parse_cmt_props(idaapi.get_struc_cmt(struct.ida.id, False))
    struct_id = cmt_props.get('id')
    if struct_id is not None:
      struct.id = struct_id
      return
    con_ea = idaapi.get_name_ea(idaapi.BADADDR, f'{struct.name}_constructor')
    if con_ea != idaapi.BADADDR:
      struct.id = f'constructor_{con_ea:08X}'
      return
    id_inst = struct.get_id_instance()
    if id_inst is not None:
      struct.id = f'instance_{id_inst.va:08X}'
      return
    if struct.name.endswith('_vtbl'):
      vft_ea = self.vftable_map.get(struct.name[:-len('_vtbl')])
      if vft_ea is None:
        ida_struc = self.get_by_name(struct.name[:-len('_vtbl')])
        if ida_struc is None:
          raise Exception([struct.name, 'no vftable ea'])
        else:
          self.resolve_id(ida_struc)
          struct.id = f'{ida_struc.id}_vtbl'
      else:
        struct.id = 'instance_%08X' % vft_ea
      return
    raise Exception(['no id', struct.name, "%X" % self.vftable_map.get(struct.name, sgmap.BADADDR),
                     self.get_by_name(struct.name + '_vtbl'), struct.super])

  def fill_missing_ids(self):
    # ensure all structs has id
    for sid, struct in self.struct_by_sid.items():
      self.resolve_id(struct)

  def get_by_name(self, name: str) -> IdaStruct or None:
    sid = idaapi.get_struc_id(name)
    if sid != -1 and sid != 0 and sid != idaapi.BADADDR:
      struct_ = self.struct_by_sid.get(sid)
      if struct_ is None:
        raise Exception("sid %08X not found. name=%s" % (sid, name))
      assert struct_ is not None
      return struct_
    return None


class IdaTypeConvert:

  def __init__(self, struct, field, structs: IdaStructs):
    self.struct = struct
    self.field = field
    self.structs = structs

  def get_tname(self, tif: idaapi.tinfo_t):
    tname = tif.__str__()  # type: str
    if tif.is_const():
      # assert tname.startswith('const ')
      if tname.startswith('const '):
        # raise Exception(tname)
        tname = tname[len('const '):]
    elif tname.startswith('const '):
      tname = tname[len('const '):]
    if tif.is_volatile():
      assert tname.startswith('volatile ')
      tname = tname[len('volatile '):]
    elif tname.startswith('volatile '):
      tname = tname[len('volatile '):]
    if tname.startswith('struct '):
      tname = tname[len('struct '):]
    return tname

  def format_func(self, tif: idaapi.tinfo_t, cmt_props: dict = None) -> sgmap.FunctionType:
    if cmt_props is None:
      cmt_props = {}
    tname = self.get_tname(tif)  # type: str
    tfunc = idaapi.func_type_data_t()
    if not tif.get_func_details(tfunc):
      raise Exception(tname)

    cxx = sgmap.NAME_TO_CXXF[cmt_props.get("cxx")]
    # cc = tfunc.guess_cc() & idaapi.CM_CC_MASK
    cc = tfunc.cc & idaapi.CM_CC_MASK
    if cc == idaapi.CM_CC_THISCALL:
      declspec = sgmap.Declspec.Thiscall
      assert not tfunc.is_vararg_cc()
    elif cc == idaapi.CM_CC_FASTCALL:
      declspec = sgmap.Declspec.Fastcall
      assert not tfunc.is_vararg_cc()
    elif cc == idaapi.CM_CC_STDCALL:
      declspec = sgmap.Declspec.Stdcall
      assert not tfunc.is_vararg_cc()
    elif cc == idaapi.CM_CC_CDECL or cc == idaapi.CM_CC_ELLIPSIS:
      declspec = sgmap.Declspec.Cdecl
      if tfunc.is_vararg_cc():
        declspec = sgmap.Declspec.Cdecl_Varargs
    elif cc in [idaapi.CM_CC_UNKNOWN, idaapi.CM_CC_VOIDARG] and tfunc.size() == 0:
      declspec = sgmap.Declspec.Stdcall
    else:
      if '__usercall' in str(tif) or '__userpurge' in str(tif):
        return sgmap.FunctionType(
          sgmap.Declspec.Assembly,
          sgmap.PtrType(sgmap.VoidType()),
          cxx
        )
      print(f"visit unsupported function type", self.struct, self.field, tname, str(tif))
      # return sgmap.WinapiType('unsupported')
      raise Exception([
        self.struct, self.field, tname, tfunc.size(), cc, idaapi.CM_CC_UNKNOWN
      ])
    ret = self.accept(tfunc.rettype)
    fun = sgmap.FunctionType(declspec, ret, cxx)
    for i in range(tif.get_nargs()):
      arg = tif.get_nth_arg(i)  # type: idaapi.tinfo_t
      fun.args.append(self.accept(arg))
    return fun

  def try_winapi(self, tif: idaapi.tinfo_t, tname: str):
    if self.structs.is_windows_type(tname):
      # size = tif.get_size()
      # if size == idaapi.BADSIZE:
      #   size = 0
      return format_windows_type(tname)
    return None

  def try_struct(self, tif: idaapi.tinfo_t, tname: str, size: int, winapi: str):
    if not tif.is_udt():  # is_type_struni
      if tif.is_struct():
        raise Exception()
      return None
    udt = idaapi.udt_type_data_t()
    if not tif.get_udt_details(udt):
      raise Exception([
        self.struct, self.field, tname, tif.is_from_subtil(), tif.has_details()
      ])

    if winapi is not None:
      tname = tif.get_final_type_name()
      if tname == "LPDIDEVICEOBJECTDATA_10":
        tname = "DIDEVICEOBJECTDATA"
        print("replace!!")
      til = tif.get_til()
      is_union = False
      if til:
        is_union = tif.is_union()
      return sgmap.WinapiType(tname, size, is_union)
    struct_ = self.structs.get_by_name(tname)
    if struct_ is not None:
      return sgmap.StructType(struct_)

    til_name = None
    til = tif.get_til()
    if til is not None:
      til_name = til.name
    raise Exception([
      self.struct, self.field,
      tname, tif.get_size(), til_name, f'details={tif.has_details()}', tif.is_struct(),
      tif.is_sue(), tif.is_union(), tif.is_paf(), tif.is_partial(), tif.is_unknown(), tif.is_complex(),
      tif.is_enum(), tif.is_volatile(), tif.is_forward_decl()
    ])
    # print(f"visit udt type {tname}", self.struct, self.field)
    # return sgmap.WinapiType(tname, udt.total_size)

  def accept(self, tif: idaapi.tinfo_t, cmt_props: dict = None):
    if cmt_props is None:
      cmt_props = {}
    if tif.is_func():
      return self.format_func(tif, cmt_props)

    tname = self.get_tname(tif)  # type: str
    winapi = self.try_winapi(tif, tname)

    # array
    if tif.is_array():
      ai = idaapi.array_type_data_t()
      if not tif.get_array_details(ai):
        raise Exception(str(tif))
      assert winapi is None
      return sgmap.ArrayType(self.accept(ai.elem_type), ai.nelems)

    # ptr
    if tif.is_ptr():
      pi = idaapi.ptr_type_data_t()
      if not tif.get_ptr_details(pi):
        raise Exception(str(tif))
      return sgmap.PtrType(self.accept(pi.obj_type), pi.obj_type.is_const(), winapi)

    size = tif.get_size()

    # float
    if tif.is_float():
      if tname not in ['float', 'FLOAT']:
        print(f"visit float type {tname}")
      assert winapi is None
      return sgmap.FloatType(4)
    if tif.is_double():
      if tname not in ['double']:
        print(f"visit double type {tname}")
      assert winapi is None
      return sgmap.FloatType(8)
    if tif.is_floating():
      print(f"visit floating type {tname}")
      if tname == '_TBYTE':  # god damn why? _TBYTE: 10-byte  floating point (x87 extended precision 80-bit value)
        return sgmap.WinapiType(tname, size)
      size = tif.get_size()
      assert size > 0 and size != idaapi.BADSIZE
      assert winapi is None
      return sgmap.FloatType(size)

    # void
    if tif.is_void():
      assert winapi is None
      return sgmap.VoidType()
    if tname.startswith('#') and size == idaapi.BADSIZE:
      assert winapi is None
      return sgmap.VoidType()
    if tif.is_forward_decl() and size == idaapi.BADSIZE:
      # print(f"visit forward_decl type", self.struct, self.field, tname)
      # if winapi is not None:
      #   return sgmap.WinapiType(winapi, size)
      return sgmap.VoidType()

    # int
    if tif.is_bool():
      assert winapi is None
      assert tname == 'bool'
      winapi = 'bool'
    if not tif.is_struct() and not tif.is_union():
      if tname == 'CObjectUnionData':
        print(tif.is_forward_decl())
        print(size)
        raise Exception()
      assert size > 0 and size != idaapi.BADSIZE
      # is_enum = tif.is_enum()  # enums are ints
      return sgmap.IntType(size, tif.is_signed(), winapi, tif.get_final_type_name())
    assert not is_int_type(tname)

    # struct
    ty = self.try_struct(tif, tname, size, winapi)
    if ty is not None:
      return ty

    # is_signed = tif.is_signed()
    # size = tif.get_size()
    # if size in [1, 2, 4]:
    #   return f'uint{8 * size}_t'
    til_name = None
    til = tif.get_til()
    if til is not None:
      til_name = til.name
    if tif.__str__() == '':
      print([tif.is_char(), tif.is_decl_char(), tif.get_type_name()])
    raise Exception([
      self.struct, self.field,
      tname, tif.get_size(), til_name, tif.has_details(), tif.is_struct(),
      tif.is_sue(), tif.is_union(), tif.is_paf(), tif.is_partial(), tif.is_unknown(), tif.is_complex(),
      tif.is_enum(), tif.is_volatile(), tif.is_forward_decl()
    ])
# end of IdaTypeConvert

def validate_vtbl_field(struct, field):
  if not struct.name.endswith('_vtbl'):
    return
  if field.name == 'super':
    return
  tif = field.tif
  if not tif.is_ptr():
    raise Exception([struct.name, field.name, str(tif)])
  pi = idaapi.ptr_type_data_t()
  if not tif.get_ptr_details(pi):
    raise Exception([struct.name, field.name, str(tif)])
  tif = pi.obj_type
  if not tif.is_func():
    raise Exception([struct.name, field.name, str(tif)])


def collect_path_by_sname() -> dict[str, str]:
  path_by_name = {}
  dt = idaapi.get_std_dirtree(idaapi.DIRTREE_STRUCTS)  # type: idaapi.dirtree_t

  def iterate(pat):
    it = idaapi.dirtree_iterator_t()
    if dt.findfirst(it, pat + '/*'):
      relp = pat[1:]
      while True:
        cur = it.cursor  # type: idaapi.dirtree_cursor_t
        assert cur.valid()
        path = dt.get_abspath(cur)
        ent = dt.resolve_cursor(cur)  # type: idaapi.direntry_t
        if ent.isdir:
          iterate(path)
        else:
          if relp:
            name = dt.get_entry_name(ent)
            path_by_name[name] = relp
        if not dt.findnext(it):
          break

  iterate('')
  return path_by_name



class IdaCollectGlobals:

  def __init__(self):
    self.structs = IdaStructs()
    self.globals_map = {}  # type: dict[int, IdaGlobal]

  def get_global(self, ea_, type_: sgmap.Type, name_=None) -> IdaGlobal:
    glob_ = self.globals_map.get(ea_)
    if glob_ is not None:
      return glob_
    if name_ is None:
      name_ = idaapi.get_ea_name(ea_)
    glob_ = IdaGlobal(ea_, name_)
    glob_.type = type_
    self.globals_map[ea_] = glob_
    return glob_

  def get_struct_name_from_instance_name(self, name: str) -> str:
    if '_instance' in name:
      return name[:name.index('_instance')]
    if name.startswith('?instance@'):
      # assert idaapi.is_struct(flags)
      sname = name[len('?instance@'):]  # type: str
      sname = sname[:sname.index('@')]
      return sname
    if 'instance' in name:
      raise Exception([name])
    return None

  def get_glob_from_idatype(self, ea: int, name: str) -> IdaGlobal:
    tif = idaapi.tinfo_t()
    if not idaapi.get_tinfo(tif, ea):
      if idaapi.guess_tinfo(tif, ea) in [0, -1, idaapi.BADADDR]:
        return None
    cmt_props = parse_cmt_props(idaapi.get_cmt(ea, False))
    type = IdaTypeConvert("%08X" % ea, name, self.structs).accept(tif, cmt_props)
    return self.get_global(ea, type)

  def collect_instances(self, glob: IdaGlobal, name: str):
    # collect instances by type
    if glob.type.kind == sgmap.TypeKind.Struct:
      ty: sgmap.StructType = glob.type
      struct = ty.struct  # type: IdaStruct
      struct.instances.append(glob)
      return True
    # collect instance by name
    sname = self.get_struct_name_from_instance_name(name)
    if sname is not None:
      struct = self.structs.get_by_name(sname)
      if struct is not None:
        print(f'{glob.va:08X} {name} detected struct instance by name')
        struct.instances.append(glob)
      else:
        print(f'{glob.va:08X} {name} ignore potential instance is_struct={idaapi.is_struct(idaapi.get_flags(glob.va))}')
      return True
    return False

  def accept_jpt(self, ea, name):
    fun: idaapi.func_t = idaapi.get_func(ea)
    size = idaapi.get_item_size(ea)
    if fun is not None:
      fun_end: idaapi.func_t = idaapi.get_func(ea + size)
      assert fun_end and fun_end.start_ea == fun.start_ea
    if fun is None:  # if jpt in function block, then it will be bundled in function global
      assert (size % 4) == 0
      type = sgmap.ArrayType(sgmap.PtrType(sgmap.VoidType()), size // 4)
      glob = self.get_global(ea, type)

  def accept_idt(self, ea, name):
    fun: idaapi.func_t = idaapi.get_func(ea)
    size = idaapi.get_item_size(ea)
    if fun is not None:
      fun_end: idaapi.func_t = idaapi.get_func(ea + size)
      assert fun_end and fun_end.start_ea == fun.start_ea
    if fun is None:
      type = sgmap.ArrayType(sgmap.IntType(1, False), size)
      glob = self.get_global(ea, type)

  def accept(self):
    self.structs.collect()

    # locate struct related globals
    for ea, name in idautils.Names():  # type: int, str
      if 0x0066C000 <= ea < 0x0066C420:  # ignore imports
        continue
      if name.startswith('??_R0?') or name.startswith('??_R1') or name.startswith('??_R2'):  # ignore rtti
        continue
      if name.startswith('__TI2?AV') or name.startswith('__TI3?AV'):  # ignore throw info
        continue
      if is_vtable_name(name):
        continue
      flags = idaapi.get_flags(ea)
      if idaapi.is_code(flags):  # ignore functions
        continue
      if idaapi.is_strlit(flags):  # ignore strings
        # print(f"{ea:08X} skip string {name}")
        continue
      if name.startswith('jpt_'):
        self.accept_jpt(ea, name)
        continue
      if name.startswith('idt_'):
        self.accept_idt(ea, name)
        continue
      glob = self.get_glob_from_idatype(ea, name)
      if glob is not None:
        if self.collect_instances(glob, name):
          continue
      sname = self.get_struct_name_from_instance_name(name)
      if sname is not None:
        raise Exception([f"{ea:08X}", name, sname])

    self.structs.parse_classes()
    # now struct has vtable field

    # touch vtable globals
    for ea, name in idautils.Names():  # type: int, str
      if not is_vtable_name(name):
        continue
      cls_name = get_name_by_vtable_name(name)
      struct = self.structs.get_by_name(cls_name)
      if struct is None:
        print(f"{ea:08X} no struct {cls_name} from vtable")
        continue
      if struct.vtable is None:
        print(f"{ea:08X} {cls_name} maybe autobuild vtable?")
        continue
      glob = self.get_global(ea, sgmap.StructType(struct.vtable), f'{cls_name}_vftable')

    self.structs.validate_super_vtable_match()
    self.structs.remove_field_structs()
    self.structs.fill_missing_supers()

    print()
    print("* * *  collect functions  * * *")
    for ea in idautils.Functions():
      name = idaapi.get_func_name(ea)
      if name[0] == '?' or name.startswith('j_?') or name.startswith('__Cxx') or name.startswith('__thread'):
        print(f'{ea:08X} skip fun {name}')
        continue
      tif = idaapi.tinfo_t()
      # if idaapi.guess_tinfo(tif, ea) not in [0, -1, idaapi.BADADDR]:
      #   raise Exception(["%08X" % ea, name])
      if idaapi.get_tinfo(tif, ea):
        try:
          chunk = idaapi.get_fchunk(ea)  # type: idaapi.func_t
          cmt_props = parse_cmt_props(idaapi.get_func_cmt(chunk, False))
          glob = self.get_global(ea, IdaTypeConvert("%08X" % ea, name, self.structs).accept(tif, cmt_props))
          assert chunk.end_ea > chunk.start_ea
          glob.size = chunk.end_ea - chunk.start_ea
        except Exception:
          print(f"{ea:08X} failed to convert type {name}")
          raise
      else:
        print(f"{ea:08X} failed to get type {name}")

    self.structs.fill_missing_ids()
    self.collect_thiscall_members()
    self.assert_no_globals_collision()
    return self.structs.struct_by_sid, self.globals_map

  def collect_thiscall_members(self):
    # todo: move to structs
    print()
    print("* * *  collect thiscall members  * * *")

    def format_function_name(name: str) -> str:
      # ?_ValidateExecute@
      name = name.replace('::', '_')
      if name[0] == '?':
        print(name)
        name = name[1:name.index('@')]
      if name[0].isdigit():
        name = f"fun_{name}"
      return name

    def find_struct_from_name(name: str) -> sgmap.Struct:
      name = format_function_name(name)
      name = name.replace('::', '_')
      parts = name.split('_')
      for i in range(len(parts) - 1, -1, -1):  # [len-1, 0]
        cls_name = '_'.join(parts[:i + 1])
        struct = self.structs.get_by_name(cls_name)
        if struct is not None:
          return struct
        # print(f" struct {cls_name} not found")
      return None

    def find_struct_from_thiscall(fun_t: sgmap.FunctionType) -> sgmap.Struct:
      if len(fun_t.args) == 0:
        raise Exception()
      ty = fun_t.args[0]
      if ty.kind is not sgmap.TypeKind.Ptr:
        return None
      ptr_t = ty  # type: sgmap.PtrType
      ty = ptr_t.type
      if ty.kind is not sgmap.TypeKind.Struct:
        return None
      stru_t = ty  # type: sgmap.StructType
      return stru_t.struct

    def filter_thicall_function_var(glob: sgmap.Global):
      if glob.type.kind is not sgmap.TypeKind.Function:
        return False
      fun_t = glob.type  # type: sgmap.FunctionType
      return fun_t.declspec is sgmap.Declspec.Thiscall

    globals: list[sgmap.Global] = list(sorted(self.globals_map.values(), key=lambda g: g.va))
    for glob in filter(filter_thicall_function_var, globals):
      fun_t = glob.type  # type: sgmap.FunctionType
      assert fun_t.declspec is sgmap.Declspec.Thiscall
      s_by_type = find_struct_from_thiscall(fun_t)
      s_by_name = find_struct_from_name(glob.name)
      if s_by_name is None and s_by_type is None:
        # print(f"{glob.va:08X} skip thiscall fun {glob.name}  struct not found")
        continue
      if (
          s_by_name is not None and
          s_by_type is not None and
          s_by_name is not s_by_type
      ):
        print(f"{glob.va:08X} skip thiscall fun {glob.name}  {s_by_name.name} != {s_by_type.name}")
        continue
      if s_by_name is None and s_by_type is not None:
        if not glob.name.startswith('optimized'):
          print(f"{glob.va:08X} * todo: thiscall fun {glob.name}  has no prefix {s_by_type.name}")
        continue
      struct = s_by_type if s_by_type is not None else s_by_name
      struct.functions.append(glob)
      # patch glob name as it is member now
      name = glob.name.replace('::', '_')
      if name.startswith(f"{struct.name}_"):
        glob.name = format_function_name(name[len(struct.name) + 1:])

  def assert_no_globals_collision(self):
    ovs = 0
    last = None
    for glob in sorted(self.globals_map.values(), key=lambda g: g.va):
      if last is not None:
        if glob.va < (last.va + last.size):
          print(f'{glob.va:08X} < {last.va:08X}-{last.va + last.size:08X} overlap')
          ovs += 1
          # raise Exception()
      size = None
      if glob.type.kind is sgmap.TypeKind.Function:
        assert glob.size is not None
        size = glob.size
      else:
        try:
          size = glob.type.get_size()
          glob.size = size
        except Exception:
          print(f'{glob.va:08X} cant get size {glob.type.kind}')
          continue
      last = glob
    if ovs != 0:
      raise Exception('overlap detected')


def gen():
  struct_id_map, globals_map = IdaCollectGlobals().accept()  # type: dict[int, IdaStruct], dict[int, IdaGlobal]
  file = pathlib.Path(__file__).parent.parent / 'DKII_EXE_v170.sgmap'
  with open(file, 'w') as f:
    f.write("## structures and globals mapping\n")
    f.write("# struct: <short properties>\n")
    f.write("#  <complex properties>\n")
    f.write("# global: <short properties>\n")
    f.write("#  type: <short properties>\n")
    f.write("#   [complex properties]\n")
    for line in sgmap.serialize_structs(struct_id_map.values()):
      f.write(line + "\n")
    for line in sgmap.serialize_globals(struct_id_map.values(), globals_map.values()):
      f.write(line + "\n")
  print(f'struct_id_map={len(struct_id_map)} globals_map={len(globals_map)}')


def test():
  tif = idaapi.tinfo_t()
  idaapi.get_tinfo(tif, 0x556650)
  tfunc = idaapi.func_type_data_t()
  tif.get_func_details(tfunc)

  # arg = tif.get_nth_arg(0)
  # pi = idaapi.ptr_type_data_t()
  # arg.get_ptr_details(pi)
  # trg = pi.obj_type

  ret = tif.get_rettype()
  return ret

