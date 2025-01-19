import sgmap


def format_declspec(decl: sgmap.Declspec):
  if decl is sgmap.Declspec.Cdecl:
    return "__cdecl"
  if decl is sgmap.Declspec.Cdecl_Varargs:
    return "__cdecl"
  if decl is sgmap.Declspec.Assembly:
    return "__cdecl"
  if decl is sgmap.Declspec.Stdcall:
    return "__stdcall"
  if decl is sgmap.Declspec.Fastcall:
    return "__fastcall"
  if decl is sgmap.Declspec.Thiscall:
    return "__thiscall"
  raise Exception()


def format_type(ty: sgmap.Type, name: str = None, is_ptr=False, is_const=False):
  if ty.kind is sgmap.TypeKind.Int:
    int_t = ty  # type: sgmap.IntType
    prefix = 'const ' if is_const and is_ptr else ''
    if int_t.winapi is not None:
      suffix = f" {name}" if name else ''
      return f"{prefix}{int_t.winapi}{suffix}"
    suffix = f" {name}" if name else ''
    if int_t.size == 4 and int_t.signed:
      return f"{prefix}int{suffix}"
    u = "" if int_t.signed else "u"
    return f"{prefix}{u}int{int_t.size * 8}_t{suffix}"
  if ty.kind is sgmap.TypeKind.Ptr:
    ptr_t = ty  # type: sgmap.PtrType
    if ptr_t.winapi is not None:
      suffix = f" {name}" if name else ''
      return f"{ptr_t.winapi}{suffix}"
    name = f'*{name}' if name else '*'
    prefix = 'const ' if is_const and not is_ptr else ''
    return f"{prefix}{format_type(ptr_t.type, name, True, ptr_t.is_const)}"
  if ty.kind is sgmap.TypeKind.Float:
    flt_t = ty  # type: sgmap.FloatType
    if flt_t.size == 4:
      prefix = 'const ' if is_const and is_ptr else ''
      suffix = f" {name}" if name else ''
      return f"{prefix}float{suffix}"
    if flt_t.size == 8:
      prefix = 'const ' if is_const and is_ptr else ''
      suffix = f" {name}" if name else ''
      return f"{prefix}double{suffix}"
    raise Exception()
  if ty.kind is sgmap.TypeKind.Void:
    prefix = 'const ' if is_const and is_ptr else ''
    suffix = f" {name}" if name else ''
    return f"{prefix}void{suffix}"
  if ty.kind is sgmap.TypeKind.Winapi:
    win_t = ty  # type: sgmap.WinapiType
    suffix = f" {name}" if name else ''
    return f"{win_t.name}{suffix}"
  if ty.kind is sgmap.TypeKind.Struct:
    stru_t = ty  # type: sgmap.StructType
    suffix = f" {name}" if name else ''
    struct_name = stru_t.struct.name
    if struct_name == 'MLDPlay':  # hardcode
      struct_name = 'net::MLDPlay'
    if struct_name == 'net_LocalService':  # hardcode
      struct_name = 'net::MyLocalService'
    return f"{struct_name}{suffix}"
  if ty.kind is sgmap.TypeKind.Function:
    fun_t = ty  # type: sgmap.FunctionType
    args = [format_type(arg) for arg in fun_t.args]
    if fun_t.declspec == sgmap.Declspec.Cdecl_Varargs:
      args.append('...')
    assert is_ptr
    assert name
    # prefix = 'const ' if is_const and is_ptr else ''
    return f"{format_type(fun_t.ret)} ({format_declspec(fun_t.declspec)} {name})({', '.join(args)})"
  if ty.kind is sgmap.TypeKind.Array:
    arr_t = ty  # type: sgmap.ArrayType
    prefix = 'const ' if is_const and is_ptr else ''
    suffix = f"{name}" if name else ''
    return f"{prefix}{format_type(arr_t.type, f'{suffix}[{arr_t.count}]')}"
  raise Exception()


def format_function(ty: sgmap.FunctionType, name: str = None):
  args = [format_type(arg) for arg in ty.args]
  if ty.declspec == sgmap.Declspec.Cdecl_Varargs:
    args.append('...')
  if ty.declspec == sgmap.Declspec.Thiscall:
    args = args[1:]
  elif ty.declspec in [
    sgmap.Declspec.Stdcall, sgmap.Declspec.Cdecl,
    sgmap.Declspec.Cdecl_Varargs, sgmap.Declspec.Fastcall,
    sgmap.Declspec.Assembly
  ]:
    pass
  else:
    raise Exception([name, ty.declspec])
  if ty.declspec not in [sgmap.Declspec.Stdcall, sgmap.Declspec.Thiscall]:
    name = f"{format_declspec(ty.declspec)} {name}"
  return f"{format_type(ty.ret, name)}({', '.join(args)})"


def format_function_name(name: str) -> str:
  # ?_ValidateExecute@
  name = name.replace('::', '_')
  if name[0] == '?':
    print(name)
    name = name[1:name.index('@')]
  if name[0].isdigit():
    raise Exception(name)
  return name


def filter_thicall_function_var(glob: sgmap.Global):
  if glob.type.kind is not sgmap.TypeKind.Function:
    return False
  fun_t = glob.type  # type: sgmap.FunctionType
  return fun_t.declspec is sgmap.Declspec.Thiscall
