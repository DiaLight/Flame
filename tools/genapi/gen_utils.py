import re
import sgmap

AUTO_OFFS = 60
empty_line = "// " + "-" * (AUTO_OFFS - 5)


def camel_to_snake(name):
  name = re.sub('(.)([A-Z][a-z]+)', r'\1_\2', name)
  return re.sub('([a-z0-9])([A-Z])', r'\1_\2', name).lower()


def format_autogen_line(line):
  has_comment = "//" in line
  gap_size = max((AUTO_OFFS - 2) - len(line), 0)
  if has_comment:
    if gap_size > 2:
      gap_size -= 2
      gap = "  " + ("-" * gap_size)
    else:
      gap = " " * gap_size
  else:
    if gap_size > 5:
      gap_size -= 5
      gap = "  // " + ("-" * gap_size)
    else:
      gap = " " * gap_size
  return line + gap + "  /* auto */"


def format_mark_line(mark):
  gap_size = max((AUTO_OFFS - 3 - 2 - 2 - 2) - len(mark), 0)
  prefix_gap = "-" * 15
  suffix_gap = "-" * (gap_size - len(prefix_gap))
  return "// " + prefix_gap + "  " + mark + "  " + suffix_gap + "  /* auto */"


def format_middle(mark):
  gap_size = max((AUTO_OFFS - 3 - 2 - 2 - 2) - len(mark), 0)
  prefix_gap = "-" * (gap_size // 2)
  suffix_gap = "-" * (gap_size - len(prefix_gap))
  return "// " + prefix_gap + "  " + mark + "  " + suffix_gap


def format_middle_line(mark):
  return format_middle(mark) + "  /* auto */"


def format_id_line(id_):
  return format_middle_line("id: " + id_)


def collect_types(ty: sgmap.Type, complete_types: set, ref_types, is_ptr=False):
  if ty.kind is sgmap.TypeKind.Ptr:
    ptr_t = ty  # type: sgmap.PtrType
    collect_types(ptr_t.type, complete_types, ref_types, True)
    return
  if ty.kind is sgmap.TypeKind.Winapi:
    win_t = ty  # type: sgmap.WinapiType
    if is_ptr and win_t.name in [
      'MLDPlay'
    ]:
      ref_types.add(win_t.name)
    return
  if ty.kind is sgmap.TypeKind.Struct:
    stru_t = ty  # type: sgmap.StructType
    if is_ptr:
      ref_types.add(stru_t.struct.name)
    else:
      complete_types.add(stru_t.struct)
    return
  if ty.kind is sgmap.TypeKind.Function:
    fun_t = ty  # type: sgmap.FunctionType
    collect_types(fun_t.ret, complete_types, ref_types, False)
    for arg in fun_t.args:
      collect_types(arg, complete_types, ref_types, False)
    return
  if ty.kind is sgmap.TypeKind.Array:
    arr_t = ty  # type: sgmap.ArrayType
    collect_types(arr_t.type, complete_types, ref_types, False)
    return


def try_get_clean_name(field: sgmap.Field, offs: int, used_names: set):
  name = field.name
  if name == f"field_{offs:X}":
    return f"f{offs:X}"
  used_names.add(name)
  prefix = f"f{offs:X}_"
  if not name.startswith(prefix):
    return field.name
  if len(name) == len(prefix):
    return field.name
  name = name[len(prefix):]
  if name[0].isdigit():
    name = '_' + name
  if name in ['gap', 'obj']:
    name = f"{name}_{offs:X}"
  elif name in used_names:
    name = f"{name}_{offs:X}"
  used_names.add(name)
  return name


def filter_function_var(glob: sgmap.Global):
  if glob.type.kind is not sgmap.TypeKind.Function:
    return False
  fun_t = glob.type  # type: sgmap.FunctionType
  return fun_t.declspec is not sgmap.Declspec.Thiscall


def is_vtable(glob: sgmap.Global):
  if glob.type.kind is sgmap.TypeKind.Struct:
    stru_t = glob.type  # type: sgmap.StructType
    if stru_t.struct.name.endswith('_vtbl'):
      return True
  return False


def filter_global_var(glob: sgmap.Global):
  if glob.type.kind is sgmap.TypeKind.Function:
    return False
  return True


def build_struct_path(struct: sgmap.Struct, ext: str) -> str:
  if struct.path is None:
    return f'dk2/{struct.name}.{ext}'
  return f'{struct.path}/{struct.name}.{ext}'

