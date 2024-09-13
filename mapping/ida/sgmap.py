import typing
from enum import Enum, auto

BADADDR = 0xFFFFFFFF


class TypeKind(Enum):
  Void = auto()
  Ptr = auto()
  Int = auto()
  Float = auto()
  Struct = auto()
  Function = auto()
  Array = auto()
  Winapi = auto()

  def __str__(self):
    return self.name.lower()


class LineIter:

  def __init__(self, it):
    self.it = it
    self.use_last = False
    self.line_num = 0

  def __iter__(self):
    return self

  def __next__(self):
    if not self.use_last:
      self.line = next(self.it)
    else:
      self.use_last = False
    self.line_num += 1
    return self.line


class ScopeLineIter:

  def __init__(self, it: LineIter, level=0):
    self.it = it
    self.level = level
    self.line = None  # type: str
    self.start_line_num = it.line_num

  @property
  def line_num(self):
    return self.it.line_num

  def __iter__(self):
    return self

  def __next__(self):
    try:
      self.line = next(self.it)
    except StopIteration:
      return None
    if not self.line.startswith("  " * self.level):
      self.it.use_last = True
      # print(f"catch end of scope lvl={self.level},line={self.it.line_num}")
      return None
    return self.line[len("  ") * self.level:]

  def __enter__(self):
    return ScopeLineIter(self.it, self.level + 1)

  def __exit__(self, exc_type, exc_val, exc_tb):
    if exc_type == StopIteration:
      self.use_last = True
      return True


def format_winapi(winapi):
  if winapi is not None:
    yield f"winapi={winapi}"


class Type:
  kind = None  # type: TypeKind

  def __init__(self):
    pass

  def serialize(self):
    yield f"{','.join(self.serialize_short())}"
    for line in self.serialize_detail():
      yield "  " + line

  def serialize_short(self):
    yield f"kind={self.kind}"

  def serialize_detail(self):
    return
    yield

  def deserialize(self, it: ScopeLineIter, short_props: typing.Dict[str, str]):
    raise Exception("unimplemented")

  @classmethod
  def create(cls, short_props: typing.Dict[str, str]):
    raise Exception("unimplemented")

  def link(self, structs_map):
    pass

  def get_size(self):
    raise Exception("unimplemented")


class VoidType(Type):
  kind = TypeKind.Void

  def __init__(self):
    super().__init__()

  def deserialize(self, it: ScopeLineIter, short_props: typing.Dict[str, str]):
    pass

  @classmethod
  def create(cls, short_props: typing.Dict[str, str]):
    return cls()


class PtrType(Type):
  kind = TypeKind.Ptr

  def __init__(self, type_, is_const=False, winapi=None):
    super().__init__()
    self.type = type_  # type: Type
    self.is_const = is_const
    self.winapi = winapi

  def serialize_short(self):
    yield from super().serialize_short()
    if self.is_const:
      yield f"is_const={self.is_const}"
    yield from format_winapi(self.winapi)


  def serialize_detail(self):
    yield from super().serialize_detail()
    yield f"type: {','.join(self.type.serialize_short())}"
    for line in self.type.serialize_detail():
      yield "  " + line

  def deserialize(self, it: ScopeLineIter, short_props: typing.Dict[str, str]):
    self.is_const = short_props.get("is_const", "False").lower() == 'true'
    self.winapi = short_props.get("winapi")
    while True:
      key, short_props = _parse_short(next(it))
      if key is None:
        break
      if key == "type":
        cls = NAME_TO_TYPE.get(short_props["kind"])
        ty = cls.create(short_props)
        with it as subit:
          ty.deserialize(subit, short_props)
        self.type = ty
      else:
        raise Exception(f"invalid {key} at {it.line_num}")

  @classmethod
  def create(cls, short_props: typing.Dict[str, str]):
    return cls(None)

  def link(self, structs_map):
    self.type.link(structs_map)

  def get_size(self):
    return 4


class IntType(Type):
  kind = TypeKind.Int

  def __init__(self, size: int, signed=False, winapi=None, fname=None):
    super().__init__()
    self.size = size  # type: int
    self.signed = signed  # type: bool
    self.winapi = winapi
    self.fname = fname

  def serialize_short(self):
    yield from super().serialize_short()
    yield f"size={self.size}"
    if self.signed:
      yield f"signed={self.signed}"
    yield from format_winapi(self.winapi)
    if self.fname is not None:
      yield f"fname={self.fname}"

  def deserialize(self, it: ScopeLineIter, short_props: typing.Dict[str, str]):
    self.size = int(short_props["size"])
    self.signed = short_props.get("signed", "False").lower() == 'true'
    self.winapi = short_props.get("winapi")
    self.fname = short_props.get("fname")

  @classmethod
  def create(cls, short_props: typing.Dict[str, str]):
    return cls(0)

  def get_size(self):
    return self.size


class FloatType(Type):
  kind = TypeKind.Float

  def __init__(self, size):
    super().__init__()
    self.size = size  # type: bool

  def serialize_short(self):
    yield from super().serialize_short()
    yield f"size={self.size}"

  def deserialize(self, it: ScopeLineIter, short_props: typing.Dict[str, str]):
    self.size = int(short_props["size"])

  @classmethod
  def create(cls, short_props: typing.Dict[str, str]):
    return cls(0)

  def get_size(self):
    return self.size


class StructType(Type):
  kind = TypeKind.Struct

  def __init__(self, struct):
    super().__init__()
    self.struct = struct  # type: Struct
    self._struct_id = None

  def serialize_short(self):
    yield from super().serialize_short()
    yield f"id={self.struct.id}"

  def deserialize(self, it: ScopeLineIter, short_props: typing.Dict[str, str]):
    self._struct_id = short_props["id"]

  @classmethod
  def create(cls, short_props: typing.Dict[str, str]):
    return cls(None)

  def link(self, structs_map):
    self.struct = structs_map[self._struct_id]

  def get_size(self):
    if self.struct.size is None:
      self.struct.size = self.struct.calc_fields_size()
    return self.struct.size


class Declspec(Enum):
  Stdcall = auto()
  Cdecl = auto()
  Cdecl_Varargs = auto()
  Fastcall = auto()
  Thiscall = auto()
  Assembly = auto()

  def __str__(self):
    return self.name.lower()


NAME_TO_DECLSPEC = {str(decl): decl for decl in Declspec}


class FunctionType(Type):
  kind = TypeKind.Function

  def __init__(self, declspec, ret):
    super().__init__()
    self.declspec = declspec  # type: Declspec
    self.ret = ret  # type: Type
    self.args = []  # type: list[Type]

  def serialize_short(self):
    yield from super().serialize_short()
    yield f"declspec={self.declspec}"

  def serialize_detail(self):
    yield from super().serialize_detail()
    yield f"ret: {','.join(self.ret.serialize_short())}"
    for line in self.ret.serialize_detail():
      yield "  " + line
    if self.args:
      for arg in self.args:
        yield f"arg: {','.join(arg.serialize_short())}"
        for line in arg.serialize_detail():
          yield "  " + line

  def deserialize(self, it: ScopeLineIter, short_props: typing.Dict[str, str]):
    self.declspec = NAME_TO_DECLSPEC[short_props["declspec"]]
    while True:
      key, short_props = _parse_short(next(it))
      if key is None:
        break
      if key == "ret":
        cls = NAME_TO_TYPE.get(short_props["kind"])
        ty = cls.create(short_props)
        with it as subit:
          ty.deserialize(subit, short_props)
        self.ret = ty
      elif key == "arg":
        cls = NAME_TO_TYPE.get(short_props["kind"])
        ty = cls.create(short_props)
        with it as subit:
          ty.deserialize(subit, short_props)
        self.args.append(ty)
      else:
        raise Exception(f"invalid {key} at {it.line_num}")

  @classmethod
  def create(cls, short_props: typing.Dict[str, str]):
    return cls(None, None)

  def link(self, structs_map):
    self.ret.link(structs_map)
    for arg in self.args:
      arg.link(structs_map)


class ArrayType(Type):
  kind = TypeKind.Array

  def __init__(self, type_: Type, count: int):
    super().__init__()
    self.type = type_  # type: Type
    self.count = count  # type: int

  def serialize_short(self):
    yield from super().serialize_short()
    yield f"count={self.count}"

  def serialize_detail(self):
    yield from super().serialize_detail()
    yield f"type: {','.join(self.type.serialize_short())}"
    for line in self.type.serialize_detail():
      yield "  " + line

  def deserialize(self, it: ScopeLineIter, short_props: typing.Dict[str, str]):
    self.count = int(short_props["count"])
    while True:
      key, short_props = _parse_short(next(it))
      if key is None:
        break
      if key == "type":
        cls = NAME_TO_TYPE.get(short_props["kind"])
        ty = cls.create(short_props)
        with it as subit:
          ty.deserialize(subit, short_props)
        self.type = ty
      else:
        raise Exception(f"invalid {key} at {it.line_num}")

  @classmethod
  def create(cls, short_props: typing.Dict[str, str]):
    return cls(None, 0)

  def link(self, structs_map):
    self.type.link(structs_map)

  def get_size(self):
    return self.type.get_size() * self.count


class WinapiType(Type):
  kind = TypeKind.Winapi

  def __init__(self, name: str, size: int = None, is_union: bool = False):
    super().__init__()
    self.name = name  # type: str
    self.size = size  # type: int
    self.is_union = is_union

  def serialize_short(self):
    yield from super().serialize_short()
    yield f"name={self.name}"
    if self.size is not None:
      yield f"size={self.size}"
    if self.is_union:
      yield f"is_union={self.is_union}"

  def deserialize(self, it: ScopeLineIter, short_props: typing.Dict[str, str]):
    self.name = short_props["name"]
    size_str = short_props.get("size", None)
    if size_str is not None:
      self.size = int(size_str)
    self.is_union = short_props.get("is_union", "False").lower() == 'true'

  @classmethod
  def create(cls, short_props: typing.Dict[str, str]):
    return cls(None, 0)

  def get_size(self):
    return self.size


ALL_TYPES = [
  VoidType, PtrType,
  IntType, FloatType, StructType,
  FunctionType, ArrayType, WinapiType
]

NAME_TO_TYPE = {str(ty.kind): ty for ty in ALL_TYPES}


def parse_type(it: ScopeLineIter, short_props: typing.Dict[str, str]):
  cls = NAME_TO_TYPE.get(short_props["kind"])
  ty = cls.create(short_props)
  with it as subit:
    ty.deserialize(subit, short_props)
  return ty


class Field:

  def __init__(self, name):
    self.name = name  # type: str
    self.type = None  # type: Type

  def serialize(self):
    yield f"{','.join(self.serialize_short())}"
    for line in self.serialize_detail():
      yield "  " + line

  def serialize_short(self):
    yield f"name={self.name}"

  def serialize_detail(self):
    yield f"type: {','.join(self.type.serialize_short())}"
    for line in self.type.serialize_detail():
      yield "  " + line

  def deserialize(self, it: ScopeLineIter, short_props: typing.Dict[str, str]):
    self.name = short_props["name"]
    while True:
      key, short_props = _parse_short(next(it))
      if key is None:
        break
      if key == "type":
        self.type = parse_type(it, short_props)
      else:
        raise Exception(f"invalid {key} at {it.line_num}")


class Struct:

  def __init__(self, name):
    self.id = None  # type: str
    self.path = None  # type: str
    self.name = name  # type: str
    self.vtable = None  # type: Struct
    self.vtable_values = []  # type: list[int]
    self.fields = []  # type: list[Field]
    self.functions = []  # type: list[Global]
    self.size = None  # type: int
    self.super = None  # type: Struct
    self.is_union = False
    self._vtable_id = None
    self._super_id = None
    self._linked = False

  def calc_fields_offs(self):
    offs = 0
    if self.vtable:
      offs += 4
    if self.super:
      if self.super.vtable is not None:
        offs += self.super.size - 4
      else:
        offs += self.super.size
    return offs

  def calc_fields_size(self):
    size = 0
    for field in self.fields:
      size += field.type.get_size()
    return size

  def serialize(self):
    yield f"{','.join(self.serialize_short())}"
    for line in self.serialize_detail():
      yield "  " + line

  def serialize_short(self):
    yield f"id={self.id}"
    if self.path:
      yield f"path={self.path}"
    yield f"name={self.name}"
    yield f"size={self.size}"
    if self.is_union:
      yield f"is_union={self.is_union}"
    if self.vtable is not None:
      yield f"vtable={self.vtable.id}"
    if self.super is not None:
      yield f"super={self.super.id}"

  def serialize_detail(self):
    if self.fields:
      for field in self.fields:
        yield f"field: {','.join(field.serialize_short())}"
        for line in field.serialize_detail():
          yield "  " + line
    for va in self.vtable_values:
      yield f"vtable_value: va={va:08X}"

  def deserialize(self, it: ScopeLineIter, short_props: typing.Dict[str, str]):
    self.id = short_props["id"]
    self.path = short_props.get("path", None)
    self.name = short_props["name"]
    self.size = int(short_props["size"])
    self.is_union = short_props.get("is_union", "False").lower() == 'true'
    self._vtable_id = short_props.get("vtable", None)
    self._super_id = short_props.get("super", None)
    while True:
      key, short_props = _parse_short(next(it))
      if key is None:
        break
      if key == "field":
        field = Field(short_props["name"])
        with it as subit:
          field.deserialize(subit, short_props)
        self.fields.append(field)
      elif key == "vtable_value":
        self.vtable_values.append(int(short_props["va"], 16))
      else:
        raise Exception(f"invalid {key} at {it.line_num}")

  def link(self, structs_map):
    if self._linked:
      return
    self._linked = True
    if self._vtable_id is not None:
      self.vtable = structs_map[self._vtable_id]
    if self._super_id is not None:
      self.super = structs_map[self._super_id]
    for field in self.fields:
      field.type.link(structs_map)

  def bake_links(self):
    for glob in self.functions:
      glob._member_of = self.id

  def sort_links(self):
    self.functions.sort(key=lambda glob: glob.va)


class Global:

  def __init__(self, va, name):
    self.va = va  # type: int
    self.name = name  # type: str
    self.type = None  # type: Type
    self.size = None  # type: int
    self._member_of = None # type: str

  def serialize(self):
    yield f"{','.join(self.serialize_short())}"
    for line in self.serialize_detail():
      yield "  " + line

  def serialize_short(self):
    yield f"va={self.va:08X}"
    yield f"name={self.name}"
    if self.size is not None:
      yield f"size={self.size}"
    if self._member_of:
      yield f"member_of={self._member_of}"

  def serialize_detail(self):
    if self.type is not None:
      yield f"type: {','.join(self.type.serialize_short())}"
      for line in self.type.serialize_detail():
        yield "  " + line

  def deserialize(self, it: ScopeLineIter, short_props: typing.Dict[str, str]):
    self.va = int(short_props["va"], 16)
    self.name = short_props["name"]
    sz = short_props.get("size")
    if sz is not None:
      self.size = int(sz)
    self._member_of = short_props.get("member_of", None)
    while True:
      key, short_props = _parse_short(next(it))
      if key is None:
        break
      if key == "type":
        self.type = parse_type(it, short_props)
      else:
        raise Exception(f"invalid {key} at {it.line_num}")

  def clear_links(self):
    self._member_of = None

  def link(self, structs_map: dict[str, Struct]):
    if self.type is not None:
      self.type.link(structs_map)
    if self._member_of:
      structs_map[self._member_of].functions.append(self)


def _parse_short(line):
  if line is None:
    return None, None
  name, props = line.split(": ", 1)
  props = props.split(",")
  result = {}
  for prop in props:
    key, value = prop.split("=", 1)
    result[key] = value
  return name, result


def deserialize(lines: typing.Iterable[str]) -> typing.Tuple[typing.List[Struct], typing.List[Global]]:
  structs_map = {}  # type: dict[str, Struct]
  globs = []  # type: list[Global]
  it = ScopeLineIter(LineIter(lines))
  while True:
    key, short_props = _parse_short(next(it))
    if key is None:
      break
    if key == "struct":
      struct = Struct(short_props["name"])
      with it as subit:
        struct.deserialize(subit, short_props)
      structs_map[struct.id] = struct
    elif key == "global":
      glob = Global(int(short_props["va"], 16), short_props["name"])
      with it as subit:
        glob.deserialize(subit, short_props)
      globs.append(glob)
    else:
      raise Exception(f"invalid {key} at {it.line_num}")

  # link refs
  vtables = set()  # type: set[str]
  for struct in structs_map.values():
    struct.link(structs_map)
    if struct.vtable is not None:
      vtables.add(struct.vtable.id)
  for glob in globs:
    glob.link(structs_map)
  for struct in structs_map.values():
    struct.sort_links()

  structs = list(sorted(structs_map.values(), key=lambda s: s.name))  # type: list[Struct]
  return structs, globs


def serialize_globals(structs: typing.Iterable[Struct], globals: typing.Iterable[Global]):
  for glob in globals:  # type: Global
    glob.clear_links()
  for struct in structs:  # type: Struct
    struct.bake_links()
  for glob in sorted(globals, key=lambda g: g.va):  # type: Global
    yield f"global: {','.join(glob.serialize_short())}"
    for line in glob.serialize_detail():
      yield "  " + line


def serialize_structs(structs: typing.Iterable[Struct]):
  for struct in sorted(structs, key=lambda s: s.name):  # type: Struct
    yield f"struct: {','.join(struct.serialize_short())}"
    for line in struct.serialize_detail():
      yield "  " + line
