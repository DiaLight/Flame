import bisect
import enum
import typing


class MySpdType(enum.IntEnum):
    Ida = 0
    Fpo = 1
    Frm = 2


class MySpd:  # spd - esp delta

    def __init__(self, offs, spd, ty: MySpdType, kind: int, cmt: str):
        self.offs = offs
        self.spd = spd
        self.ty = ty
        self.kind = kind
        self.cmt = cmt

    def __repr__(self):
        return f'offs:{self.offs:04X} spd:{self.spd:X} ty:{self.ty.name} kind:{self.kind}'


class MyFpoFun:

    def __init__(self, rva, name):
        assert rva > 0
        self.rva = rva
        self.name = name
        self.spds: list[MySpd] = []
        self.size = 0

    def contains(self, rva):
        return self.rva <= rva < (rva + self.size)

    def __repr__(self):
        return f'rva:{self.rva:X}-{self.rva + self.size:X} {self.name}'

        # self._ty: my_pdb.FrameType = None

    def _add(self, my_spd: MySpd):
        bisect.insort(self.spds, my_spd, key=lambda mspd: mspd.offs)

    def _find_ge(self, offs) -> MySpd or None:
        idx = bisect.bisect_left(self.spds, offs, key=lambda mspd: mspd.offs)
        if idx >= len(self.spds):
            return None
        return self.spds[idx]

    def add_ida(self, rva, spd, kind: int, cmt: str):
        assert rva > 0
        offs = rva - self.rva
        self.size = max(self.size, offs + 1)
        self._add(MySpd(offs, spd, MySpdType.Ida, kind, cmt))

    def add_pdb(self, start_rva, end_rva, spd, flags: int, ty: MySpdType, cmt: str):
        start_offs, end_offs = (start_rva - self.rva), (end_rva - self.rva)
        my_spd: MySpd = self._find_ge(start_offs)
        if my_spd is not None:
            self._add(MySpd(start_offs, my_spd.spd, my_spd.ty, my_spd.kind, my_spd.cmt))
        self._add(MySpd(end_offs - 1, spd, ty, flags, cmt))


def write_varint(f, number):
    assert number >= 0
    while True:
        towrite = number & 0x7f
        number >>= 7
        if number:
            f.write(int.to_bytes(towrite | 0x80, 1, 'little'))
        else:
            f.write(int.to_bytes(towrite, 1, 'little'))
            break

def write_signed_varint(f, number):
    if number < 0:
        number = ((-number) << 1) | 1
    else:
        number = (number << 1) | 0
    write_varint(f, number)

def fpobin_serialize(f: typing.BinaryIO, fpos: list[MyFpoFun]):
    write_varint(f, len(fpos))
    last_rva = 0
    for mfpo in fpos:
        write_varint(f, mfpo.rva - last_rva)
        write_varint(f, mfpo.size)
        f.write(mfpo.name.encode('ascii') + b'\x00')
        write_varint(f, len(mfpo.spds))
        for mspd in mfpo.spds:
            write_varint(f, mspd.offs)
            write_signed_varint(f, mspd.spd)
            write_varint(f, mspd.ty)
            write_varint(f, mspd.kind)
        last_rva = mfpo.rva

def fpomap_serialize(f: typing.TextIO, fpos: list[MyFpoFun]):
    for mfpo in fpos:
        f.write(f'{mfpo.rva:08X}-{mfpo.rva+mfpo.size:08X} {mfpo.name}\n')
        for mspd in mfpo.spds:
            f.write(f'{mfpo.rva+mspd.offs:08X} {mspd.spd:X} {mspd.ty.name}  // {mspd.cmt}\n')
