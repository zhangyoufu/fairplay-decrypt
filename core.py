"""FairPlay IPA decryption and page-key derivation."""

from __future__ import annotations

import hashlib
import struct
from collections.abc import Iterator, Sequence
from dataclasses import dataclass

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

ARM32 = 0x0000000C
ARM64 = 0x0100000C
ARM_CPU_TYPES = (ARM32, ARM64)
CPU_SUBTYPE_MASK = 0x00FFFFFF
MH_MAGIC = 0xFEEDFACE
MH_MAGIC_64 = 0xFEEDFACF
LC_ENCRYPTION_INFO = 0x21
LC_ENCRYPTION_INFO_64 = 0x2C
MAX_LOAD_COMMANDS = 1000
MAX_FAT_ARCHES = 32
MASK32 = 0xFFFFFFFF
PAGE_SIZE = 4096
ROUND_SELECTORS = (
    ((0, 1), (2, 3), (4, 5), (6, 7)),
    ((2, 1), (0, 3), (4, 7), (6, 5)),
    ((2, 0), (4, 1), (6, 3), (7, 5)),
    ((1, 2), (4, 0), (7, 3), (5, 6)),
)
ROUND_CONSTANTS = (0x68547C2E, 0x7E05E1DE, 0xD495038B, 0x0AB24ADD)
FINAL_SELECTORS = ((0, 1, 2, 3), (0, 2, 4, 6), (0, 3, 5, 7), (4, 5, 6, 7))
FINAL_CONSTANTS = (0x5B7198C7, 0xEB5DE22C, 0x0F8AA8FA, 0xF6E1BB3F)


@dataclass(frozen=True)
class MachoSlice:
    base: int
    size: int
    cpu: int
    subtype: int
    cryptoff: int
    cryptsize: int
    cryptid: int
    cryptid_offset: int

    @property
    def page_count(self) -> int:
        return self.cryptsize // PAGE_SIZE


@dataclass(frozen=True)
class PageKeyTable:
    offset: int
    page_count: int
    absolute_index: bool


def _xor(a: bytes, b: bytes) -> bytes:
    if len(a) != len(b):
        raise ValueError("XOR inputs must have equal lengths")
    return bytes(x ^ y for x, y in zip(a, b))


def _xor_int(lhs: Sequence[int], rhs: Sequence[int]) -> Sequence[int]:
    return [x ^ y for x, y in zip(lhs, rhs)]


def _fat_entries(data: bytes) -> list[tuple[int, int, int, int]]:
    """Return ``(cpu, subtype, offset, size)`` for every FAT architecture."""
    magic = data[:4]
    if magic == b"\xca\xfe\xba\xbe":
        entry_size, fmt = 20, ">IIIII"
    elif magic == b"\xca\xfe\xba\xbf":
        entry_size, fmt = 32, ">IIQQII"
    else:
        raise ValueError("not a FAT Mach-O")
    if len(data) < 8:
        raise ValueError("truncated FAT header")
    count = struct.unpack_from(">I", data, 4)[0]
    if not 0 < count <= MAX_FAT_ARCHES:
        raise ValueError("invalid FAT architecture count")
    if 8 + count * entry_size > len(data):
        raise ValueError("invalid FAT architecture table")
    entries = []
    for index in range(count):
        fields = struct.unpack_from(fmt, data, 8 + index * entry_size)
        cpu, subtype, offset, size = fields[:4]
        if size == 0 or offset + size > len(data):
            raise ValueError("FAT slice exceeds file")
        entries.append((cpu, subtype, offset, size))
    return entries


def _macho_slice(data: bytes, base: int, size: int) -> MachoSlice:
    if size < 28 or base + size > len(data):
        raise ValueError("Mach-O slice exceeds file")
    magic = struct.unpack_from("<I", data, base)[0]
    if magic == MH_MAGIC:
        _, cpu, subtype, _filetype, ncmds, sizeofcmds, _flags = struct.unpack_from(
            "<IIIIIII", data, base
        )
        if cpu != ARM32:
            raise ValueError("not an arm Mach-O slice")
        header_size, encryption_command = 28, LC_ENCRYPTION_INFO
    elif magic == MH_MAGIC_64:
        if size < 32:
            raise ValueError("truncated Mach-O header")
        _, cpu, subtype, _filetype, ncmds, sizeofcmds, _flags, _res = (
            struct.unpack_from("<IIIIIIII", data, base)
        )
        if cpu != ARM64:
            raise ValueError("not an arm64 Mach-O slice")
        header_size, encryption_command = 32, LC_ENCRYPTION_INFO_64
    else:
        raise ValueError("invalid Mach-O header")
    if ncmds > MAX_LOAD_COMMANDS:
        raise ValueError("too many Mach-O load commands")
    pos = base + header_size
    commands_end = pos + sizeofcmds
    if commands_end > base + size:
        raise ValueError("load commands exceed Mach-O slice")
    found = None
    for _ in range(ncmds):
        if pos + 8 > commands_end:
            raise ValueError("truncated load command")
        cmd, cmd_size = struct.unpack_from("<II", data, pos)
        if cmd_size < 8 or pos + cmd_size > commands_end:
            raise ValueError("invalid load command")
        if cmd == encryption_command:
            if cmd_size < 20:
                raise ValueError("short encryption info command")
            if found is not None:
                raise ValueError("duplicate encryption info command")
            cryptoff, cryptsize, cryptid = struct.unpack_from("<III", data, pos + 8)
            found = (cryptoff, cryptsize, cryptid, pos + 16)
        pos += cmd_size
    if found is None:
        return MachoSlice(base, size, cpu, subtype, 0, 0, 0, 0)
    cryptoff, cryptsize, cryptid, cryptid_offset = found
    if cryptid == 0:
        return MachoSlice(base, size, cpu, subtype, cryptoff, cryptsize, 0, 0)
    if cryptid != 1 or cryptsize == 0 or cryptsize % PAGE_SIZE:
        raise ValueError(f"unsupported cryptid/size: {cryptid}, {cryptsize}")
    if cryptoff % PAGE_SIZE:
        raise ValueError("encrypted region is not page aligned")
    if cryptoff + cryptsize > size:
        raise ValueError("invalid encrypted region bounds")
    if cryptid_offset >= base + cryptoff:
        raise ValueError("invalid encryption info location")
    return MachoSlice(
        base, size, cpu, subtype, cryptoff, cryptsize, cryptid, cryptid_offset
    )


def macho_slices(data: bytes) -> tuple[MachoSlice, ...]:
    """Parse every arm/arm64 slice in a thin or FAT Mach-O file."""
    if data[:4] in (b"\xca\xfe\xba\xbe", b"\xca\xfe\xba\xbf"):
        entries = _fat_entries(data)
        arm = [
            (base, size)
            for cpu, _subtype, base, size in entries
            if cpu in ARM_CPU_TYPES
        ]
        if not arm:
            raise ValueError("no ARM Mach-O slices")
    elif data[:4] in (b"\xce\xfa\xed\xfe", b"\xcf\xfa\xed\xfe"):
        arm = [(0, len(data))]
    else:
        raise ValueError("not a supported Mach-O")
    return tuple(_macho_slice(data, base, size) for base, size in arm)


def _children(data: bytes, start: int, end: int) -> Iterator[tuple[bytes, int, int]]:
    offset = start
    while offset < end:
        if offset + 8 > end:
            raise ValueError("truncated SINF atom")
        size = int.from_bytes(data[offset : offset + 4], "big")
        if size < 8 or offset + size > end:
            raise ValueError(f"invalid SINF atom size at {offset:#x}")
        yield data[offset + 4 : offset + 8], offset + 8, offset + size
        offset += size


def _sinf_field(sinf: bytes, wanted: bytes) -> bytes:
    roots = list(_children(sinf, 0, len(sinf)))
    if len(roots) != 1 or roots[0][0] != b"sinf":
        raise ValueError("expected outer sinf atom")
    schi = [x for x in _children(sinf, roots[0][1], roots[0][2]) if x[0] == b"schi"]
    if len(schi) != 1:
        raise ValueError("expected one schi container")
    fields = [x for x in _children(sinf, schi[0][1], schi[0][2]) if x[0] == wanted]
    if len(fields) != 1:
        raise ValueError(f"expected one {wanted!r} field")
    return sinf[fields[0][1] : fields[0][2]]


def derive_work16(credential: bytes, sinf: bytes) -> bytes:
    name = _sinf_field(sinf, b"name").split(b"\0", 1)[0]
    iviv = _sinf_field(sinf, b"iviv")
    raw_priv = _sinf_field(sinf, b"priv")
    if len(raw_priv) not in (440, 448):
        raise ValueError("unsupported SINF priv-record length")
    if len(raw_priv) == 440:
        if raw_priv[-8:] != bytes(8):
            raise ValueError("invalid SINF priv-record trailer")
        raw_priv = raw_priv[:-8]
    if len(credential) != 16 or len(iviv) != 16:
        raise ValueError("invalid SINF priv-record dimensions")
    iv = hashlib.md5(name + iviv).digest()
    op = Cipher(algorithms.AES(_xor(credential, b"0" * 16)), modes.CBC(iv)).decryptor()
    clear = op.update(raw_priv) + op.finalize()
    if clear[:4] != b"itun" or clear[20:24] != b"key " or clear[44:48] != b"iviv":
        raise ValueError("credential does not decode this SINF priv record")
    return clear[24:40]


def _p_class_tables(
    supf: bytes, slices: Sequence[MachoSlice]
) -> tuple[PageKeyTable, ...]:
    """Parse a p-class container (``.supp`` v01 / ``.v4.supp`` v04).

    Page keys are indexed by absolute file page: the table starts at page 0
    and therefore also covers the unencrypted Mach-O header pages.
    """
    version = supf[0]
    offset = 28 if version == 1 else 8
    if len(supf) < offset:
        raise ValueError("truncated SUPF header")
    count = struct.unpack_from(">I", supf, offset - 4)[0]
    if count == 0:
        raise ValueError("SUPF page table is empty")
    trailer = offset + count * 32
    if trailer + 4 > len(supf):
        raise ValueError("SUPF page table exceeds file")
    cert_length = struct.unpack_from(">I", supf, trailer)[0]
    if cert_length == 0 or trailer + 4 + cert_length > len(supf):
        raise ValueError("invalid SUPF certificate trailer")
    if trailer + 4 + cert_length + 128 > len(supf):
        raise ValueError("truncated SUPF signature")
    for image in slices:
        first = (image.base + image.cryptoff) // PAGE_SIZE
        if first + image.page_count > count:
            raise ValueError("SUPF page keys are incomplete")
    return tuple(PageKeyTable(offset, count, True) for _ in slices)


def _f_class_tables(
    supf: bytes, slices: Sequence[MachoSlice]
) -> tuple[PageKeyTable, ...]:
    """Parse an f-class container (``.supf`` v03 / ``.v5.supf`` v05)."""
    version = supf[0]
    if len(supf) < 12:
        raise ValueError("truncated SUPF header")
    segment_count = struct.unpack_from(">I", supf, 8)[0]
    if not 0 < segment_count <= MAX_FAT_ARCHES:
        raise ValueError("invalid SUPF architecture count")
    header_size = 32 if version == 3 else 12
    pos = 12
    segments = {}
    base_segments = {}
    for _ in range(segment_count):
        if pos + 12 > len(supf):
            raise ValueError("truncated SUPF architecture header")
        length, cpu, subtype = struct.unpack_from(">III", supf, pos)
        if length < header_size or pos + 4 + length > len(supf):
            raise ValueError("invalid SUPF architecture length")
        pages = struct.unpack_from(">I", supf, pos + header_size)[0]
        if pages == 0 or length < header_size + pages * 32:
            raise ValueError("SUPF page records are incomplete")
        entry = (pos + 4 + header_size, pages)
        key = (cpu, subtype)
        if key in segments:
            raise ValueError("duplicate SUPF architecture record")
        segments[key] = entry
        base_key = (cpu, subtype & CPU_SUBTYPE_MASK)
        base_segments[base_key] = None if base_key in base_segments else entry
        pos += 4 + length
    tables = []
    for image in slices:
        entry = segments.get((image.cpu, image.subtype))
        if entry is None:
            entry = base_segments.get(
                (image.cpu, image.subtype & CPU_SUBTYPE_MASK)
            )
        if entry is None:
            raise ValueError(
                f"SUPF record missing for cpu {image.cpu:#x} "
                f"subtype {image.subtype:#x}"
            )
        offset, pages = entry
        if pages < image.page_count:
            raise ValueError("SUPF page keys are incomplete")
        tables.append(PageKeyTable(offset, pages, False))
    return tuple(tables)


def supf_page_key_tables(
    supf: bytes, slices: Sequence[MachoSlice]
) -> tuple[PageKeyTable, ...]:
    if not supf:
        raise ValueError("empty SUPF file")
    if not slices:
        raise ValueError("no encrypted Mach-O slices")
    version = supf[0]
    if version in (1, 4):
        return _p_class_tables(supf, slices)
    if version in (3, 5):
        return _f_class_tables(supf, slices)
    raise ValueError(f"unsupported SUPF version: {version}")


def source_blocks(wrapped: bytes, absolute_index: int) -> tuple[bytes, bytes, bytes]:
    if len(wrapped) != 16 or not 0 <= absolute_index < 1 << 32:
        raise ValueError("invalid wrapped record or page index")
    page_offset = (absolute_index << 12).to_bytes(8, "big")
    first = wrapped[8:16] + page_offset
    second = wrapped
    third = page_offset + wrapped[:8]
    return first, second, third


def finish(state: Sequence[int]) -> Sequence[int]:
    # 16-bit
    src = state
    for selectors in ROUND_SELECTORS:
        dst = []
        for pair, constant in zip(selectors, ROUND_CONSTANTS):
            mixed = src[pair[0]] + src[pair[1]]  # carry bit kept
            square = mixed * mixed
            x = (square & MASK32) ^ (mixed >> 16) ^ constant
            dst.extend((x & 0xFFFF, x >> 16))
        src = dst

    # 32-bit
    dst = []
    for quartet, constant in zip(FINAL_SELECTORS, FINAL_CONSTANTS):
        a = (src[quartet[1]] << 16) | src[quartet[0]]
        b = (src[quartet[3]] << 16) | src[quartet[2]]
        mixed = (a + b) & MASK32  # carry bit dropped
        square = mixed * mixed
        x = (square & MASK32) ^ (square >> 32) ^ constant
        dst.extend((x & 0xFFFF, x >> 16))

    return _xor_int(state, dst)


def block_transform(source: bytes, work: bytes) -> bytes:
    """AES-128-ECB encrypt of ``source`` block under ``work``."""
    if len(source) != 16 or len(work) != 16:
        raise ValueError("block-transform inputs require 16 bytes")
    op = Cipher(algorithms.AES(work), modes.ECB()).encryptor()
    return op.update(source) + op.finalize()


def derive_page_key(wrapped: bytes, absolute_index: int, work: bytes) -> bytes:
    a, b, c = (struct.unpack(">8H", block_transform(s, work)) for s in source_blocks(wrapped, absolute_index))
    return struct.pack(">8H", *finish(_xor_int(finish(_xor_int(finish(a), b)), c)))


def decrypt_binary(
    source: bytes, sinf: bytes, supf: bytes, credential: bytes
) -> tuple[bytes, int]:
    slices = tuple(image for image in macho_slices(source) if image.cryptid == 1)
    if not slices:
        raise ValueError("no encrypted Mach-O slices")
    tables = supf_page_key_tables(supf, slices)
    work = derive_work16(credential, sinf)
    result = bytearray(source)
    total_pages = 0
    for image, table in zip(slices, tables):
        first_page = (image.base + image.cryptoff) // PAGE_SIZE
        for local_page in range(image.page_count):
            absolute_index = first_page + local_page
            index = absolute_index if table.absolute_index else local_page
            record_start = table.offset + 32 * index
            record = supf[record_start : record_start + 32]
            if len(record) != 32:
                raise ValueError("truncated SUPF page record")
            key = derive_page_key(record[:16], absolute_index, work)
            start = image.base + image.cryptoff + PAGE_SIZE * local_page
            ciphertext = source[start : start + PAGE_SIZE]
            op = Cipher(algorithms.AES(key), modes.CBC(record[16:32])).decryptor()
            result[start : start + PAGE_SIZE] = op.update(ciphertext) + op.finalize()
            total_pages += 1
        struct.pack_into("<I", result, image.cryptid_offset, 0)
    return bytes(result), total_pages
