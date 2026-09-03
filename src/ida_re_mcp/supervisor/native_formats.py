"""workspace 原生镜像格式与架构预检。"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import BinaryIO, Literal

type NativeContainer = Literal["elf", "pe"]
type NativeArchitecture = Literal["aarch64", "arm", "x86", "x86_64"]

_ELF32_HEADER_SIZE = 52
_ELF64_HEADER_SIZE = 64
_ELF32_PROGRAM_HEADER_SIZE = 32
_ELF64_PROGRAM_HEADER_SIZE = 56
_MAX_ELF_PROGRAM_HEADERS = 4_096
_UINT32_MAX = (1 << 32) - 1
_UINT64_MAX = (1 << 64) - 1
_PE_DOS_HEADER_SIZE = 64
_PE_COFF_PREFIX_SIZE = 24
_PE_DATA_DIRECTORY_SIZE = 8
_PE_MAX_DATA_DIRECTORIES = 16
_PE32_OPTIONAL_FIXED_SIZE = 96
_PE32_PLUS_OPTIONAL_FIXED_SIZE = 112
_PE_SECURITY_DIRECTORY_INDEX = 4
_PE_SECTION_HEADER_SIZE = 40
_MAX_PE_OPTIONAL_HEADER_SIZE = 4_096
_MAX_PE_SECTIONS = 96
_PE_PAGE_SIZE = 0x1_000
_PE_MIN_FILE_ALIGNMENT = 0x200
_PE_MAX_FILE_ALIGNMENT = 0x1_0000
_PE_SECTION_EXECUTE = 0x2000_0000


@dataclass(frozen=True, slots=True)
class NativeImageIdentity:
    """由文件头确定并经过格式预检的原生镜像身份。"""

    container: NativeContainer
    architecture: NativeArchitecture
    bitness: Literal[32, 64]
    endian: Literal["little"] = "little"


class UnsupportedNativeImageError(ValueError):
    """样本不是当前产品可可靠加载的原生镜像。"""

    def __init__(self, message: str, *, detected: str) -> None:
        super().__init__(message)
        self.detected = detected

    @property
    def details(self) -> dict[str, object]:
        return {
            "detected": self.detected,
            "supported_images": [
                "elf32-arm-little",
                "elf32-x86-little",
                "elf64-aarch64-little",
                "elf64-x86_64-little",
                "pe32-x86-little",
                "pe32+-x86_64-little",
            ],
        }


def inspect_native_image(path: Path) -> NativeImageIdentity:
    """有界读取文件头, 拒绝脚本、压缩包装器、托管 PE、原始数据和未知架构。"""

    resolved = path.resolve(strict=True)
    if not resolved.is_file():
        raise UnsupportedNativeImageError("样本不是普通文件", detected="not_regular_file")
    size = resolved.stat().st_size
    with resolved.open("rb") as stream:
        prefix = stream.read(_ELF64_HEADER_SIZE)
        if prefix.startswith(b"\x7fELF"):
            return _inspect_elf(stream, prefix, size=size)
        if prefix.startswith(b"MZ"):
            return _inspect_pe(stream, prefix, size=size)
        if prefix[:4] in {
            b"\xca\xfe\xba\xbe",
            b"\xcf\xfa\xed\xfe",
            b"\xfe\xed\xfa\xcf",
        }:
            raise UnsupportedNativeImageError(
                "当前版本尚未通过 Mach-O 硬门禁",
                detected="mach_o",
            )
        if prefix.startswith(b"#!"):
            detected = "shell_script" if b"/sh" in prefix[:32] else "script"
            raise UnsupportedNativeImageError(
                "样本是脚本或自解压包装器, 不是原生镜像; 请先在隔离环境中提取载荷",
                detected=detected,
            )
        if prefix.startswith(b"\x1f\x8b\x08"):
            raise UnsupportedNativeImageError(
                "样本是 gzip 数据, 不是原生镜像; 请先在隔离环境中提取载荷",
                detected="gzip",
            )
    raise UnsupportedNativeImageError(
        "无法从文件头识别受支持的原生镜像",
        detected="unknown",
    )


def _inspect_elf(stream: BinaryIO, header: bytes, *, size: int) -> NativeImageIdentity:
    if len(header) < _ELF32_HEADER_SIZE:
        raise UnsupportedNativeImageError("ELF 文件头不完整", detected="truncated_elf")
    elf_class = header[4]
    if elf_class == 1:
        bitness: Literal[32, 64] = 32
        header_size = _ELF32_HEADER_SIZE
        program_entry_size = _ELF32_PROGRAM_HEADER_SIZE
        integer_limit = _UINT32_MAX
    elif elf_class == 2:
        bitness = 64
        header_size = _ELF64_HEADER_SIZE
        program_entry_size = _ELF64_PROGRAM_HEADER_SIZE
        integer_limit = _UINT64_MAX
    else:
        raise UnsupportedNativeImageError("ELF 位数标记无效", detected="invalid_elf")
    if len(header) < header_size:
        raise UnsupportedNativeImageError("ELF 文件头不完整", detected="truncated_elf")
    if header[5] != 1:
        detected = "elf_big_endian" if header[5] == 2 else "invalid_elf"
        raise UnsupportedNativeImageError("仅支持小端 ELF 镜像", detected=detected)
    if header[6] != 1 or int.from_bytes(header[20:24], "little") != 1:
        raise UnsupportedNativeImageError("ELF 版本无效", detected="invalid_elf")
    image_type = int.from_bytes(header[16:18], "little")
    if image_type not in {2, 3}:
        raise UnsupportedNativeImageError(
            "仅支持 ELF 可执行文件或共享对象",
            detected="unsupported_elf_type",
        )
    machine = int.from_bytes(header[18:20], "little")
    architecture = _elf_architecture(machine, bitness=bitness)
    if bitness == 32:
        entry = int.from_bytes(header[24:28], "little")
        program_offset = int.from_bytes(header[28:32], "little")
        declared_header_size = int.from_bytes(header[40:42], "little")
        declared_program_entry_size = int.from_bytes(header[42:44], "little")
        program_count = int.from_bytes(header[44:46], "little")
    else:
        entry = int.from_bytes(header[24:32], "little")
        program_offset = int.from_bytes(header[32:40], "little")
        declared_header_size = int.from_bytes(header[52:54], "little")
        declared_program_entry_size = int.from_bytes(header[54:56], "little")
        program_count = int.from_bytes(header[56:58], "little")
    if declared_header_size != header_size or declared_program_entry_size != program_entry_size:
        raise UnsupportedNativeImageError("ELF 头尺寸无效", detected="invalid_elf")
    if program_count == 0xFFFF:
        raise UnsupportedNativeImageError(
            "当前版本不接受扩展 ELF program-header 数量",
            detected="unsupported_elf_header",
        )
    if program_count == 0 or program_count > _MAX_ELF_PROGRAM_HEADERS:
        raise UnsupportedNativeImageError("ELF program-header 数量无效", detected="invalid_elf")
    program_bytes = program_count * program_entry_size
    if (
        program_offset < header_size
        or program_offset > size
        or program_bytes > size - program_offset
    ):
        raise UnsupportedNativeImageError("ELF program-header 表越界", detected="invalid_elf")

    has_load_segment = False
    executable_ranges: list[tuple[int, int]] = []
    stream.seek(program_offset)
    for _index in range(program_count):
        program = stream.read(program_entry_size)
        if len(program) != program_entry_size:
            raise UnsupportedNativeImageError(
                "ELF program-header 不完整",
                detected="invalid_elf",
            )
        if int.from_bytes(program[:4], "little") != 1:
            continue
        if bitness == 32:
            file_offset = int.from_bytes(program[4:8], "little")
            virtual_address = int.from_bytes(program[8:12], "little")
            file_size = int.from_bytes(program[16:20], "little")
            memory_size = int.from_bytes(program[20:24], "little")
            flags = int.from_bytes(program[24:28], "little")
            alignment = int.from_bytes(program[28:32], "little")
        else:
            flags = int.from_bytes(program[4:8], "little")
            file_offset = int.from_bytes(program[8:16], "little")
            virtual_address = int.from_bytes(program[16:24], "little")
            file_size = int.from_bytes(program[32:40], "little")
            memory_size = int.from_bytes(program[40:48], "little")
            alignment = int.from_bytes(program[48:56], "little")
        if memory_size == 0:
            raise UnsupportedNativeImageError(
                "ELF PT_LOAD 不能为空",
                detected="invalid_elf",
            )
        if file_size > memory_size or file_offset > size or file_size > size - file_offset:
            raise UnsupportedNativeImageError(
                "ELF PT_LOAD 文件区间越界",
                detected="invalid_elf",
            )
        if alignment not in {0, 1} and (
            not _is_power_of_two(alignment)
            or file_offset % alignment != virtual_address % alignment
        ):
            raise UnsupportedNativeImageError(
                "ELF PT_LOAD alignment 无效",
                detected="invalid_elf",
            )
        if memory_size > integer_limit - virtual_address:
            raise UnsupportedNativeImageError(
                "ELF PT_LOAD 虚拟区间溢出",
                detected="invalid_elf",
            )
        virtual_end = virtual_address + memory_size
        has_load_segment = True
        if flags & 0x1:
            executable_ranges.append((virtual_address, virtual_end))
    if not has_load_segment:
        raise UnsupportedNativeImageError(
            "ELF 不包含可加载段",
            detected="invalid_elf",
        )
    if (image_type == 2 or entry != 0) and not any(
        start <= entry < end for start, end in executable_ranges
    ):
        raise UnsupportedNativeImageError(
            "ELF entry 不在可执行 PT_LOAD 内",
            detected="invalid_elf",
        )
    return NativeImageIdentity("elf", architecture, bitness=bitness)


def _inspect_pe(stream: BinaryIO, dos_header: bytes, *, size: int) -> NativeImageIdentity:
    if len(dos_header) < _PE_DOS_HEADER_SIZE:
        raise UnsupportedNativeImageError("PE DOS 文件头不完整", detected="truncated_pe")
    pe_offset = int.from_bytes(dos_header[0x3C:0x40], "little")
    if pe_offset < _PE_DOS_HEADER_SIZE or pe_offset > size - _PE_COFF_PREFIX_SIZE:
        raise UnsupportedNativeImageError("PE 头偏移越界", detected="invalid_pe")
    stream.seek(pe_offset)
    coff = stream.read(_PE_COFF_PREFIX_SIZE)
    if len(coff) != _PE_COFF_PREFIX_SIZE or coff[:4] != b"PE\0\0":
        raise UnsupportedNativeImageError("PE 签名无效", detected="invalid_pe")
    machine = int.from_bytes(coff[4:6], "little")
    if machine not in {0x014C, 0x8664}:
        raise UnsupportedNativeImageError(
            "PE 架构不受支持",
            detected=f"pe_machine_0x{machine:x}",
        )
    section_count = int.from_bytes(coff[6:8], "little")
    optional_size = int.from_bytes(coff[20:22], "little")
    characteristics = int.from_bytes(coff[22:24], "little")
    if section_count == 0 or section_count > _MAX_PE_SECTIONS:
        raise UnsupportedNativeImageError("PE section 数量无效", detected="invalid_pe")
    if characteristics & 0x0002 == 0:
        raise UnsupportedNativeImageError(
            "PE 不是 executable image",
            detected="unsupported_pe_type",
        )
    if optional_size < 2 or optional_size > _MAX_PE_OPTIONAL_HEADER_SIZE:
        raise UnsupportedNativeImageError("PE 可选头尺寸无效", detected="invalid_pe")
    if pe_offset + _PE_COFF_PREFIX_SIZE + optional_size > size:
        raise UnsupportedNativeImageError("PE 可选头越界", detected="invalid_pe")
    optional = stream.read(optional_size)
    if len(optional) != optional_size:
        raise UnsupportedNativeImageError("PE 可选头不完整", detected="invalid_pe")
    optional_magic = int.from_bytes(optional[:2], "little")
    if optional_magic == 0x010B:
        architecture: NativeArchitecture = "x86"
        bitness: Literal[32, 64] = 32
        expected_machine = 0x014C
        optional_fixed_size = _PE32_OPTIONAL_FIXED_SIZE
        directory_count_offset = 92
    elif optional_magic == 0x020B:
        architecture = "x86_64"
        bitness = 64
        expected_machine = 0x8664
        optional_fixed_size = _PE32_PLUS_OPTIONAL_FIXED_SIZE
        directory_count_offset = 108
    else:
        raise UnsupportedNativeImageError("PE 可选头标记无效", detected="invalid_pe")
    if machine != expected_machine:
        raise UnsupportedNativeImageError("PE 架构与位数不匹配", detected="invalid_pe")
    if optional_size < optional_fixed_size:
        raise UnsupportedNativeImageError("PE 可选头尺寸无效", detected="invalid_pe")
    entry = int.from_bytes(optional[16:20], "little")
    section_alignment = int.from_bytes(optional[32:36], "little")
    file_alignment = int.from_bytes(optional[36:40], "little")
    size_of_image = int.from_bytes(optional[56:60], "little")
    size_of_headers = int.from_bytes(optional[60:64], "little")
    if not _valid_pe_alignments(
        section_alignment=section_alignment,
        file_alignment=file_alignment,
    ):
        raise UnsupportedNativeImageError("PE section/file alignment 无效", detected="invalid_pe")
    section_table_offset = pe_offset + _PE_COFF_PREFIX_SIZE + optional_size
    section_table_size = section_count * _PE_SECTION_HEADER_SIZE
    section_table_end = section_table_offset + section_table_size
    if (
        size_of_image == 0
        or size_of_image % section_alignment != 0
        or size_of_headers < section_table_end
        or size_of_headers > size
        or size_of_image < _align_up(size_of_headers, section_alignment)
        or section_table_size > size - section_table_offset
    ):
        raise UnsupportedNativeImageError("PE image/header 尺寸无效", detected="invalid_pe")
    directory_count = int.from_bytes(
        optional[directory_count_offset : directory_count_offset + 4],
        "little",
    )
    directory_capacity = (optional_size - optional_fixed_size) // _PE_DATA_DIRECTORY_SIZE
    if directory_count > _PE_MAX_DATA_DIRECTORIES or directory_count > directory_capacity:
        raise UnsupportedNativeImageError("PE data directory 数量越界", detected="invalid_pe")
    directories: list[tuple[int, int]] = []
    for index in range(directory_count):
        offset = optional_fixed_size + index * _PE_DATA_DIRECTORY_SIZE
        address = int.from_bytes(optional[offset : offset + 4], "little")
        directory_size = int.from_bytes(optional[offset + 4 : offset + 8], "little")
        directories.append((address, directory_size))
    if directory_count > 14 and any(directories[14]):
        raise UnsupportedNativeImageError(
            "普通 .NET/Mono PE 不在产品范围内",
            detected="managed_runtime",
        )
    for index, (address, directory_size) in enumerate(directories):
        if address == 0 and directory_size == 0:
            continue
        if address == 0 or directory_size == 0:
            raise UnsupportedNativeImageError("PE data directory 区间无效", detected="invalid_pe")
        limit = size if index == _PE_SECURITY_DIRECTORY_INDEX else size_of_image
        if address > limit or directory_size > limit - address:
            raise UnsupportedNativeImageError("PE data directory 越界", detected="invalid_pe")

    stream.seek(section_table_offset)
    executable_ranges: list[tuple[int, int]] = []
    has_mapped_section = False
    first_section_rva = _align_up(size_of_headers, section_alignment)
    for _index in range(section_count):
        section = stream.read(_PE_SECTION_HEADER_SIZE)
        if len(section) != _PE_SECTION_HEADER_SIZE:
            raise UnsupportedNativeImageError("PE section 头不完整", detected="invalid_pe")
        virtual_size = int.from_bytes(section[8:12], "little")
        virtual_address = int.from_bytes(section[12:16], "little")
        raw_size = int.from_bytes(section[16:20], "little")
        raw_offset = int.from_bytes(section[20:24], "little")
        section_characteristics = int.from_bytes(section[36:40], "little")
        if raw_size and (
            raw_offset < size_of_headers
            or raw_offset % file_alignment != 0
            or raw_size % file_alignment != 0
            or raw_offset > size
            or raw_size > size - raw_offset
        ):
            raise UnsupportedNativeImageError("PE section 文件区间越界", detected="invalid_pe")
        mapped_size = max(virtual_size, raw_size)
        if (
            virtual_address < first_section_rva
            or virtual_address % section_alignment != 0
            or virtual_address > size_of_image
            or mapped_size > size_of_image - virtual_address
        ):
            raise UnsupportedNativeImageError("PE section 虚拟区间越界", detected="invalid_pe")
        if mapped_size == 0:
            continue
        has_mapped_section = True
        virtual_end = virtual_address + mapped_size
        if section_characteristics & _PE_SECTION_EXECUTE:
            executable_ranges.append((virtual_address, virtual_end))
    if not has_mapped_section:
        raise UnsupportedNativeImageError("PE 不包含非空 section", detected="invalid_pe")
    if entry != 0 and not any(start <= entry < end for start, end in executable_ranges):
        raise UnsupportedNativeImageError(
            "PE entry 不在可执行 section 内",
            detected="invalid_pe",
        )
    return NativeImageIdentity("pe", architecture, bitness=bitness)


def _elf_architecture(
    machine: int,
    *,
    bitness: Literal[32, 64],
) -> NativeArchitecture:
    if bitness == 32 and machine == 0x03:
        return "x86"
    if bitness == 32 and machine == 0x28:
        return "arm"
    if bitness == 64 and machine == 0x3E:
        return "x86_64"
    if bitness == 64 and machine == 0xB7:
        return "aarch64"
    raise UnsupportedNativeImageError(
        "ELF 架构不受支持",
        detected=f"elf_machine_0x{machine:x}",
    )


def _is_power_of_two(value: int) -> bool:
    return value > 0 and value & (value - 1) == 0


def _valid_pe_alignments(*, section_alignment: int, file_alignment: int) -> bool:
    if (
        not _is_power_of_two(section_alignment)
        or not _is_power_of_two(file_alignment)
        or section_alignment < file_alignment
        or file_alignment > _PE_MAX_FILE_ALIGNMENT
    ):
        return False
    if section_alignment < _PE_PAGE_SIZE:
        return section_alignment == file_alignment
    return file_alignment >= _PE_MIN_FILE_ALIGNMENT


def _align_up(value: int, alignment: int) -> int:
    return (value + alignment - 1) // alignment * alignment
