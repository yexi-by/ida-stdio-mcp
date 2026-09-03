from __future__ import annotations

from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Literal

import pytest
from hypothesis import given
from hypothesis import strategies as st

from ida_re_mcp.supervisor.native_formats import (
    NativeImageIdentity,
    UnsupportedNativeImageError,
    inspect_native_image,
)

FIXTURE_ROOT = Path(__file__).parents[1] / "fixtures" / "bin"


def _elf(
    *,
    bitness: Literal[32, 64],
    machine: int,
    image_type: int = 3,
    entry: int | None = None,
    flags: int = 5,
    file_offset: int = 0,
    virtual_address: int = 0,
    file_size: int | None = None,
    memory_size: int | None = None,
    alignment: int = 0x1_000,
    declared_header_size: int | None = None,
    declared_program_entry_size: int | None = None,
) -> bytes:
    header_size = 52 if bitness == 32 else 64
    program_entry_size = 32 if bitness == 32 else 56
    actual_declared_header_size = (
        header_size if declared_header_size is None else declared_header_size
    )
    actual_declared_program_entry_size = (
        program_entry_size if declared_program_entry_size is None else declared_program_entry_size
    )
    image = bytearray(header_size + program_entry_size)
    actual_file_size = len(image) if file_size is None else file_size
    actual_memory_size = actual_file_size if memory_size is None else memory_size
    actual_entry = header_size if entry is None and image_type == 2 else entry or 0
    image[:4] = b"\x7fELF"
    image[4] = 1 if bitness == 32 else 2
    image[5] = 1
    image[6] = 1
    image[16:18] = image_type.to_bytes(2, "little")
    image[18:20] = machine.to_bytes(2, "little")
    image[20:24] = (1).to_bytes(4, "little")
    if bitness == 32:
        image[24:28] = actual_entry.to_bytes(4, "little")
        image[28:32] = header_size.to_bytes(4, "little")
        image[40:42] = actual_declared_header_size.to_bytes(2, "little")
        image[42:44] = actual_declared_program_entry_size.to_bytes(2, "little")
        image[44:46] = (1).to_bytes(2, "little")
        image[52:56] = (1).to_bytes(4, "little")
        image[56:60] = file_offset.to_bytes(4, "little")
        image[60:64] = virtual_address.to_bytes(4, "little")
        image[68:72] = actual_file_size.to_bytes(4, "little")
        image[72:76] = actual_memory_size.to_bytes(4, "little")
        image[76:80] = flags.to_bytes(4, "little")
        image[80:84] = alignment.to_bytes(4, "little")
    else:
        image[24:32] = actual_entry.to_bytes(8, "little")
        image[32:40] = header_size.to_bytes(8, "little")
        image[52:54] = actual_declared_header_size.to_bytes(2, "little")
        image[54:56] = actual_declared_program_entry_size.to_bytes(2, "little")
        image[56:58] = (1).to_bytes(2, "little")
        image[64:68] = (1).to_bytes(4, "little")
        image[68:72] = flags.to_bytes(4, "little")
        image[72:80] = file_offset.to_bytes(8, "little")
        image[80:88] = virtual_address.to_bytes(8, "little")
        image[96:104] = actual_file_size.to_bytes(8, "little")
        image[104:112] = actual_memory_size.to_bytes(8, "little")
        image[112:120] = alignment.to_bytes(8, "little")
    return bytes(image)


def _pe(
    *,
    bitness: Literal[32, 64],
    machine: int | None = None,
    managed: bool = False,
    entry: int = 0x1_000,
    optional_size: int | None = None,
    directory_count: int = 16,
    directories: dict[int, tuple[int, int]] | None = None,
    section_alignment: int = 0x1_000,
    file_alignment: int = 0x200,
    size_of_image: int = 0x2_000,
    size_of_headers: int = 0x200,
    virtual_size: int = 0x180,
    virtual_address: int = 0x1_000,
    raw_size: int = 0x200,
    raw_offset: int = 0x200,
    section_characteristics: int = 0x6000_0020,
    total_size: int = 0x400,
) -> bytes:
    if bitness == 32:
        default_machine = 0x014C
        default_optional_size = 0xE0
        optional_fixed_size = 96
        directory_count_offset = 92
    else:
        default_machine = 0x8664
        default_optional_size = 0xF0
        optional_fixed_size = 112
        directory_count_offset = 108
    actual_machine = default_machine if machine is None else machine
    actual_optional_size = default_optional_size if optional_size is None else optional_size
    pe_offset = 0x80
    section_table_offset = pe_offset + 24 + actual_optional_size
    image = bytearray(total_size)
    image[:2] = b"MZ"
    image[0x3C:0x40] = pe_offset.to_bytes(4, "little")
    image[pe_offset : pe_offset + 4] = b"PE\0\0"
    image[pe_offset + 4 : pe_offset + 6] = actual_machine.to_bytes(2, "little")
    image[pe_offset + 6 : pe_offset + 8] = (1).to_bytes(2, "little")
    image[pe_offset + 20 : pe_offset + 22] = actual_optional_size.to_bytes(2, "little")
    image[pe_offset + 22 : pe_offset + 24] = (0x0002).to_bytes(2, "little")
    optional_offset = pe_offset + 24
    image[optional_offset : optional_offset + 2] = (0x010B if bitness == 32 else 0x020B).to_bytes(
        2, "little"
    )
    image[optional_offset + 16 : optional_offset + 20] = entry.to_bytes(4, "little")
    image[optional_offset + 32 : optional_offset + 36] = section_alignment.to_bytes(
        4,
        "little",
    )
    image[optional_offset + 36 : optional_offset + 40] = file_alignment.to_bytes(4, "little")
    image[optional_offset + 56 : optional_offset + 60] = size_of_image.to_bytes(4, "little")
    image[optional_offset + 60 : optional_offset + 64] = size_of_headers.to_bytes(4, "little")
    image[
        optional_offset + directory_count_offset : optional_offset + directory_count_offset + 4
    ] = directory_count.to_bytes(4, "little")
    selected_directories = dict(directories or {})
    if managed:
        selected_directories[14] = (0x1_100, 72)
    for index, (address, size) in selected_directories.items():
        directory_offset = optional_offset + optional_fixed_size + index * 8
        image[directory_offset : directory_offset + 4] = address.to_bytes(4, "little")
        image[directory_offset + 4 : directory_offset + 8] = size.to_bytes(4, "little")
    image[section_table_offset : section_table_offset + 5] = b".text"
    image[section_table_offset + 8 : section_table_offset + 12] = virtual_size.to_bytes(
        4,
        "little",
    )
    image[section_table_offset + 12 : section_table_offset + 16] = virtual_address.to_bytes(
        4,
        "little",
    )
    image[section_table_offset + 16 : section_table_offset + 20] = raw_size.to_bytes(
        4,
        "little",
    )
    image[section_table_offset + 20 : section_table_offset + 24] = raw_offset.to_bytes(
        4,
        "little",
    )
    image[section_table_offset + 36 : section_table_offset + 40] = section_characteristics.to_bytes(
        4, "little"
    )
    return bytes(image)


_SYNTHETIC_CASES = (
    (_elf(bitness=32, machine=0x03), NativeImageIdentity("elf", "x86", bitness=32)),
    (
        _elf(bitness=32, machine=0x28),
        NativeImageIdentity("elf", "arm", bitness=32),
    ),
    (_elf(bitness=64, machine=0x3E), NativeImageIdentity("elf", "x86_64", 64)),
    (_elf(bitness=64, machine=0xB7), NativeImageIdentity("elf", "aarch64", 64)),
    (
        _elf(bitness=64, machine=0x3E, image_type=2),
        NativeImageIdentity("elf", "x86_64", 64),
    ),
    (_pe(bitness=32), NativeImageIdentity("pe", "x86", bitness=32)),
    (_pe(bitness=64), NativeImageIdentity("pe", "x86_64", 64)),
)
_SYNTHETIC_IMAGES = tuple(image for image, _expected in _SYNTHETIC_CASES)


@pytest.mark.parametrize(
    ("image", "expected"),
    _SYNTHETIC_CASES,
)
def test_inspect_native_image_accepts_stripped_dynamic_and_executable_images(
    tmp_path: Path,
    image: bytes,
    expected: NativeImageIdentity,
) -> None:
    sample = tmp_path / "sample.bin"
    sample.write_bytes(image)

    assert inspect_native_image(sample) == expected


@pytest.mark.parametrize(
    ("name", "expected"),
    [
        ("debug_target_x86.exe", NativeImageIdentity("pe", "x86", 32)),
        ("debug_target_x64.exe", NativeImageIdentity("pe", "x86_64", 64)),
        ("il2cpp_elf_armv7.so", NativeImageIdentity("elf", "arm", 32)),
        ("il2cpp_elf_x86.so", NativeImageIdentity("elf", "x86", 32)),
        ("il2cpp_elf_x64.so", NativeImageIdentity("elf", "x86_64", 64)),
        ("il2cpp_pe_x86.dll", NativeImageIdentity("pe", "x86", 32)),
        ("il2cpp_pe_x64.dll", NativeImageIdentity("pe", "x86_64", 64)),
        ("native_elf_armv7.so", NativeImageIdentity("elf", "arm", 32)),
        ("native_elf_arm64.so", NativeImageIdentity("elf", "aarch64", 64)),
        ("native_elf_x86.so", NativeImageIdentity("elf", "x86", 32)),
        ("native_elf_x64.so", NativeImageIdentity("elf", "x86_64", 64)),
        ("native_pe_x86.dll", NativeImageIdentity("pe", "x86", 32)),
        ("native_pe_x64.dll", NativeImageIdentity("pe", "x86_64", 64)),
    ],
)
def test_inspect_native_image_accepts_all_hard_gate_fixtures(
    name: str,
    expected: NativeImageIdentity,
) -> None:
    assert inspect_native_image(FIXTURE_ROOT / name) == expected


@pytest.mark.parametrize(
    ("bitness", "expected"),
    [
        (32, NativeImageIdentity("pe", "x86", bitness=32)),
        (64, NativeImageIdentity("pe", "x86_64", 64)),
    ],
)
def test_pe_security_directory_uses_file_offset_not_rva(
    tmp_path: Path,
    bitness: Literal[32, 64],
    expected: NativeImageIdentity,
) -> None:
    sample = tmp_path / "signed.exe"
    sample.write_bytes(
        _pe(
            bitness=bitness,
            directories={4: (0x2_200, 0x80)},
            total_size=0x2_300,
        )
    )

    assert inspect_native_image(sample) == expected


def test_pe32_accepts_headers_smaller_than_file_alignment(tmp_path: Path) -> None:
    sample = tmp_path / "legacy-pe32.dll"
    sample.write_bytes(
        _pe(
            bitness=32,
            file_alignment=0x1000,
            size_of_headers=0x400,
            raw_offset=0x1000,
            raw_size=0x1000,
            total_size=0x2000,
        )
    )

    assert inspect_native_image(sample) == NativeImageIdentity("pe", "x86", 32)


def test_unsupported_error_lists_all_supported_native_images(tmp_path: Path) -> None:
    sample = tmp_path / "unknown.bin"
    sample.write_bytes(b"unknown")

    with pytest.raises(UnsupportedNativeImageError) as raised:
        inspect_native_image(sample)

    assert raised.value.details == {
        "detected": "unknown",
        "supported_images": [
            "elf32-arm-little",
            "elf32-x86-little",
            "elf64-aarch64-little",
            "elf64-x86_64-little",
            "pe32-x86-little",
            "pe32+-x86_64-little",
        ],
    }


@pytest.mark.parametrize(
    ("image", "detected"),
    [
        (
            b"#!/system/bin/sh\n" + b"\0" * 48 + _elf(bitness=64, machine=0xB7) + b"\x1f\x8b\x08",
            "shell_script",
        ),
        (b"\x1f\x8b\x08" + b"\0" * 64, "gzip"),
        (_elf(bitness=64, machine=0x28), "elf_machine_0x28"),
        (_elf(bitness=32, machine=0x3E), "elf_machine_0x3e"),
        (_elf(bitness=64, machine=0x3E, image_type=1), "unsupported_elf_type"),
        (
            _elf(bitness=32, machine=0x03, declared_header_size=64),
            "invalid_elf",
        ),
        (
            _elf(bitness=32, machine=0x03, declared_program_entry_size=56),
            "invalid_elf",
        ),
        (
            _elf(bitness=32, machine=0x03)[:5] + b"\x02" + _elf(bitness=32, machine=0x03)[6:],
            "elf_big_endian",
        ),
        (
            _elf(bitness=64, machine=0x3E, file_size=0, memory_size=0),
            "invalid_elf",
        ),
        (
            _elf(
                bitness=64,
                machine=0x3E,
                virtual_address=1,
                alignment=3,
            ),
            "invalid_elf",
        ),
        (
            _elf(
                bitness=64,
                machine=0x3E,
                virtual_address=0xFFFF_FFFF_FFFF_FFF0,
                file_size=120,
                memory_size=0x100,
                alignment=1,
            ),
            "invalid_elf",
        ),
        (
            _elf(
                bitness=32,
                machine=0x03,
                virtual_address=0xFFFF_FFF0,
                file_size=84,
                memory_size=0x100,
                alignment=1,
            ),
            "invalid_elf",
        ),
        (_elf(bitness=64, machine=0x3E, entry=0x1_000), "invalid_elf"),
        (_elf(bitness=32, machine=0x03, entry=52, flags=4), "invalid_elf"),
        (b"MZ" + b"\0" * 62, "invalid_pe"),
        (_pe(bitness=32, managed=True), "managed_runtime"),
        (_pe(bitness=32, machine=0x8664), "invalid_pe"),
        (_pe(bitness=64, machine=0x014C), "invalid_pe"),
        (_pe(bitness=32, optional_size=95, directory_count=0), "invalid_pe"),
        (_pe(bitness=64, optional_size=112, directory_count=14), "invalid_pe"),
        (_pe(bitness=32, optional_size=96, directory_count=1), "invalid_pe"),
        (_pe(bitness=64, directory_count=17), "invalid_pe"),
        (_pe(bitness=64, file_alignment=0x100), "invalid_pe"),
        (_pe(bitness=64, size_of_image=0x1_800), "invalid_pe"),
        (_pe(bitness=64, size_of_headers=0x300), "invalid_pe"),
        (_pe(bitness=64, raw_offset=0x201), "invalid_pe"),
        (_pe(bitness=64, virtual_address=0x2_000), "invalid_pe"),
        (_pe(bitness=32, section_characteristics=0x4000_0040), "invalid_pe"),
        (_pe(bitness=32, directories={1: (0x1_FF0, 0x20)}), "invalid_pe"),
        (_pe(bitness=32, directories={1: (0x1_100, 0)}), "invalid_pe"),
        (_pe(bitness=32, directories={4: (0x3F0, 0x20)}), "invalid_pe"),
        (b"\xcf\xfa\xed\xfe" + b"\0" * 64, "mach_o"),
        (b"raw firmware", "unknown"),
    ],
)
def test_inspect_native_image_rejects_ambiguous_or_malformed_inputs(
    tmp_path: Path,
    image: bytes,
    detected: str,
) -> None:
    sample = tmp_path / "sample.bin"
    sample.write_bytes(image)

    with pytest.raises(UnsupportedNativeImageError) as raised:
        inspect_native_image(sample)

    assert raised.value.detected == detected


def test_identification_uses_content_instead_of_extension(tmp_path: Path) -> None:
    native_with_script_suffix = tmp_path / "native.sh"
    native_with_script_suffix.write_bytes(_elf(bitness=32, machine=0x28))
    script_with_executable_suffix = tmp_path / "wrapper.exe"
    script_with_executable_suffix.write_bytes(b"#!/system/bin/sh\nexit 0\n")

    assert inspect_native_image(native_with_script_suffix) == NativeImageIdentity(
        "elf",
        "arm",
        bitness=32,
    )
    with pytest.raises(UnsupportedNativeImageError) as raised:
        inspect_native_image(script_with_executable_suffix)
    assert raised.value.detected == "shell_script"


@st.composite
def _truncated_native_images(draw: st.DrawFn) -> bytes:
    image = draw(st.sampled_from(_SYNTHETIC_IMAGES))
    end = draw(st.integers(min_value=0, max_value=len(image) - 1))
    return image[:end]


@given(image=_truncated_native_images())
def test_every_strict_prefix_of_a_supported_image_is_rejected(image: bytes) -> None:
    with TemporaryDirectory() as directory:
        sample = Path(directory) / "truncated.bin"
        sample.write_bytes(image)
        with pytest.raises(UnsupportedNativeImageError):
            inspect_native_image(sample)
