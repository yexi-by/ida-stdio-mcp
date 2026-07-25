from __future__ import annotations

from pathlib import Path
from tempfile import TemporaryDirectory

import pytest
from hypothesis import given
from hypothesis import strategies as st

from ida_re_mcp.supervisor.native_formats import (
    NativeImageIdentity,
    UnsupportedNativeImageError,
    inspect_native_image,
)

FIXTURE_ROOT = Path(__file__).parents[1] / "fixtures" / "bin"


def _elf64(
    *,
    machine: int,
    image_type: int = 3,
    entry: int | None = None,
    flags: int = 5,
    file_offset: int = 0,
    virtual_address: int = 0,
    file_size: int | None = None,
    memory_size: int | None = None,
    alignment: int = 0x1_000,
) -> bytes:
    image = bytearray(120)
    actual_file_size = len(image) if file_size is None else file_size
    actual_memory_size = actual_file_size if memory_size is None else memory_size
    actual_entry = 64 if entry is None and image_type == 2 else entry or 0
    image[:4] = b"\x7fELF"
    image[4] = 2
    image[5] = 1
    image[6] = 1
    image[16:18] = image_type.to_bytes(2, "little")
    image[18:20] = machine.to_bytes(2, "little")
    image[20:24] = (1).to_bytes(4, "little")
    image[24:32] = actual_entry.to_bytes(8, "little")
    image[32:40] = (64).to_bytes(8, "little")
    image[52:54] = (64).to_bytes(2, "little")
    image[54:56] = (56).to_bytes(2, "little")
    image[56:58] = (1).to_bytes(2, "little")
    image[64:68] = (1).to_bytes(4, "little")
    image[68:72] = flags.to_bytes(4, "little")
    image[72:80] = file_offset.to_bytes(8, "little")
    image[80:88] = virtual_address.to_bytes(8, "little")
    image[96:104] = actual_file_size.to_bytes(8, "little")
    image[104:112] = actual_memory_size.to_bytes(8, "little")
    image[112:120] = alignment.to_bytes(8, "little")
    return bytes(image)


def _pe32_plus(
    *,
    managed: bool = False,
    entry: int = 0x1_000,
    optional_size: int = 0xF0,
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
    pe_offset = 0x80
    section_table_offset = pe_offset + 24 + optional_size
    image = bytearray(total_size)
    image[:2] = b"MZ"
    image[0x3C:0x40] = pe_offset.to_bytes(4, "little")
    image[pe_offset : pe_offset + 4] = b"PE\0\0"
    image[pe_offset + 4 : pe_offset + 6] = (0x8664).to_bytes(2, "little")
    image[pe_offset + 6 : pe_offset + 8] = (1).to_bytes(2, "little")
    image[pe_offset + 20 : pe_offset + 22] = optional_size.to_bytes(2, "little")
    image[pe_offset + 22 : pe_offset + 24] = (0x0002).to_bytes(2, "little")
    optional_offset = pe_offset + 24
    image[optional_offset : optional_offset + 2] = b"\x0b\x02"
    image[optional_offset + 16 : optional_offset + 20] = entry.to_bytes(4, "little")
    image[optional_offset + 32 : optional_offset + 36] = section_alignment.to_bytes(
        4,
        "little",
    )
    image[optional_offset + 36 : optional_offset + 40] = file_alignment.to_bytes(4, "little")
    image[optional_offset + 56 : optional_offset + 60] = size_of_image.to_bytes(4, "little")
    image[optional_offset + 60 : optional_offset + 64] = size_of_headers.to_bytes(4, "little")
    image[optional_offset + 108 : optional_offset + 112] = directory_count.to_bytes(
        4,
        "little",
    )
    selected_directories = dict(directories or {})
    if managed:
        selected_directories[14] = (0x1_100, 72)
    for index, (address, size) in selected_directories.items():
        directory_offset = optional_offset + 112 + index * 8
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


_SYNTHETIC_IMAGES = (
    _elf64(machine=0x3E),
    _elf64(machine=0xB7),
    _elf64(machine=0x3E, image_type=2),
    _pe32_plus(),
)


@pytest.mark.parametrize(
    ("image", "expected"),
    [
        (_SYNTHETIC_IMAGES[0], NativeImageIdentity("elf", "x86_64")),
        (_SYNTHETIC_IMAGES[1], NativeImageIdentity("elf", "aarch64")),
        (_SYNTHETIC_IMAGES[2], NativeImageIdentity("elf", "x86_64")),
        (_SYNTHETIC_IMAGES[3], NativeImageIdentity("pe", "x86_64")),
    ],
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
        ("debug_target_x64.exe", NativeImageIdentity("pe", "x86_64")),
        ("il2cpp_elf_x64.so", NativeImageIdentity("elf", "x86_64")),
        ("il2cpp_pe_x64.dll", NativeImageIdentity("pe", "x86_64")),
        ("native_elf_arm64.so", NativeImageIdentity("elf", "aarch64")),
        ("native_elf_x64.so", NativeImageIdentity("elf", "x86_64")),
        ("native_pe_x64.dll", NativeImageIdentity("pe", "x86_64")),
    ],
)
def test_inspect_native_image_accepts_all_hard_gate_fixtures(
    name: str,
    expected: NativeImageIdentity,
) -> None:
    assert inspect_native_image(FIXTURE_ROOT / name) == expected


def test_pe_security_directory_uses_file_offset_not_rva(tmp_path: Path) -> None:
    sample = tmp_path / "signed.exe"
    sample.write_bytes(
        _pe32_plus(
            directories={4: (0x2_200, 0x80)},
            total_size=0x2_300,
        )
    )

    assert inspect_native_image(sample) == NativeImageIdentity("pe", "x86_64")


@pytest.mark.parametrize(
    ("image", "detected"),
    [
        (
            b"#!/system/bin/sh\n" + b"\0" * 48 + _elf64(machine=0xB7) + b"\x1f\x8b\x08",
            "shell_script",
        ),
        (b"\x1f\x8b\x08" + b"\0" * 64, "gzip"),
        (_elf64(machine=0x28), "elf_machine_0x28"),
        (_elf64(machine=0x3E, image_type=1), "unsupported_elf_type"),
        (
            _elf64(machine=0x3E)[:5] + b"\x02" + _elf64(machine=0x3E)[6:],
            "elf_big_endian",
        ),
        (_elf64(machine=0x3E, file_size=0, memory_size=0), "invalid_elf"),
        (
            _elf64(
                machine=0x3E,
                virtual_address=1,
                alignment=3,
            ),
            "invalid_elf",
        ),
        (
            _elf64(
                machine=0x3E,
                virtual_address=0xFFFF_FFFF_FFFF_FFF0,
                file_size=120,
                memory_size=0x100,
                alignment=1,
            ),
            "invalid_elf",
        ),
        (_elf64(machine=0x3E, entry=0x1_000), "invalid_elf"),
        (_elf64(machine=0x3E, entry=64, flags=4), "invalid_elf"),
        (b"MZ" + b"\0" * 62, "invalid_pe"),
        (_pe32_plus(managed=True), "managed_runtime"),
        (_pe32_plus(optional_size=112, directory_count=14), "invalid_pe"),
        (_pe32_plus(directory_count=17), "invalid_pe"),
        (_pe32_plus(file_alignment=0x100), "invalid_pe"),
        (_pe32_plus(size_of_image=0x1_800), "invalid_pe"),
        (_pe32_plus(size_of_headers=0x300), "invalid_pe"),
        (_pe32_plus(raw_offset=0x201), "invalid_pe"),
        (_pe32_plus(virtual_address=0x2_000), "invalid_pe"),
        (_pe32_plus(section_characteristics=0x4000_0040), "invalid_pe"),
        (_pe32_plus(directories={1: (0x1_FF0, 0x20)}), "invalid_pe"),
        (_pe32_plus(directories={1: (0x1_100, 0)}), "invalid_pe"),
        (_pe32_plus(directories={4: (0x3F0, 0x20)}), "invalid_pe"),
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
    native_with_script_suffix.write_bytes(_elf64(machine=0x3E))
    script_with_executable_suffix = tmp_path / "wrapper.exe"
    script_with_executable_suffix.write_bytes(b"#!/system/bin/sh\nexit 0\n")

    assert inspect_native_image(native_with_script_suffix) == NativeImageIdentity(
        "elf",
        "x86_64",
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
