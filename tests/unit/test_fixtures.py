import hashlib
import struct
from pathlib import Path

FIXTURE_ROOT = Path(__file__).parents[1] / "fixtures" / "bin"


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def test_fixture_hash_manifest_matches_binaries() -> None:
    manifest_lines = (FIXTURE_ROOT / "SHA256SUMS").read_text(encoding="utf-8").splitlines()
    expected = {
        name: digest
        for digest, name in (line.split("  ", maxsplit=1) for line in manifest_lines if line)
    }

    binaries = sorted(
        path for path in FIXTURE_ROOT.iterdir() if path.is_file() and path.name != "SHA256SUMS"
    )
    assert expected == {path.name: _sha256(path) for path in binaries}


def test_fixture_formats_are_explicit() -> None:
    for name in ("native_pe_x64.dll", "debug_target_x64.exe", "il2cpp_pe_x64.dll"):
        assert (FIXTURE_ROOT / name).read_bytes().startswith(b"MZ")

    for name in ("native_elf_x64.so", "native_elf_arm64.so", "il2cpp_elf_x64.so"):
        assert (FIXTURE_ROOT / name).read_bytes().startswith(b"\x7fELF")

    metadata = (FIXTURE_ROOT / "il2cpp_metadata_fingerprint.bin").read_bytes()
    magic = b"IDA-RE-IL2CPP-METADATA\0"
    assert metadata.startswith(magic)
    source_size = struct.unpack_from("<I", metadata, len(magic))[0]
    digest_offset = len(magic) + 4
    source_offset = digest_offset + 32
    source = metadata[source_offset:]
    assert source_size == len(source)
    assert metadata[digest_offset:source_offset] == hashlib.sha256(source).digest()


def _pe_directory(path: Path, index: int) -> tuple[int, int]:
    data = path.read_bytes()
    pe_offset = struct.unpack_from("<I", data, 0x3C)[0]
    assert data[pe_offset : pe_offset + 4] == b"PE\0\0"
    optional = pe_offset + 24
    assert struct.unpack_from("<H", data, optional)[0] == 0x20B
    return struct.unpack_from("<II", data, optional + 112 + index * 8)


def test_pe_fixtures_contain_real_unwind_and_aslr_evidence() -> None:
    exception_rva, exception_size = _pe_directory(FIXTURE_ROOT / "native_pe_x64.dll", 3)
    relocation_rva, relocation_size = _pe_directory(
        FIXTURE_ROOT / "debug_target_x64.exe",
        5,
    )

    assert exception_rva > 0
    assert exception_size > 0
    assert relocation_rva > 0
    assert relocation_size > 0


def test_native_elf_fixtures_contain_tls_program_header() -> None:
    for name in ("native_elf_x64.so", "native_elf_arm64.so"):
        data = (FIXTURE_ROOT / name).read_bytes()
        assert data[4] == 2
        byte_order = "<" if data[5] == 1 else ">"
        program_offset = struct.unpack_from(f"{byte_order}Q", data, 32)[0]
        entry_size = struct.unpack_from(f"{byte_order}H", data, 54)[0]
        entry_count = struct.unpack_from(f"{byte_order}H", data, 56)[0]
        program_types = {
            struct.unpack_from(
                f"{byte_order}I",
                data,
                program_offset + entry_size * index,
            )[0]
            for index in range(entry_count)
        }
        assert 7 in program_types
