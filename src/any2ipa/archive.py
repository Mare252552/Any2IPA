"""Defensive, deliberately conservative ZIP / IPA handling.

All public operations reject links and portable-name ambiguities. Work in a
private directory on a trusted local filesystem; this is not an OS sandbox.
"""

from __future__ import annotations

import contextlib
import dataclasses
import hashlib
import os
from pathlib import Path
import plistlib
import re
import shutil
import stat
import struct
import tempfile
import unicodedata
import zipfile

from .errors import Any2IPAError

CHUNK = 1024 * 1024
PLIST_LIMIT = 4 * 1024 * 1024
_RESERVED = re.compile(r"^(CON|PRN|AUX|NUL|COM[1-9¹²³]|LPT[1-9¹²³])(?:\.|$)", re.I)


@dataclasses.dataclass(frozen=True)
class Limits:
    max_entries: int = 50000
    max_file_bytes: int = 2 * 1024**3
    max_total_bytes: int = 8 * 1024**3
    max_ratio: float = 1000.0
    max_archive_bytes: int = 8 * 1024**3

    def __post_init__(self):
        import math
        if any(v <= 0 for v in dataclasses.astuple(self)) or not math.isfinite(self.max_ratio):
            raise Any2IPAError("All limits must be positive and finite.")


def portable_parts(name: str) -> tuple[str, ...]:
    """Validate before using Path: Windows/ZIP separators must not reinterpret it."""
    if not name or len(name) > 1024 or "\\" in name or name.startswith("/"):
        raise Any2IPAError(f"Unsafe archive path: {name!r}")
    value = name[:-1] if name.endswith("/") else name
    parts = tuple(value.split("/"))
    if len(parts) > 64:
        raise Any2IPAError("Path nesting exceeds 64 components.")
    for part in parts:
        if (part in ("", ".", "..") or part.endswith((" ", "."))
                or any(ord(c) < 32 or ord(c) == 127 or c in '<>:"|?*' for c in part)
                or _RESERVED.match(part) or len(part.encode("utf-8")) > 255):
            raise Any2IPAError(f"Unsafe or non-portable path: {name!r}")
    return parts


def _key(parts):
    return tuple(unicodedata.normalize("NFC", p).casefold() for p in parts)


class _Names:
    def __init__(self):
        self.entries = set()
        self.components = {}
        self.kinds = {}

    def add(self, name: str, is_dir: bool):
        parts = portable_parts(name)
        key = _key(parts)
        if key in self.entries:
            raise Any2IPAError(f"Duplicate/colliding archive entry: {name!r}")
        self.entries.add(key)
        for n in range(1, len(parts) + 1):
            prefix, spelling = key[:n], parts[:n]
            if prefix in self.components and self.components[prefix] != spelling:
                raise Any2IPAError(f"Case/Unicode path collision: {name!r}")
            self.components[prefix] = spelling
            kind = "dir" if n < len(parts) or is_dir else "file"
            if prefix in self.kinds and self.kinds[prefix] != kind:
                raise Any2IPAError(f"File/directory path conflict: {name!r}")
            self.kinds[prefix] = kind
        return parts


def _reparse(st):
    return bool(getattr(st, "st_file_attributes", 0) & 0x400)


def regular_file(path: Path) -> Path:
    path = Path(os.path.abspath(path))
    st = path.lstat()
    if not stat.S_ISREG(st.st_mode) or _reparse(st):
        raise Any2IPAError(f"Expected a regular file, not a link or special file: {path}")
    return path


def _parent_target(path: Path) -> Path:
    # Resolve the parent only: resolving the leaf would follow a dangling symlink.
    path = Path(path)
    if not path.name or path.name in (".", ".."):
        raise Any2IPAError("Choose a new output path.")
    target = path.parent.resolve(strict=True) / path.name
    if not target.parent.is_dir():
        raise Any2IPAError("Output parent must be a directory.")
    if os.path.lexists(target):
        raise Any2IPAError(f"Output already exists; choose a new path: {target}")
    return target


def publish_file(source: Path, target: Path):
    """Publish without replacing an existing leaf, including dangling symlinks."""
    try:
        os.link(source, target)
    except FileExistsError:
        raise Any2IPAError(f"Output already exists: {target}") from None
    except OSError:
        # Filesystems without hardlinks still get exclusive creation and cleanup.
        created = False
        try:
            with target.open("xb") as out:
                created = True
                with source.open("rb") as inp:
                    shutil.copyfileobj(inp, out, CHUNK)
                out.flush()
                os.fsync(out.fileno())
        except BaseException:
            if created:
                target.unlink(missing_ok=True)
            raise


def _checked_entries(zf: zipfile.ZipFile, limits: Limits):
    entries = zf.infolist()
    if len(entries) > limits.max_entries:
        raise Any2IPAError("Archive entry count exceeds the configured limit.")
    total = 0
    names = _Names()
    for info in entries:
        # ZipInfo.filename silently truncates NUL; orig_filename retains it.
        if info.orig_filename != info.filename:
            raise Any2IPAError("NUL/truncated archive filename rejected.")
        names.add(info.filename, info.is_dir())
        mode = (info.external_attr >> 16) & 0xFFFF
        kind = stat.S_IFMT(mode)
        if kind not in (0, stat.S_IFREG, stat.S_IFDIR):
            raise Any2IPAError(f"Link/special archive entry rejected: {info.filename!r}")
        if ((kind == stat.S_IFDIR and not info.is_dir())
                or (kind == stat.S_IFREG and info.is_dir())):
            raise Any2IPAError(f"Inconsistent entry type: {info.filename!r}")
        if info.flag_bits & 1:
            raise Any2IPAError("Encrypted ZIP entries are unsupported.")
        if info.external_attr & 0x400:
            raise Any2IPAError("Windows reparse-point archive entry rejected.")
        if info.compress_type not in (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED):
            raise Any2IPAError("Only stored/deflated ZIP entries are supported.")
        if info.is_dir() and info.file_size:
            raise Any2IPAError("Directory entries must have no file data.")
        if info.file_size > limits.max_file_bytes:
            raise Any2IPAError(f"File exceeds size limit: {info.filename!r}")
        total += info.file_size
        if total > limits.max_total_bytes:
            raise Any2IPAError("Archive uncompressed size exceeds the configured limit.")
        if info.file_size / max(1, info.compress_size) > limits.max_ratio:
            raise Any2IPAError(f"Compression ratio exceeds limit: {info.filename!r}")
    return entries


def _copy_member(zf, info, out, limits):
    count = 0
    with zf.open(info, "r") as inp:
        while True:
            data = inp.read(CHUNK)
            if not data:
                break
            count += len(data)
            if count > info.file_size or count > limits.max_file_bytes:
                raise Any2IPAError("ZIP member expanded beyond its declared/allowed size.")
            if out is not None:
                out.write(data)
    if count != info.file_size:
        raise Any2IPAError("ZIP member size mismatch.")


def _metadata(zf, entries):
    apps = set()
    by_name = {i.filename: i for i in entries if not i.is_dir()}
    for info in entries:
        parts = portable_parts(info.filename)
        if len(parts) >= 2 and parts[0] == "Payload" and parts[1].endswith(".app"):
            apps.add(parts[1])
    if len(apps) != 1:
        raise Any2IPAError("IPA must contain exactly one Payload/<name>.app bundle.")
    app = "Payload/" + apps.pop()
    plist_name = app + "/Info.plist"
    if plist_name not in by_name or by_name[plist_name].file_size > PLIST_LIMIT:
        raise Any2IPAError("App Info.plist is missing or exceeds 4 MiB.")
    try:
        raw = zf.read(by_name[plist_name])
        # plistlib does not resolve XML external entities; reject internal ones too.
        if b"<!ENTITY" in raw.upper():
            raise ValueError("XML entity declarations are unsupported")
        plist = plistlib.loads(raw)
    except Exception as exc:
        raise Any2IPAError("Invalid app Info.plist.") from exc
    if not isinstance(plist, dict):
        raise Any2IPAError("Info.plist root must be a dictionary.")
    bundle_id, executable = plist.get("CFBundleIdentifier"), plist.get("CFBundleExecutable")
    if not isinstance(bundle_id, str) or not bundle_id.strip():
        raise Any2IPAError("Info.plist needs a nonempty CFBundleIdentifier.")
    if not isinstance(executable, str) or len(portable_parts(executable)) != 1:
        raise Any2IPAError("CFBundleExecutable must name a file inside the app.")
    if executable.endswith("/") or app + "/" + executable not in by_name:
        raise Any2IPAError("CFBundleExecutable file is missing.")
    for field in ("CFBundleDisplayName", "CFBundleName", "CFBundleVersion",
                  "CFBundleShortVersionString", "MinimumOSVersion"):
        if field in plist and not isinstance(plist[field], str):
            raise Any2IPAError(f"Info.plist {field} must be a string.")
    return {
        "app_path": app,
        "bundle_id": bundle_id,
        "executable": executable,
        "display_name": plist.get("CFBundleDisplayName", plist.get("CFBundleName")),
        "version": plist.get("CFBundleShortVersionString"),
        "build": plist.get("CFBundleVersion"),
        "minimum_os_version": plist.get("MinimumOSVersion"),
        "signature_resources_present": app + "/_CodeSignature/CodeResources" in by_name,
        "embedded_profile_present": app + "/embedded.mobileprovision" in by_name,
        "signature_verified": False,
    }


def _preflight(stream, limits):
    """Cap central-directory allocation BEFORE ZipFile parses it (ZIP64 too)."""
    stream.seek(0, 2)
    length = stream.tell()
    stream.seek(max(0, length - 65557))
    tail = stream.read()
    pos = tail.rfind(b"PK\x05\x06")
    if pos < 0 or pos + 22 > len(tail):
        raise Any2IPAError("Missing ZIP end record.")
    _, disk, cd_disk, disk_count, count, size, offset, comment = struct.unpack_from("<4s4H2LH", tail, pos)
    if pos + 22 + comment != len(tail) or disk or cd_disk or disk_count != count:
        raise Any2IPAError("Multi-volume ZIP or noncanonical trailing data rejected.")
    if count == 65535 or size == 0xFFFFFFFF or offset == 0xFFFFFFFF:
        absolute = length - len(tail) + pos
        if absolute < 20:
            raise Any2IPAError("Missing ZIP64 locator.")
        stream.seek(absolute - 20)
        locator = stream.read(20)
        signature, disk, record_offset, disks = struct.unpack("<4sLQL", locator)
        if signature != b"PK\x06\x07" or disk or disks != 1:
            raise Any2IPAError("Unsupported ZIP64 locator.")
        stream.seek(record_offset)
        record = stream.read(56)
        if len(record) != 56:
            raise Any2IPAError("Truncated ZIP64 record.")
        fields = struct.unpack("<4sQ2H2L4Q", record)
        if fields[0] != b"PK\x06\x06" or fields[1] != 44 or fields[4] or fields[5] or fields[6] != fields[7]:
            raise Any2IPAError("Unsupported ZIP64 end record.")
        count, size, offset = fields[7:10]
    if count > limits.max_entries or size > 32 * 1024**2:
        raise Any2IPAError("ZIP entry count or 32 MiB central-directory limit exceeded.")
    if offset + size > length:
        raise Any2IPAError("Invalid central-directory bounds.")
    stream.seek(0)


@contextlib.contextmanager
def _open_archive(path, limits):
    path = regular_file(Path(path))
    with path.open("rb") as stream:
        if os.fstat(stream.fileno()).st_size > limits.max_archive_bytes:
            raise Any2IPAError("Archive file size exceeds the configured limit.")
        _preflight(stream, limits)
        try:
            with zipfile.ZipFile(stream, "r") as zf:
                entries = _checked_entries(zf, limits)
                yield zf, entries
        except (zipfile.BadZipFile, zipfile.LargeZipFile, EOFError, RuntimeError,
                NotImplementedError) as exc:
            raise Any2IPAError(f"Invalid or unsupported ZIP archive: {exc}") from exc


def inspect_ipa(path: Path, limits: Limits = Limits()) -> dict:
    """Stream every entry to enforce CRC/size checks; never execute app content."""
    with _open_archive(path, limits) as (zf, entries):
        result = _metadata(zf, entries)
        for info in entries:
            _copy_member(zf, info, None, limits)
        result.update(entries=len(entries),
                      uncompressed_bytes=sum(i.file_size for i in entries),
                      compressed_bytes=sum(i.compress_size for i in entries))
        return result


def extract_ipa(path: Path, destination: Path, limits: Limits = Limits()) -> dict:
    target = _parent_target(destination)
    with tempfile.TemporaryDirectory(prefix=".any2ipa-", dir=target.parent) as temporary:
        root = Path(temporary) / "contents"
        root.mkdir(mode=0o700)
        with _open_archive(path, limits) as (zf, entries):
            result = _metadata(zf, entries)
            for info in entries:
                out = root.joinpath(*portable_parts(info.filename))
                if info.is_dir():
                    out.mkdir(parents=True, exist_ok=True)
                    _copy_member(zf, info, None, limits)
                else:
                    out.parent.mkdir(parents=True, exist_ok=True)
                    with out.open("xb") as stream:
                        _copy_member(zf, info, stream, limits)
                    # Drop setuid/setgid/sticky and group/world writes.
                    mode = (info.external_attr >> 16) & 0o777
                    os.chmod(out, 0o755 if mode & 0o111 else 0o644)
            os.chmod(root / result["app_path"] / result["executable"], 0o755)
        # Existing nonempty directories and files cannot be replaced. Protect
        # against an accidental overwrite; concurrent hostile writers unsupported.
        if os.path.lexists(target):
            raise Any2IPAError(f"Output already exists: {target}")
        root.rename(target)
    result["destination"] = str(target)
    return result


def _tree(source: Path, limits: Limits):
    source = Path(os.path.abspath(source))
    st = source.lstat()
    if not stat.S_ISDIR(st.st_mode) or _reparse(st):
        raise Any2IPAError("Pack source must be a real directory, not a link.")
    # Both an extracted IPA root and a standalone .app are accepted.
    prefix = ("Payload", source.name) if source.name.endswith(".app") else ()
    result, names, total = [], _Names(), 0

    def visit(folder, relative):
        nonlocal total
        with os.scandir(folder) as items:
            children = sorted(items, key=lambda entry: entry.name)
        for entry in children:
            # DirEntry's cached Windows stat may omit a file ID. Use lstat so
            # the later fstat identity comparison uses the same information.
            st = Path(entry.path).lstat()
            if _reparse(st) or not (stat.S_ISREG(st.st_mode) or stat.S_ISDIR(st.st_mode)):
                raise Any2IPAError(f"Link/reparse/special source rejected: {entry.path}")
            parts = relative + (entry.name,)
            is_dir = stat.S_ISDIR(st.st_mode)
            name = "/".join(parts) + ("/" if is_dir else "")
            names.add(name, is_dir)
            if len(result) >= limits.max_entries:
                raise Any2IPAError("Source entry count exceeds limit.")
            if not is_dir:
                total += st.st_size
                if st.st_size > limits.max_file_bytes or total > limits.max_total_bytes:
                    raise Any2IPAError("Source size exceeds configured limits.")
            result.append((Path(entry.path), name, st, is_dir))
            if is_dir:
                visit(Path(entry.path), parts)

    if prefix:
        names.add("Payload/" + source.name + "/", True)
        result.append((source, "Payload/" + source.name + "/", st, True))
    visit(source, prefix)
    return source, result


def _zip_tree(source: Path, output: Path, limits: Limits, level: int):
    _, items = _tree(source, limits)
    executables = set()
    for path, name, original, is_dir in items:
        if not is_dir and path.name == "Info.plist" and original.st_size <= PLIST_LIMIT:
            try:
                raw = path.read_bytes()
                if b"<!ENTITY" in raw.upper():
                    continue
                value = plistlib.loads(raw)
                exe = value.get("CFBundleExecutable") if isinstance(value, dict) else None
                if isinstance(exe, str) and len(portable_parts(exe)) == 1:
                    executables.add(name.rsplit("/", 1)[0] + "/" + exe)
            except (ValueError, plistlib.InvalidFileException):
                pass
    with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_DEFLATED,
                         compresslevel=level, allowZip64=True) as zf:
        for path, name, original, is_dir in items:
            info = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
            info.create_system = 3
            perms = 0o755 if is_dir or original.st_mode & 0o111 or name in executables else 0o644
            info.external_attr = ((stat.S_IFDIR if is_dir else stat.S_IFREG) | perms) << 16
            info.compress_type = zipfile.ZIP_DEFLATED
            # ZipInfo's public compression_level setter was added in Python 3.13.
            info._compresslevel = level
            if is_dir:
                info.external_attr |= 0x10
                zf.writestr(info, b"")
                continue
            current = path.lstat()
            if _reparse(current) or not stat.S_ISREG(current.st_mode):
                raise Any2IPAError("Source changed into a link/special file during packing.")
            flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
            fd = os.open(path, flags)
            with os.fdopen(fd, "rb") as inp:
                opened = os.fstat(inp.fileno())
                if ((opened.st_dev, opened.st_ino, opened.st_size, opened.st_mtime_ns)
                        != (original.st_dev, original.st_ino, original.st_size, original.st_mtime_ns)):
                    raise Any2IPAError("Source changed during packing; retry with a stable copy.")
                if inp.read(4) in (b"\xcf\xfa\xed\xfe", b"\xce\xfa\xed\xfe", b"\xfe\xed\xfa\xcf", b"\xfe\xed\xfa\xce", b"\xca\xfe\xba\xbe", b"\xbe\xba\xfe\xca", b"\xca\xfe\xba\xbf", b"\xbf\xba\xfe\xca"):
                    info.external_attr = (stat.S_IFREG | 0o755) << 16
                inp.seek(0)
                info.file_size = original.st_size
                count = 0
                with zf.open(info, "w", force_zip64=True) as out:
                    while True:
                        data = inp.read(CHUNK)
                        if not data:
                            break
                        count += len(data)
                        if count > original.st_size:
                            raise Any2IPAError("Source grew during packing.")
                        out.write(data)
                if count != original.st_size or os.fstat(inp.fileno()).st_mtime_ns != original.st_mtime_ns:
                    raise Any2IPAError("Source changed during packing.")


def pack_ipa(source: Path, output: Path, limits: Limits = Limits(), level: int = 6) -> dict:
    if not 0 <= level <= 9:
        raise Any2IPAError("Compression level must be 0 through 9.")
    source, _ = _tree(source, limits)
    target = _parent_target(output)
    if target.is_relative_to(source.resolve()):
        raise Any2IPAError("Output must be outside the source tree.")
    with tempfile.TemporaryDirectory(prefix=".any2ipa-", dir=target.parent) as temporary:
        staged = Path(temporary) / "packed.ipa"
        _zip_tree(source, staged, limits, level)
        result = inspect_ipa(staged, limits)
        publish_file(staged, target)
    result["output"] = str(target)
    result["warning"] = "Repacking does not create or verify an Apple code signature."
    return result


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with Path(path).open("rb") as inp:
        for block in iter(lambda: inp.read(CHUNK), b""):
            digest.update(block)
    return digest.hexdigest()
