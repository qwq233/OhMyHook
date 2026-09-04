#!/usr/bin/env python3

import argparse
import gzip
import io
import json
import os
import shutil
import stat
import struct
import subprocess
import sys
import tarfile
import tempfile
import urllib.request
from pathlib import Path


ALPINE_REL = "latest-stable"
ALPINE = f"https://dl-cdn.alpinelinux.org/alpine/{ALPINE_REL}"
CACHE = Path(os.environ.get("TEMP") or os.environ.get("TMPDIR") or "/tmp") / "omhook-qemu-cache"
REPO = Path(__file__).resolve().parent.parent

TARGETS = {
    "i686-unknown-linux-gnu": {
        "alpine": "x86_64",
        "qemu": "qemu-system-x86_64",
        "machine": [],
        "console": "ttyS0",
        "linker": "gcc",
        "rustflags": ["-C", "link-arg=-m32"],
        "lib_dirs": [
            "/usr/lib32",
            "/lib32",
            "/usr/i686-linux-gnu/lib",
            "/usr/lib/i386-linux-gnu",
            "/lib/i386-linux-gnu",
            "/usr/i686-linux-gnu",
        ],
    },
    "armv7-unknown-linux-gnueabihf": {
        "alpine": "armv7",
        "qemu": "qemu-system-arm",
        "machine": ["-M", "virt", "-cpu", "cortex-a15"],
        "console": "ttyAMA0",
        "linker": "arm-linux-gnueabihf-gcc",
        "linker_fallbacks": [
            str(
                CACHE
                / "bootlin/armv7-eabihf--glibc--stable-2024.05-1/bin/arm-buildroot-linux-gnueabihf-gcc"
            ),
        ],
        "kernel": "virt-apk",
        "rustflags": [],
        "lib_dirs": [
            "/usr/arm-linux-gnueabihf/lib",
            "/usr/lib/arm-linux-gnueabihf",
            "/lib/arm-linux-gnueabihf",
            "/usr/arm-linux-gnueabihf",
            str(
                CACHE
                / "bootlin/armv7-eabihf--glibc--stable-2024.05-1/arm-buildroot-linux-gnueabihf/sysroot/lib"
            ),
            str(
                CACHE
                / "bootlin/armv7-eabihf--glibc--stable-2024.05-1/arm-buildroot-linux-gnueabihf/sysroot/usr/lib"
            ),
        ],
    },
    "aarch64-unknown-linux-gnu": {
        "alpine": "aarch64",
        "qemu": "qemu-system-aarch64",
        "machine": ["-M", "virt", "-cpu", "max"],
        "console": "ttyAMA0",
        "linker": "aarch64-linux-gnu-gcc",
        "linker_fallbacks": [
            str(
                CACHE
                / "bootlin/aarch64--glibc--stable-2024.05-1/bin/aarch64-buildroot-linux-gnu-gcc"
            ),
            str(CACHE / "bootlin/aarch64--glibc--stable-2024.05-1/bin/aarch64-linux-gcc"),
        ],
        "rustflags": [],
        "lib_dirs": [
            "/usr/aarch64-linux-gnu/lib",
            "/usr/lib/aarch64-linux-gnu",
            "/lib/aarch64-linux-gnu",
            str(
                CACHE
                / "bootlin/aarch64--glibc--stable-2024.05-1/aarch64-buildroot-linux-gnu/sysroot/lib"
            ),
            str(
                CACHE
                / "bootlin/aarch64--glibc--stable-2024.05-1/aarch64-buildroot-linux-gnu/sysroot/usr/lib"
            ),
        ],
    },
}

INIT = """#!/busybox sh
/busybox mkdir -p /proc /sys /dev
/busybox mount -t proc proc /proc
/busybox mount -t sysfs sysfs /sys
/busybox mount -t devtmpfs devtmpfs /dev
/omhook_test --test-threads=1
echo OMHOOK_EXIT:$?
/busybox reboot -f
"""


def qemu_bin(name: str) -> str:
    found = shutil.which(name) or shutil.which(f"{name}.exe")
    if found:
        return found
    for root in (
        Path(r"C:\Program Files\qemu"),
        Path(r"C:\Program Files\QEMU"),
        Path("/mnt/c/Program Files/qemu"),
        Path("/mnt/c/Program Files/QEMU"),
    ):
        candidate = root / f"{name}.exe"
        if candidate.is_file():
            return str(candidate)
    raise FileNotFoundError(name)


def qemu_path(qemu: str, path: Path) -> str:
    if qemu.endswith(".exe") and os.name != "nt":
        return subprocess.check_output(["wslpath", "-w", str(path)], text=True).strip()
    return str(path)


def download(url: str, dest: Path) -> None:
    dest.parent.mkdir(parents=True, exist_ok=True)
    size = None
    try:
        with urllib.request.urlopen(urllib.request.Request(url, method="HEAD")) as resp:
            size = resp.headers.get("Content-Length")
    except OSError:
        pass
    if dest.is_file() and dest.stat().st_size and (
        size is None or int(size) == dest.stat().st_size
    ):
        return
    tmp = dest.with_suffix(dest.suffix + ".part")
    urllib.request.urlretrieve(url, tmp)
    tmp.replace(dest)


def alpine_pkg_ver(arch: str, pkg: str) -> str:
    data = urllib.request.urlopen(f"{ALPINE}/main/{arch}/APKINDEX.tar.gz").read()
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as tar:
        idx = tar.extractfile("APKINDEX")
        if idx is None:
            raise FileNotFoundError("APKINDEX")
        text = idx.read().decode()
    cur: dict[str, str] = {}
    for line in text.splitlines():
        if not line:
            if cur.get("P") == pkg:
                return cur["V"]
            cur = {}
            continue
        if len(line) > 1 and line[1] == ":":
            cur[line[0]] = line[2:]
    raise FileNotFoundError(pkg)


def alpine_minirootfs(arch: str) -> Path:
    text = urllib.request.urlopen(
        f"{ALPINE}/releases/{arch}/latest-releases.yaml"
    ).read().decode()
    fname = next(
        (
            line.split(":", 1)[1].strip()
            for line in text.splitlines()
            if line.strip().startswith("file:") and "minirootfs" in line
        ),
        None,
    )
    if not fname:
        raise FileNotFoundError(f"minirootfs {arch}")
    dest = CACHE / arch / fname
    download(f"{ALPINE}/releases/{arch}/{fname}", dest)
    return dest


def fetch_kernel(spec: dict) -> Path:
    arch = spec["alpine"]
    if spec.get("kernel") == "virt-apk":
        ver = alpine_pkg_ver(arch, "linux-virt")
        kernel = CACHE / arch / f"vmlinuz-virt-{ver}"
        if kernel.is_file() and kernel.stat().st_size:
            return kernel
        apk = CACHE / arch / f"linux-virt-{ver}.apk"
        download(f"{ALPINE}/main/{arch}/linux-virt-{ver}.apk", apk)
        with tarfile.open(apk, "r:gz") as tar:
            fileobj = tar.extractfile("boot/vmlinuz-virt")
            if fileobj is None:
                raise FileNotFoundError("boot/vmlinuz-virt")
            kernel.write_bytes(fileobj.read())
        return kernel
    kernel = CACHE / arch / "vmlinuz-virt"
    download(f"{ALPINE}/releases/{arch}/netboot/vmlinuz-virt", kernel)
    return kernel


def resolve_linker(target: str, spec: dict) -> str:
    triple = target.upper().replace("-", "_")
    env_val = os.environ.get(f"CARGO_TARGET_{triple}_LINKER")
    if env_val:
        return env_val
    found = shutil.which(spec["linker"])
    if found:
        return found
    for cand in spec.get("linker_fallbacks", []):
        path = Path(cand)
        if path.is_file():
            return str(path)
        found = shutil.which(cand)
        if found:
            return found
    raise FileNotFoundError(spec["linker"])


def pad4(buf: bytearray) -> None:
    buf.extend(b"\0" * ((4 - (len(buf) % 4)) % 4))


def cpio_entry(name: str, data: bytes, mode: int) -> bytes:
    name_b = name.encode("utf-8") + b"\0"
    header = bytearray(b"070701")
    fields = (0, mode, 0, 0, 1, 0, len(data), 0, 0, 0, 0, len(name_b), 0)
    header.extend("".join(f"{value:08x}" for value in fields).encode("ascii"))
    header.extend(name_b)
    pad4(header)
    header.extend(data)
    pad4(header)
    return bytes(header)


def elf_interp_and_needed(path: Path) -> tuple[str, list[str]]:
    data = path.read_bytes()
    if data[:4] != b"\x7fELF":
        raise ValueError(f"not ELF: {path}")
    bits = data[4]
    if data[5] != 1:
        raise ValueError("big-endian ELF")
    if bits == 1:
        e_phoff = struct.unpack_from("<I", data, 28)[0]
        e_phentsize, e_phnum = struct.unpack_from("<HH", data, 42)
        load, interp, dyn = [], None, None
        for index in range(e_phnum):
            off = e_phoff + index * e_phentsize
            p_type, p_offset, p_vaddr, _, p_filesz, _, _, _ = struct.unpack_from(
                "<IIIIIIII", data, off
            )
            if p_type == 1:
                load.append((p_vaddr, p_offset, p_filesz))
            elif p_type == 3:
                interp = data[p_offset : p_offset + p_filesz].split(b"\0", 1)[0].decode()
            elif p_type == 2:
                dyn = (p_offset, p_filesz)
        def v2f(v):
            for vaddr, offset, filesz in load:
                if vaddr <= v < vaddr + filesz:
                    return offset + (v - vaddr)
            raise ValueError("vaddr")
        needed = []
        if dyn:
            entries = dyn[1] // 8
            strtab = None
            tags = [
                struct.unpack_from("<II", data, dyn[0] + i * 8) for i in range(entries)
            ]
            for tag, val in tags:
                if tag == 5:
                    strtab = v2f(val)
            if strtab is not None:
                for tag, val in tags:
                    if tag == 1:
                        end = data.index(b"\0", strtab + val)
                        needed.append(data[strtab + val : end].decode())
        return interp or "", needed
    if bits == 2:
        e_phoff = struct.unpack_from("<Q", data, 32)[0]
        e_phentsize, e_phnum = struct.unpack_from("<HH", data, 54)
        load, interp, dyn = [], None, None
        for index in range(e_phnum):
            off = e_phoff + index * e_phentsize
            p_type, _, p_offset, p_vaddr, _, p_filesz, _, _ = struct.unpack_from(
                "<IIQQQQQQ", data, off
            )
            if p_type == 1:
                load.append((p_vaddr, p_offset, p_filesz))
            elif p_type == 3:
                interp = data[p_offset : p_offset + p_filesz].split(b"\0", 1)[0].decode()
            elif p_type == 2:
                dyn = (p_offset, p_filesz)
        def v2f64(v):
            for vaddr, offset, filesz in load:
                if vaddr <= v < vaddr + filesz:
                    return offset + (v - vaddr)
            raise ValueError("vaddr")
        needed = []
        if dyn:
            entries = dyn[1] // 16
            strtab = None
            tags = [
                struct.unpack_from("<QQ", data, dyn[0] + i * 16) for i in range(entries)
            ]
            for tag, val in tags:
                if tag == 5:
                    strtab = v2f64(val)
            if strtab is not None:
                for tag, val in tags:
                    if tag == 1:
                        end = data.index(b"\0", strtab + val)
                        needed.append(data[strtab + val : end].decode())
        return interp or "", needed
    raise ValueError("ELF class")


def resolve_lib(name: str, dirs: list[str]) -> Path:
    if name.startswith("/"):
        direct = Path(name)
        if direct.is_file():
            return direct
        name = Path(name).name
    for directory in dirs:
        candidate = Path(directory) / name
        if candidate.is_file() or candidate.is_symlink():
            return candidate
    raise FileNotFoundError(name)


def collect_libs(binary: Path, dirs: list[str]) -> dict[str, bytes]:
    files: dict[str, bytes] = {}
    pending = []
    interp, needed = elf_interp_and_needed(binary)
    if interp:
        pending.append(interp)
    pending.extend(needed)
    seen = set()
    while pending:
        name = pending.pop()
        if name in seen:
            continue
        seen.add(name)
        path = resolve_lib(name, dirs)
        guest = path.as_posix().lstrip("/")
        files[guest] = path.read_bytes()
        files[f"lib/{Path(name).name}"] = files[guest]
        files[f"lib64/{Path(name).name}"] = files[guest]
        if path.is_symlink():
            target = Path(os.path.join(path.parent, os.readlink(path))).resolve()
            if target.is_file():
                files[target.as_posix().lstrip("/")] = target.read_bytes()
                files[f"lib/{target.name}"] = target.read_bytes()
                files[f"lib64/{target.name}"] = target.read_bytes()
        try:
            _, more = elf_interp_and_needed(path if not path.is_symlink() else path.resolve())
            pending.extend(more)
        except (ValueError, FileNotFoundError, OSError):
            continue
    return files


def busybox_from_alpine(rootfs_tar: Path) -> bytes:
    with tarfile.open(rootfs_tar, "r:gz") as tar:
        for member in tar:
            name = member.name.lstrip("./")
            if name == "bin/busybox" and member.isfile():
                fileobj = tar.extractfile(member)
                if fileobj:
                    return fileobj.read()
    raise FileNotFoundError("alpine busybox")


def alpine_musl_libs(rootfs_tar: Path) -> dict[str, bytes]:
    files: dict[str, bytes] = {}
    with tarfile.open(rootfs_tar, "r:gz") as tar:
        for member in tar:
            name = member.name.lstrip("./")
            if not name.startswith("lib/") or not member.isfile():
                continue
            if "ld-musl" in name or name.endswith("libc.musl-i386.so.1") or "musl" in name:
                fileobj = tar.extractfile(member)
                if fileobj:
                    files[name] = fileobj.read()
            if member.issym() and "musl" in name:
                files[name] = os.fsencode(member.linkname)
    return files


def build_test(target: str) -> Path:
    spec = TARGETS[target]
    env = os.environ.copy()
    triple = target.upper().replace("-", "_")
    linker_key = f"CARGO_TARGET_{triple}_LINKER"
    linker = resolve_linker(target, spec)
    env[linker_key] = linker
    if spec["rustflags"] and Path(linker).name in ("gcc", "gcc.exe"):
        env["CARGO_ENCODED_RUSTFLAGS"] = "\x1f".join(spec["rustflags"])
    env.setdefault("CARGO_TARGET_DIR", "/tmp/omhook-gnu-test")
    proc = subprocess.run(
        [
            "cargo",
            "test",
            "--target",
            target,
            "--workspace",
            "--lib",
            "--tests",
            "--no-run",
            "--message-format=json",
        ],
        cwd=REPO,
        env=env,
        check=True,
        stdout=subprocess.PIPE,
        text=True,
    )
    executable = None
    for line in proc.stdout.splitlines():
        try:
            msg = json.loads(line)
        except json.JSONDecodeError:
            continue
        path = msg.get("executable")
        if path:
            executable = Path(path)
    if executable is None:
        raise RuntimeError("cargo did not emit a test executable")
    return executable


def pack_initrd(binary: Path, libs: dict[str, bytes], busybox: bytes, dest: Path) -> None:
    blob = bytearray()
    dirs = {"proc", "sys", "dev", "lib", "usr", "usr/lib"}
    for guest in libs:
        parent = str(Path(guest).parent)
        while parent not in (".", "", "/"):
            dirs.add(parent)
            parent = str(Path(parent).parent)
    for directory in sorted(dirs):
        blob.extend(cpio_entry(directory, b"", stat.S_IFDIR | 0o755))
    blob.extend(cpio_entry("busybox", busybox, stat.S_IFREG | 0o755))
    init = INIT.replace(
        "/omhook_test",
        "export LD_LIBRARY_PATH=/lib:/lib64\n/omhook_test",
        1,
    )
    blob.extend(cpio_entry("init", init.encode("ascii"), stat.S_IFREG | 0o755))
    blob.extend(cpio_entry("omhook_test", binary.read_bytes(), stat.S_IFREG | 0o755))
    for guest, data in libs.items():
        blob.extend(cpio_entry(guest, data, stat.S_IFREG | 0o755))
    blob.extend(cpio_entry("TRAILER!!!", b"", 0))
    dest.write_bytes(gzip.compress(bytes(blob)))


def run_qemu(target: str, kernel: Path, initrd: Path) -> int:
    spec = TARGETS[target]
    qemu = qemu_bin(spec["qemu"])
    cmd = [
        qemu,
        "-nographic",
        "-no-reboot",
        "-m",
        "512",
        "-smp",
        "1",
        *spec["machine"],
        "-kernel",
        qemu_path(qemu, kernel),
        "-initrd",
        qemu_path(qemu, initrd),
        "-append",
        f"console={spec['console']} panic=1 rdinit=/init",
    ]
    fd, name = tempfile.mkstemp(prefix="omhook-qemu-", suffix=".log")
    os.close(fd)
    log_path = Path(name)
    try:
        with log_path.open("wb") as log:
            try:
                proc = subprocess.run(
                    cmd, cwd=REPO, stdout=log, stderr=subprocess.STDOUT, timeout=180
                )
            except subprocess.TimeoutExpired:
                sys.stdout.write(log_path.read_text(encoding="utf-8", errors="replace"))
                return 1
        text = log_path.read_text(encoding="utf-8", errors="replace")
        sys.stdout.write(text)
        (REPO / "target").mkdir(exist_ok=True)
        (REPO / "target" / "qemu-last.log").write_text(text, encoding="utf-8", errors="replace")
        for line in text.splitlines():
            if line.startswith("OMHOOK_EXIT:"):
                return int(line.split(":", 1)[1])
        return proc.returncode or 1
    finally:
        try:
            log_path.unlink(missing_ok=True)
        except OSError:
            pass


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--target", required=True, choices=sorted(TARGETS))
    args = parser.parse_args()
    spec = TARGETS[args.target]
    arch = spec["alpine"]
    kernel = fetch_kernel(spec)
    rootfs = alpine_minirootfs(arch)
    test_bin = build_test(args.target)
    interp, _ = elf_interp_and_needed(test_bin)
    if "musl" in interp:
        raise SystemExit(f"refusing musl test binary: {interp}")
    libs = collect_libs(test_bin, spec["lib_dirs"])
    busybox = busybox_from_alpine(rootfs)
    musl = alpine_musl_libs(rootfs)
    libs.update(musl)
    with tempfile.TemporaryDirectory() as tmp:
        initrd = Path(tmp) / "initrd.gz"
        pack_initrd(test_bin, libs, busybox, initrd)
        return run_qemu(args.target, kernel, initrd)


if __name__ == "__main__":
    raise SystemExit(main())
