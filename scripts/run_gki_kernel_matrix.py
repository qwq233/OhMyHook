#!/usr/bin/env python3
"""Runs the full test suite in QEMU against Android GKI/LTS kernels.

GKI kernels come from the official source.android.com release artifacts.
The non-GKI android-4.14 branch has no published boot image and is built
from source. Every runtime file (cross toolchain, busybox, libc) comes from
its official upstream download; nothing is extracted from the local machine.
The caller caches the kernel cache directory (actions/cache in CI), keyed by
the resolved release tag.
"""

import argparse
import functools
import html
import json
import os
import re
import struct
import subprocess
import tarfile
import tempfile
import urllib.request
import zipfile
from pathlib import Path

import run_qemu_system_tests as qemu_tests


SOURCE_ANDROID = "https://source.android.com"
BOOTLIN_AARCH64 = (
    "https://toolchains.bootlin.com/downloads/releases/toolchains/aarch64/tarballs/"
    "aarch64--glibc--stable-2024.05-1.tar.xz"
)
GKI_PAGES = {
    "6.18": "gki-android17-6_18-release-builds",
    "6.12": "gki-android16-6_12-release-builds",
    "6.6": "gki-android15-6_6-release-builds",
    "6.1": "gki-android14-6_1-release-builds",
    "5.10": "gki-android12-5_10-release-builds",
    "5.15": "gki-android14-5_15-release-builds",
}
TARGET = "aarch64-unknown-linux-gnu"
DEFAULT_CACHE_DIR = Path.home() / ".cache" / "omhook-gki-kernels"
BOOT_HEADER_V4_SIZE = 4096
TAG_RE = re.compile(r"android(\d+)-(\d+\.\d+)-(\d{4})-(\d{2})_r(\d+)")


def fetch(url: str) -> bytes:
    request = urllib.request.Request(url, headers={"User-Agent": "omhook-ci"})
    with urllib.request.urlopen(request, timeout=180) as response:
        return response.read()


def bootlin_sha256() -> str:
    checksum_url = f"{BOOTLIN_AARCH64.removesuffix('.tar.xz')}.sha256"
    checksum = fetch(checksum_url).decode("utf-8", "replace")
    match = re.match(r"([0-9a-f]{64})", checksum)
    if match is None:
        raise RuntimeError("Bootlin toolchain checksum is malformed")
    return match.group(1)


@functools.lru_cache(maxsize=None)
def release_page(kernel_version: str) -> str:
    page = GKI_PAGES[kernel_version]
    return fetch(f"{SOURCE_ANDROID}/docs/core/architecture/kernel/{page}").decode(
        "utf-8", "replace"
    )


def latest_release_tag(kernel_version: str) -> str:
    """Picks the newest tag published on the release-builds page."""
    matches = TAG_RE.findall(release_page(kernel_version))
    if not matches:
        raise RuntimeError(f"no release tags found for {kernel_version}")
    android, version, year, month, revision = max(
        matches, key=lambda parts: (int(parts[2]), int(parts[3]), int(parts[4]))
    )
    return f"android{android}-{version}-{year}-{month}_r{revision}"


def boot_image_archive_url(kernel_version: str, tag: str) -> str:
    """Finds the boot.img download URL for one tag on its release page."""
    text = release_page(kernel_version)
    escaped = re.escape(html.escape(tag, quote=True))
    pattern = (
        rf"{escaped}.*?(https://dl\.google\.com/android/gki/[^\"]+?\.zip)"
    )
    row = re.search(
        pattern,
        text,
        re.DOTALL,
    )
    if row is None:
        raise RuntimeError(f"no boot image link for {tag}")
    return row.group(1)


def unpack_boot_image(data: bytes) -> bytes:
    """Extracts the raw arm64 Image from an Android boot image v3/v4."""
    if data[:8] != b"ANDROID!":
        raise ValueError("not an Android boot image")
    kernel_size = struct.unpack_from("<I", data, 8)[0]
    header_version = struct.unpack_from("<I", data, 8 + 32)[0]
    if header_version < 3:
        raise ValueError(f"unsupported boot header v{header_version}")
    kernel = data[BOOT_HEADER_V4_SIZE : BOOT_HEADER_V4_SIZE + kernel_size]
    if len(kernel) != kernel_size:
        raise ValueError("truncated kernel payload")
    return kernel


def gki_kernel(kernel_version: str, cache_dir: Path) -> tuple[Path, str]:
    tag = latest_release_tag(kernel_version)
    image = cache_dir / tag / "Image"
    image.parent.mkdir(parents=True, exist_ok=True)
    archive_path = image.parent / "boot.zip"
    qemu_tests.download(boot_image_archive_url(kernel_version, tag), archive_path)
    with zipfile.ZipFile(archive_path) as archive:
        member = archive.namelist()[0]
        boot_image = archive.read(member)
    payload = unpack_boot_image(boot_image)
    tmp = image.with_suffix(".part")
    tmp.write_bytes(payload)
    tmp.replace(image)
    return image, tag


def latest_4_14_tag() -> str:
    # android-4.14 predates GKI release tags; its final published release
    # marker is the last ASB tag on the deprecated stable branch.
    listing = fetch(
        "https://android.googlesource.com/kernel/common/+refs/tags?format=JSON"
    ).decode("utf-8", "replace")
    matches = re.findall(r"ASB-(\d{4})-(\d{2})-05_4\.14-stable", listing)
    if not matches:
        raise RuntimeError("no android-4.14 ASB release tags found")
    year, month = max(matches, key=lambda parts: (int(parts[0]), int(parts[1])))
    return f"ASB-{year}-{month}-05_4.14-stable"


def build_4_14_kernel(tag: str, cache_dir: Path) -> Path:
    image = cache_dir / tag / "Image"
    metadata_path = image.with_suffix(".build.json")
    try:
        metadata = json.loads(metadata_path.read_text())
    except (FileNotFoundError, UnicodeError, json.JSONDecodeError):
        metadata = None
    if image.is_file() and isinstance(metadata, dict) and (
        metadata.get("tag") == tag
        and metadata.get("sha256") == qemu_tests.file_sha256(image)
    ):
        return image
    ensure_bootlin_toolchain(cache_dir)
    work = cache_dir / tag / "src"
    if not (work / "Makefile").is_file():
        if work.exists():
            subprocess.run(["rm", "-rf", str(work)], check=True)
        work.parent.mkdir(parents=True, exist_ok=True)
        subprocess.run(
            [
                "git",
                "clone",
                "--depth",
                "1",
                "--branch",
                tag,
                "https://android.googlesource.com/kernel/common",
                str(work),
            ],
            check=True,
        )
    out = (work.parent / "build").resolve()
    config_ext = work.parent / "Kconfig.ext"
    config_ext.write_text(
        "# SPDX-License-Identifier: GPL-2.0\n"
        "config OMHOOK_KCONFIG_EXT_STUB\n\tbool\n\tdefault y\n"
    )
    cross_prefix = (
        qemu_tests.CACHE
        / "bootlin/aarch64--glibc--stable-2024.05-1/bin/aarch64-buildroot-linux-gnu-"
    )
    env = {**os.environ, "KCONFIG_EXT_PREFIX": f"{config_ext.parent}/"}
    make_flags = (
        ["LLVM=1"]
        if kernel_version_is_modern(work)
        else [f"CROSS_COMPILE={cross_prefix}"]
    )
    subprocess.run(
        ["make", f"O={out}", "ARCH=arm64", *make_flags, "defconfig"],
        cwd=work,
        env=env,
        check=True,
    )
    subprocess.run(
        [
            "make",
            f"O={out}",
            "ARCH=arm64",
            *make_flags,
            f"-j{os.cpu_count() or 2}",
        ],
        cwd=work,
        env=env,
        check=True,
    )
    built = out / "arch/arm64/boot/Image"
    if not built.is_file():
        raise RuntimeError("kernel build produced no Image")
    image.parent.mkdir(parents=True, exist_ok=True)
    metadata_tmp = metadata_path.with_suffix(".part")
    metadata_tmp.write_text(json.dumps({"tag": tag, "sha256": qemu_tests.file_sha256(built)}))
    metadata_tmp.replace(metadata_path)
    built.replace(image)
    return image


def kernel_version_is_modern(source: Path) -> bool:
    makefile = (source / "Makefile").read_text()
    patchlevel = re.search(r"^PATCHLEVEL\s*=\s*(\d+)", makefile, re.MULTILINE)
    version = re.search(r"^VERSION\s*=\s*(\d+)", makefile, re.MULTILINE)
    if not patchlevel or not version:
        raise RuntimeError("cannot parse kernel Makefile version")
    major, minor = int(version.group(1)), int(patchlevel.group(1))
    return (major, minor) >= (5, 10)


def ensure_bootlin_toolchain(cache_dir: Path) -> None:
    """Downloads the official Bootlin aarch64 glibc toolchain when missing."""
    root = qemu_tests.CACHE / "bootlin"
    marker = root / "aarch64--glibc--stable-2024.05-1"
    gcc = marker / "bin" / "aarch64-buildroot-linux-gnu-gcc"
    if gcc.is_file():
        return
    archive_path = cache_dir / "bootlin-aarch64.tar.xz"
    expected_sha256 = bootlin_sha256()
    if archive_path.is_file() and qemu_tests.file_sha256(archive_path) != expected_sha256:
        archive_path.unlink()
    if not archive_path.is_file():
        archive_path.parent.mkdir(parents=True, exist_ok=True)
        archive_path.write_bytes(fetch(BOOTLIN_AARCH64))
        if qemu_tests.file_sha256(archive_path) != expected_sha256:
            archive_path.unlink()
            raise RuntimeError("Bootlin toolchain SHA-256 mismatch")
    root.mkdir(parents=True, exist_ok=True)
    with tarfile.open(archive_path, "r:xz") as archive:
        archive.extractall(root, filter="data")
    archive_path.unlink()
    if not gcc.is_file():
        raise RuntimeError("bootlin toolchain unpacked without gcc")


def run_matrix(kernel_version: str, cache_dir: Path) -> int:
    if kernel_version == "4.14":
        tag = latest_4_14_tag()
        kernel = build_4_14_kernel(tag, cache_dir)
    else:
        kernel, tag = gki_kernel(kernel_version, cache_dir)

    ensure_bootlin_toolchain(cache_dir)
    # Old kernels do not boot on QEMU's newest "max" CPU model.
    cpu = "cortex-a57" if kernel_version == "4.14" else "max"
    spec = qemu_tests.TARGETS[TARGET]
    rootfs = qemu_tests.alpine_minirootfs(spec["alpine"])
    busybox = qemu_tests.busybox_from_alpine(rootfs)
    musl = qemu_tests.alpine_musl_libs(rootfs)
    test_bin = qemu_tests.build_test(TARGET)
    libs = qemu_tests.collect_libs(test_bin, spec["lib_dirs"])
    libs.update(musl)
    with tempfile.TemporaryDirectory() as tmp:
        initrd = Path(tmp) / "initrd.gz"
        qemu_tests.pack_initrd(test_bin, libs, busybox, initrd)
        print(f"[gki-matrix] kernel={tag} image={kernel}")
        qemu_tests.TARGETS[TARGET]["machine"] = ["-M", "virt", "-cpu", cpu]
        return qemu_tests.run_qemu(TARGET, kernel, initrd)


def prepare_kernel(kernel_version: str, cache_dir: Path) -> str:
    """Only materializes the kernel image; returns its release tag."""
    if kernel_version == "4.14":
        tag = latest_4_14_tag()
        build_4_14_kernel(tag, cache_dir)
    else:
        tag = latest_release_tag(kernel_version)
        gki_kernel(kernel_version, cache_dir)
    return tag


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--kernel",
        required=True,
        choices=sorted([*GKI_PAGES, "4.14"]),
        help="kernel version whose latest published release is tested",
    )
    parser.add_argument(
        "--cache-dir",
        type=Path,
        default=DEFAULT_CACHE_DIR,
        help="directory the caller (CI) caches; repopulated on cache misses",
    )
    parser.add_argument(
        "--print-tag",
        action="store_true",
        help="print the resolved release tag and exit (for CI cache keys)",
    )
    parser.add_argument(
        "--prepare-only",
        action="store_true",
        help="only materialize the kernel image, do not run tests",
    )
    args = parser.parse_args()
    if args.prepare_only:
        prepare_kernel(args.kernel, args.cache_dir)
        return 0
    if args.print_tag:
        tag = latest_4_14_tag() if args.kernel == "4.14" else latest_release_tag(
            args.kernel
        )
        print(tag)
        return 0
    return run_matrix(args.kernel, args.cache_dir)


if __name__ == "__main__":
    raise SystemExit(main())
