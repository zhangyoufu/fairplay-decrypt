#!/usr/bin/env python3
"""Decrypt an authorized IPA using a 16-byte credential."""

from __future__ import annotations

import argparse
import copy
import os
import shutil
import tempfile
from pathlib import Path
from zipfile import ZipFile

from core import decrypt_binary, macho_slices

ROOT = Path(__file__).resolve().parent
COPY_BUFSIZE = 64 * 1024
SUPF_SUFFIXES = (".v5.supf", ".supf", ".v4.supp", ".supp")


def supf_candidates(names: set[str]) -> dict[str, list[str]]:
    by_binary: dict[str, list[tuple[int, str]]] = {}
    for name in sorted(names):
        for priority, suffix in enumerate(SUPF_SUFFIXES):
            if name.endswith(suffix):
                stem = name.removesuffix(suffix)
                by_binary.setdefault(stem, []).append((priority, name))
                break
    return {
        stem: [name for _priority, name in sorted(entries)]
        for stem, entries in by_binary.items()
    }


def enclosing_app_sinf(names: set[str], bundle: str) -> str | None:
    parts = bundle.split("/")
    for i in range(len(parts), 0, -1):
        prefix = "/".join(parts[:i])
        if not prefix.endswith(".app"):
            continue
        sc_info = prefix + "/SC_Info/"
        sinfs = sorted(
            name
            for name in names
            if name.startswith(sc_info)
            and name.endswith(".sinf")
            and name.count("/") == sc_info.count("/")
        )
        if not sinfs:
            continue
        for suffix in (".sinf", ".v4.sinf"):
            preferred = sc_info + Path(prefix).stem + suffix
            if preferred in sinfs:
                return preferred
        unversioned = [name for name in sinfs if not name.endswith(".v4.sinf")]
        return (unversioned or sinfs)[0]
    return None


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("ipa", type=Path, help="authorized encrypted IPA")
    parser.add_argument(
        "output", type=Path, help="decrypted IPA output; must not exist"
    )
    parser.add_argument(
        "--credential",
        type=Path,
        default=ROOT / "credential.bin",
        help="saved 16-byte credential",
    )
    args = parser.parse_args()
    if not args.ipa.is_file() or not args.credential.is_file():
        parser.error("input IPA or credential file missing")
    if args.output.exists():
        parser.error("output already exists; never overwrite it")
    if args.output.resolve() == args.ipa.resolve():
        parser.error("input and output must differ")
    credential = args.credential.read_bytes()
    if len(credential) != 16:
        parser.error("credential must contain exactly 16 bytes")
    with ZipFile(args.ipa) as archive:
        members = archive.namelist()
        names = set(members)
        if len(names) != len(members):
            raise ValueError("input ZIP has duplicate member names")
        plan = []
        for candidates in supf_candidates(names).values():
            supf_path = next(
                (name for name in candidates if archive.getinfo(name).file_size), None
            )
            if supf_path is None:
                continue
            parts = supf_path.rsplit("/SC_Info/", 1)
            if len(parts) != 2:
                raise ValueError(f"SUPF outside SC_Info: {supf_path}")
            bundle, filename = parts
            suffix = next(s for s in SUPF_SUFFIXES if filename.endswith(s))
            stem = filename.removesuffix(suffix)
            binary_path = bundle + "/" + stem
            sinf_names = [stem + ".sinf"]
            if suffix in (".v5.supf", ".v4.supp"):
                sinf_names.insert(0, stem + ".v4.sinf")
            sinf_path = next(
                (
                    bundle + "/SC_Info/" + name
                    for name in sinf_names
                    if bundle + "/SC_Info/" + name in names
                ),
                None,
            )
            if binary_path not in names:
                raise ValueError(f"SUPF lacks binary/SINF: {supf_path}")
            source = archive.read(binary_path)
            if not any(image.cryptid == 1 for image in macho_slices(source)):
                continue
            supf = archive.read(supf_path)
            if not supf:
                continue
            if sinf_path is None:
                fallback = enclosing_app_sinf(names, bundle)
                if fallback is None:
                    raise ValueError(f"SUPF lacks binary/SINF: {supf_path}")
                sinf_path = fallback
            plan.append(
                (
                    binary_path,
                    source,
                    archive.read(sinf_path),
                    supf,
                )
            )
        if not plan:
            raise ValueError("no encrypted binaries with supported SINF/SUPF")
        replacements = {}
        total_pages = 0
        for ordinal, (binary_path, source, sinf, supf) in enumerate(plan, 1):
            result, pages = decrypt_binary(source, sinf, supf, credential)
            replacements[binary_path] = result
            total_pages += pages
            print(f"{ordinal:02d}/{len(plan)} pages={pages} {binary_path}", flush=True)
        del plan, source
        args.output.parent.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(
            prefix="fairplay-output-", dir=args.output.parent
        ) as temp:
            provisional = Path(temp) / "provisional.ipa"
            with ZipFile(provisional, "w") as output:
                for entry in archive.infolist():
                    info = copy.copy(entry)
                    if entry.filename in replacements:
                        data = replacements[entry.filename]
                        info.file_size = len(data)
                        with output.open(info, "w") as destination:
                            view = memoryview(data)
                            for offset in range(0, len(view), COPY_BUFSIZE):
                                destination.write(view[offset : offset + COPY_BUFSIZE])
                    else:
                        with (
                            archive.open(entry, "r") as member,
                            output.open(info, "w") as destination,
                        ):
                            shutil.copyfileobj(member, destination, length=COPY_BUFSIZE)
            os.link(provisional, args.output)
    print(
        f"decrypted-binaries={len(replacements)} pages={total_pages} output={args.output}"
    )


if __name__ == "__main__":
    main()
