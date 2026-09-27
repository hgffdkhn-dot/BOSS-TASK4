#!/usr/bin/env python3
"""Make an ELF executable acceptable to Android's Bionic loader.

Two independent Android quirks are handled:

1. TLS alignment. Bionic refuses to load a binary whose PT_TLS segment is
   underaligned - it needs >= 64 bytes on 64-bit ABIs and >= 32 on 32-bit.
   NDK's lld emits 8 for static binaries, giving:

       error: "veritpath": executable's TLS segment is underaligned:
              alignment is 8 (skew 0), needs to be at least 64 for ARM64 Bionic
       Aborted

   This is exactly what termux-elf-cleaner fixes; we do it in-tree so the
   build needs no extra tooling.

2. 16KB page size. Android 15+ devices with 16KB pages additionally require
   PT_LOAD segments to be 16KB aligned; the check below reports it.

usage:
  elf_fix.py FILE [FILE ...]     patch TLS alignment in place
  elf_fix.py --check FILE        report e_type / TLS / LOAD alignment

Pure standard library, works on CPython 3.6+.
"""

import struct
import sys

PT_LOAD = 1
PT_TLS = 7

ET_EXEC = 2
ET_DYN = 3

# Bionic: 64 for 64-bit ABIs, 32 for 32-bit (linker_main.cpp)
MIN_TLS_ALIGN = {32: 32, 64: 64}
PAGE16K = 16384


class ElfError(Exception):
    pass


def read_header(f):
    ident = f.read(16)
    if ident[:4] != b"\x7fELF":
        raise ElfError("not an ELF file")
    ei_class = ident[4]
    ei_data = ident[5]
    if ei_class not in (1, 2):
        raise ElfError("bad EI_CLASS %d" % ei_class)
    if ei_data not in (1, 2):
        raise ElfError("bad EI_DATA %d" % ei_data)
    is64 = ei_class == 2
    end = "<" if ei_data == 1 else ">"
    # e_type, e_machine, e_version, e_entry, e_phoff, e_shoff
    if is64:
        head = f.read(32)
        e_type = struct.unpack_from(end + "H", head, 0)[0]
        e_phoff = struct.unpack_from(end + "Q", head, 16)[0]
    else:
        head = f.read(20)
        e_type = struct.unpack_from(end + "H", head, 0)[0]
        e_phoff = struct.unpack_from(end + "I", head, 12)[0]
    # then e_flags(4), e_ehsize(2), e_phentsize(2), e_phnum(2)
    tail = f.read(10)
    e_phentsize = struct.unpack_from(end + "H", tail, 6)[0]
    e_phnum = struct.unpack_from(end + "H", tail, 8)[0]
    return is64, end, e_type, e_phoff, e_phentsize, e_phnum


def phdr_offsets(is64):
    """(p_type, p_align) byte offsets inside a program header."""
    if is64:
        # p_type@0 (4) p_flags@4 (4) p_offset@8 (8) p_vaddr@16 p_paddr@24
        # p_filesz@32 p_memsz@40 p_align@48
        return 0, 48
    # p_type@0 p_offset@4 p_vaddr@8 p_paddr@12 p_filesz@16 p_memsz@20
    # p_flags@24 p_align@28
    return 0, 28


def scan(path):
    with open(path, "r+b") as f:
        is64, end, e_type, e_phoff, phentsize, phnum = read_header(f)
        off_type, off_align = phdr_offsets(is64)
        fmt = end + ("Q" if is64 else "I")
        info = {
            "path": path,
            "is64": is64,
            "e_type": e_type,
            "tls": [],
            "load_min_align": None,
        }
        for i in range(phnum):
            base = e_phoff + i * phentsize
            f.seek(base + off_type)
            p_type = struct.unpack(end + "I", f.read(4))[0]
            f.seek(base + off_align)
            p_align = struct.unpack(fmt, f.read(8 if is64 else 4))[0]
            if p_type == PT_TLS:
                info["tls"].append((base + off_align, p_align))
            elif p_type == PT_LOAD:
                if info["load_min_align"] is None:
                    info["load_min_align"] = p_align
                info["load_min_align"] = min(info["load_min_align"], p_align or 1)
        return info


def fix(path):
    info = scan(path)
    need = MIN_TLS_ALIGN[64 if info["is64"] else 32]
    f = open(path, "r+b")
    f.seek(5)
    end = "<" if f.read(1) == b"\x01" else ">"
    wfmt = end + ("Q" if info["is64"] else "I")
    changed = []
    for pos, align in info["tls"]:
        if align < need:
            f.seek(pos)
            f.write(struct.pack(wfmt, need))
            changed.append((align, need))
    f.close()
    return info, changed


def main(argv):
    args = [a for a in argv[1:] if not a.startswith("--")]
    check_only = "--check" in argv
    files = args
    if not files:
        print(__doc__)
        return 2

    rc = 0
    for path in files:
        try:
            info = scan(path)
        except (ElfError, OSError) as exc:
            print("  %s: %s" % (path, exc))
            rc = 1
            continue

        if check_only:
            kind = "ET_DYN (PIE)" if info["e_type"] == ET_DYN else (
                "ET_EXEC (not PIE)" if info["e_type"] == ET_EXEC
                else "e_type=%d" % info["e_type"]
            )
            need = MIN_TLS_ALIGN[64 if info["is64"] else 32]
            tls = [a for _, a in info["tls"]] or [None]
            print("  %s" % path)
            print("    class   : %d-bit" % (64 if info["is64"] else 32))
            print("    e_type  : %s" % kind)
            print("    PT_TLS  : align=%s (need >= %d)" % (tls, need))
            print("    PT_LOAD : min align=%s (16KB pages need %d)"
                  % (info["load_min_align"], PAGE16K))
            if info["e_type"] != ET_DYN:
                print("    -> NOT PIE, Android 5+ will refuse it")
                rc = 1
            for a in tls:
                if a is not None and a < need:
                    print("    -> TLS underaligned, Bionic will refuse it")
                    rc = 1
            continue

        _, changed = fix(path)
        if changed:
            for old, new in changed:
                print("  %s: TLS alignment %d -> %d" % (path, old, new))
        else:
            print("  %s: TLS alignment already fine" % path)
    return rc


if __name__ == "__main__":
    sys.exit(main(sys.argv))
