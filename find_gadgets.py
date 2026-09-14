#!/usr/bin/env python3
"""Find the 21 ROP gadgets rop.js needs in a DECRYPTED 13.40 libSceNKWebKit.

Usage:
    python3 find_gadgets.py <decrypted-libSceNKWebKit.sprx> > gadgets.txt

Searches executable segments for ret-terminated byte patterns and prints
a paste-ready wk_gadgetmap plus a missing list. Only executable (R+E, not W)
segments are searched, so data bytes can never produce false hits.

Where the input comes from (do this on your Mac, no PS5 involved):
  1. Download Sony's official 13.40 PS5 system-software update (PUP).
  2. Unpack + decrypt it with scene PS5 PUP tooling (the same pipeline
     named in every offsets/*.js header: "generated from libSceNKWebKit /
     libkernel_web / libSceLibcInternal").
  3. Pull out the decrypted libSceNKWebKit module and run this script on it.
  4. Paste the printed map back -- it gets wired into offsets/13.40.js and
     boot-tested (main.js "chain operational" check, zero kernel interaction).
Tip: run it on decrypted libkernel_web.sprx too -- every 0F 05 with a
`mov eax, N` nearby cross-checks the +0x90 syscall table for free.
"""
import struct
import sys

PATTERNS = [
    ("ret", bytes([0xC3])),
    ("pop rdi", bytes([0x5F, 0xC3])),
    ("pop rsi", bytes([0x5E, 0xC3])),
    ("pop rdx", bytes([0x5A, 0xC3])),
    ("pop rcx", bytes([0x59, 0xC3])),
    ("pop rax", bytes([0x58, 0xC3])),
    ("pop rsp", bytes([0x5C, 0xC3])),
    ("pop r8", bytes([0x41, 0x58, 0xC3])),
    ("pop r9", bytes([0x41, 0x59, 0xC3])),
    ("mov [rdi], rsi", bytes([0x48, 0x89, 0x37, 0xC3])),
    ("mov [rdi], rax", bytes([0x48, 0x89, 0x07, 0xC3])),
    ("mov [rdi], eax", bytes([0x89, 0x07, 0xC3])),
    ("mov rax, [rax]", bytes([0x48, 0x8B, 0x00, 0xC3])),
    ("add rax, rcx", bytes([0x48, 0x01, 0xC8, 0xC3])),
    ("cmp [rcx], eax", bytes([0x39, 0x01, 0xC3])),
    ("inc dword [rax]", bytes([0xFF, 0x00, 0xC3])),
    ("seta al", bytes([0x0F, 0x97, 0xC0, 0xC3])),
    ("setb al", bytes([0x0F, 0x92, 0xC0, 0xC3])),
    ("sete al", bytes([0x0F, 0x94, 0xC0, 0xC3])),
    ("setg al", bytes([0x0F, 0x9F, 0xC0, 0xC3])),
    ("setl al", bytes([0x0F, 0x9C, 0xC0, 0xC3])),
    ("shl rax, 3", bytes([0x48, 0xC1, 0xE0, 0x03, 0xC3])),
    ("shl rax, 4", bytes([0x48, 0xC1, 0xE0, 0x04, 0xC3])),
    ("shr rax, 3", bytes([0x48, 0xC1, 0xE8, 0x03, 0xC3])),
    ("shr rax, 4", bytes([0x48, 0xC1, 0xE8, 0x04, 0xC3])),
    ("infloop", bytes([0xEB, 0xFE])),
]


def load_segments(path):
    with open(path, "rb") as f:
        data = f.read()
    segs = []  # (file_off, vaddr, filesz, flags)
    if data[:4] == b"\x7fELF" and data[4:5] == b"\x02":
        e_phoff, = struct.unpack("<Q", data[0x20:0x28])
        e_phentsize, = struct.unpack("<H", data[0x36:0x38])
        e_phnum, = struct.unpack("<H", data[0x38:0x3A])
        for i in range(e_phnum):
            off = e_phoff + i * e_phentsize
            p_type, p_flags, p_offset, p_vaddr, _, p_filesz, _, _ = \
                struct.unpack("<IIQQQQQQ", data[off:off + 56])
            if p_type == 1 and p_filesz:
                segs.append((p_offset, p_vaddr, p_filesz, p_flags))
    return data, segs


def main():
    if len(sys.argv) != 2:
        print("usage: python3 find_gadgets.py <decrypted-module>", file=sys.stderr)
        return 2
    data, segs = load_segments(sys.argv[1])
    print(f"# file: {sys.argv[1]} ({len(data)} bytes, {len(segs)} PT_LOAD)")
    for off, va, sz, fl in segs:
        print(f"#   seg fileoff=0x{off:x} vaddr=0x{va:x} size=0x{sz:x} "
              f"{'R' if fl & 4 else '-'}{'W' if fl & 2 else '-'}{'X' if fl & 1 else '-'}")
    exec_segs = [s for s in segs if (s[3] & 4) and not (s[3] & 2)]
    if exec_segs:
        print(f"# searching {len(exec_segs)} executable segment(s)")
    else:
        print("# WARNING: no R+E segment found, searching whole file (hits may be data)")
        exec_segs = [(0, 0, len(data), 7)]
    found, missing = {}, []
    for name, pat in PATTERNS:
        hit = None
        for off, va, sz, _ in exec_segs:
            idx = data.find(pat, off, off + sz)
            if idx >= 0 and idx + len(pat) <= off + sz:
                hit = va + (idx - off)
                break
        if hit is None:
            missing.append(name)
        else:
            found[name] = hit
    print("")
    print("let wk_gadgetmap = {")
    for name, _ in PATTERNS:
        if name in found:
            print(f'\t"{name}": 0x{found[name]:08X},')
    print("};")
    print("")
    if missing:
        print(f"# MISSING {len(missing)}: {', '.join(missing)}")
        print("# (extend the search or check the module is fully decrypted)")
        return 1
    print(f"# ALL {len(found)} GADGETS FOUND")
    return 0


if __name__ == "__main__":
    sys.exit(main())
