"""Find BSS variables by ADRP reference frequency.

Usage: python find_bss_vars.py <kernel_image>
"""
import struct
from collections import Counter
import sys

if len(sys.argv) < 2:
    print(__doc__)
    sys.exit(1)

kernel_path = sys.argv[1]

VA_BASE = 0xFFFFFFC00A000000
BSS_FILE_START = 0x22CAA00
BSS_FILE_END = 0x2370000
BSS_VA_START = VA_BASE + BSS_FILE_START
BSS_VA_END = VA_BASE + BSS_FILE_END
DATA_START = 0x20A7000

def decode_adrp(insn):
    if (insn & 0x9F000000) != 0x90000000:
        return None
    immlo = (insn >> 29) & 0x3
    immhi = (insn >> 5) & 0x7FFFF
    imm = (immhi << 2) | immlo
    if imm & (1 << 20):
        imm -= 1 << 21
    return imm

with open(kernel_path, 'rb') as f:
    data = f.read()

page_refcnt = Counter()
page_sources = {}
page_pa_map = {}

for off in range(0, min(DATA_START, len(data)), 4):
    insn = struct.unpack_from('<I', data, off)[0]
    imm = decode_adrp(insn)
    if imm is None:
        continue

    insn_va = VA_BASE + off
    pc_page = insn_va & ~0xFFF
    target_page = pc_page + (imm << 12)

    if BSS_VA_START <= target_page < BSS_VA_END:
        page_off_bss = target_page - BSS_VA_START
        file_target = BSS_FILE_START + page_off_bss
        pa_target = file_target + 0xA8000000
        page_refcnt[target_page] += 1
        if target_page not in page_sources:
            page_sources[target_page] = []
        page_sources[target_page].append((off, insn))
        page_pa_map[target_page] = (file_target, pa_target)

print('BSS pages by ADRP ref count:')
for target_page, cnt in page_refcnt.most_common(77):
    foff, pa = page_pa_map[target_page]
    bss_off = foff - BSS_FILE_START
    first_code = page_sources[target_page][0][0]
    print(f'  BSS+{bss_off:#010x} PA={pa:#018x} refs={cnt:4d}  first_ref@code_{first_code:#010x}')
