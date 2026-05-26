"""Extract ELF structure info from abl.elf for analysis.
Supports both 32-bit and 64-bit ELF."""

import struct
import sys
import os
from pathlib import Path

ELFCLASS32 = 1
ELFCLASS64 = 2
ELFDATA2LSB = 1
ET_EXEC = 2
EM_ARM = 40       # ARM 32-bit
EM_AARCH64 = 183  # ARM 64-bit

PT_LOAD = 1
SHT_STRTAB = 3
SHT_SYMTAB = 2

def read_elf_header(data):
    ident = data[:16]
    if ident[:4] != b'\x7fELF':
        raise ValueError("Not an ELF file")
    if ident[5] != ELFDATA2LSB:
        raise ValueError("Not little-endian")

    elf_class = ident[4]
    if elf_class == ELFCLASS32:
        return read_elf32_header(data)
    elif elf_class == ELFCLASS64:
        return read_elf64_header(data)
    else:
        raise ValueError(f"Unknown ELF class: {elf_class}")

def read_elf32_header(data):
    hdr = struct.unpack('<HHIIIIIHHHHHH', data[16:52])
    (e_type, e_machine, e_version, e_entry, e_phoff, e_shoff,
     e_flags, e_ehsize, e_phentsize, e_phnum, e_shentsize, e_shnum, e_shstrndx) = hdr
    return {
        'bits': 32, 'type': e_type, 'machine': e_machine,
        'version': e_version, 'entry': e_entry, 'phoff': e_phoff,
        'shoff': e_shoff, 'flags': e_flags, 'ehsize': e_ehsize,
        'phentsize': e_phentsize, 'phnum': e_phnum,
        'shentsize': e_shentsize, 'shnum': e_shnum,
        'shstrndx': e_shstrndx, 'total_size': len(data)
    }

def read_elf64_header(data):
    hdr = struct.unpack('<HHIQQQIHHHHHH', data[16:64])
    (e_type, e_machine, e_version, e_entry, e_phoff, e_shoff,
     e_flags, e_ehsize, e_phentsize, e_phnum, e_shentsize, e_shnum, e_shstrndx) = hdr
    return {
        'bits': 64, 'type': e_type, 'machine': e_machine,
        'version': e_version, 'entry': e_entry, 'phoff': e_phoff,
        'shoff': e_shoff, 'flags': e_flags, 'ehsize': e_ehsize,
        'phentsize': e_phentsize, 'phnum': e_phnum,
        'shentsize': e_shentsize, 'shnum': e_shnum,
        'shstrndx': e_shstrndx, 'total_size': len(data)
    }

def read_program_headers(data, hdr):
    is64 = hdr['bits'] == 64
    phoff = hdr['phoff']
    phentsize = hdr['phentsize']
    segments = []
    for i in range(hdr['phnum']):
        off = phoff + i * phentsize
        if is64:
            ph = struct.unpack('<IIQQQQQQ', data[off:off+56])
            p_type, p_flags, p_offset, p_vaddr, p_paddr, p_filesz, p_memsz, p_align = ph
        else:
            ph = struct.unpack('<IIIIIIII', data[off:off+32])
            p_type, p_offset, p_vaddr, p_paddr, p_filesz, p_memsz, p_flags, p_align = ph
        segments.append({
            'type': p_type, 'flags': p_flags, 'offset': p_offset,
            'vaddr': p_vaddr, 'paddr': p_paddr, 'filesz': p_filesz,
            'memsz': p_memsz, 'align': p_align
        })
    return segments

def read_section_headers(data, hdr):
    is64 = hdr['bits'] == 64
    shoff = hdr['shoff']
    shentsize = hdr['shentsize']
    sections = []
    for i in range(hdr['shnum']):
        off = shoff + i * shentsize
        if is64:
            sh = struct.unpack('<IIQQQQIIQQ', data[off:off+64])
            sh_name, sh_type, sh_flags, sh_addr, sh_offset, sh_size, sh_link, sh_info, sh_addralign, sh_entsize = sh
        else:
            sh = struct.unpack('<IIIIIIIIII', data[off:off+40])
            sh_name, sh_type, sh_flags, sh_addr, sh_offset, sh_size, sh_link, sh_info, sh_addralign, sh_entsize = sh
        sections.append({
            'name_idx': sh_name, 'type': sh_type, 'flags': sh_flags,
            'addr': sh_addr, 'offset': sh_offset, 'size': sh_size,
            'link': sh_link, 'info': sh_info, 'addralign': sh_addralign,
            'entsize': sh_entsize
        })
    return sections

def get_section_names(sections, shstrndx, data):
    if shstrndx >= len(sections):
        return sections
    shstrtab = sections[shstrndx]
    str_start = shstrtab['offset']
    str_end = str_start + shstrtab['size']
    strings = data[str_start:str_end]
    for s in sections:
        end = strings.find(b'\x00', s['name_idx'])
        if end >= 0:
            s['name'] = strings[s['name_idx']:end].decode('utf-8', errors='replace')
        else:
            s['name'] = ''
    return sections

def extract_strings(data, min_len=4):
    strings = []
    current = b''
    i = 0
    for byte in data:
        if 0x20 <= byte <= 0x7e:
            current += bytes([byte])
        else:
            if len(current) >= min_len:
                strings.append(current.decode('ascii', errors='replace'))
            current = b''
        i += 1
    if len(current) >= min_len:
        strings.append(current.decode('ascii', errors='replace'))
    return strings

def find_fastboot_strings(strings):
    keywords = ['fastboot', 'oem', 'flash:', 'erase:', 'boot ',
                 'unlock', 'lock', 'download:', 'getvar:',
                 'reboot', 'set_active', 'gpt', 'partition',
                 'critical', 'token', 'verify', 'rollback',
                 'anti', 'flashing', 'continue',
                 'DisableVB', 'keymaster', 'avb']
    found = set()
    categorized = {k: [] for k in keywords}
    for s in strings:
        slow = s.lower()
        for kw in keywords:
            if kw in slow:
                categorized[kw].append(s)
                found.add(s)
    return found, categorized

def analyze_elf(filepath):
    with open(filepath, 'rb') as f:
        data = f.read()

    hdr = read_elf_header(data)
    segments = read_program_headers(data, hdr)
    sections = read_section_headers(data, hdr)
    sections = get_section_names(sections, hdr['shstrndx'], data)

    strings = extract_strings(data)
    fb_strings, fb_categorized = find_fastboot_strings(strings)

    return hdr, segments, sections, strings, fb_strings, fb_categorized

def machine_name(m):
    names = {40: 'ARM (32-bit)', 183: 'AArch64', 62: 'x86_64', 3: 'i386'}
    return names.get(m, f'0x{m:x}')

def print_report(filepath):
    hdr, segs, secs, strings, fb_strings, fb_categorized = analyze_elf(filepath)

    print(f"\n{'='*70}")
    print(f"ELF Analysis: {filepath}")
    print(f"{'='*70}")

    print(f"\n[Header]")
    print(f"  Bits:       {hdr['bits']}-bit")
    print(f"  Machine:    {machine_name(hdr['machine'])}")
    print(f"  Size:       {hdr['total_size']:,} bytes ({hdr['total_size']/1024:.1f} KB)")
    print(f"  Type:       {'EXEC' if hdr['type']==2 else hdr['type']}")
    print(f"  Entry:      0x{hdr['entry']:08x}")
    print(f"  PH offset:  0x{hdr['phoff']:x} ({hdr['phnum']} segments)")
    print(f"  SH offset:  0x{hdr['shoff']:x} ({hdr['shnum']} sections)")

    print(f"\n[LOAD Segments]")
    load_segs = [s for s in segs if s['type'] == PT_LOAD]
    for s in load_segs:
        rwx = ''
        rwx += 'R' if s['flags'] & 4 else '-'
        rwx += 'W' if s['flags'] & 2 else '-'
        rwx += 'X' if s['flags'] & 1 else '-'
        print(f"  [{rwx}] off=0x{s['offset']:06x} vaddr=0x{s['vaddr']:08x}"
              f" filesz=0x{s['filesz']:x} memsz=0x{s['memsz']:x}")

    print(f"\n[Sections with content]")
    for s in secs:
        if s.get('name') and s['size'] > 0:
            print(f"  {s['name']:<24} off=0x{s['offset']:06x} addr=0x{s['addr']:08x}"
                  f" size=0x{s['size']:06x} ({s['size']:,} bytes)")

    print(f"\n[Total ASCII strings: {len(strings)}]")
    print(f"[Fastboot-related strings: {len(fb_strings)}]")

    for kw in sorted(fb_categorized):
        items = fb_categorized[kw]
        if items:
            print(f"\n  [{kw}] ({len(items)} matches)")
            for s in sorted(set(items)):
                print(f"    {s}")

    return fb_categorized

if __name__ == '__main__':
    if len(sys.argv) > 1:
        path = sys.argv[1]
    else:
        path = r'E:\develop\k80_reverse\firmware\extracted\v3.0.302.0\abl.elf'
    print_report(path)
