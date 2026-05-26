"""Kallsyms parser: find symbol physical addresses from kernel Image.

Usage:
    python kallsyms_parser.py <kernel_image> [symbol_name]

Without symbol_name: dumps kallsyms_offsets, kallsyms_token_table size.
With symbol_name: prints FILE_OFFSET and PA for that symbol.

Example:
    python kallsyms_parser.py kernel selinux_state
    python kallsyms_parser.py kernel init_task
    python kallsyms_parser.py kernel __sys_setuid
"""

import struct
import sys

PHYS_BASE = 0xA8000000  # Kernel image loaded at this physical address

def find_offsets(data):
    """Find kallsyms_offsets array start and count."""
    # Search .rodata for longest ascending u32 sequence
    rodata_start = 0x800000
    rodata_end = min(len(data), 0x2100000)
    best_start, best_len = 0, 0
    for off in range(rodata_start, rodata_end, 4):
        v = struct.unpack_from('<I', data, off)[0]
        if v < 0x10000:
            continue
        seq_len, expected = 0, v
        for j in range(0, 500):
            if off + j * 4 >= rodata_end:
                break
            curr = struct.unpack_from('<I', data, off + j * 4)[0]
            if curr >= expected and curr - expected < 0x100000:
                seq_len += 1
                expected = curr
            else:
                break
        if seq_len > best_len:
            best_len, best_start = seq_len, off

    # Scan forward from best_start to count all valid offsets
    real_count, prev = 0, 0
    max_off = min(len(data) * 2, 0xC000000)
    for i in range(300000):
        if best_start + i * 4 + 4 > len(data):
            break
        v = struct.unpack_from('<I', data, best_start + i * 4)[0]
        if v < prev or v > max_off:
            break
        real_count = i + 1
        prev = v
    return best_start, real_count


def find_token_table(data, names_start):
    """Find token table start by scanning after names for token density + count."""
    # Walk names to find end
    pos = names_start
    for _ in range(300000):
        if pos >= len(data):
            break
        first = data[pos]
        if first == 0 or first > 200:
            break
        pos += first + 1
    names_end = pos

    best_count, best_start = 0, 0
    search_end = min(names_end + 0x80000, len(data) - 256)
    for scan in range(names_end, search_end, 256):
        win = data[scan:scan + 256]
        nulls = sum(1 for b in win if b == 0)
        printable = sum(1 for b in win if 0x20 <= b <= 0x7E)
        if nulls < 30 or printable < 100:
            continue
        # Backtrack to find token block start, then count consecutive tokens
        for back in range(scan, max(names_end, scan - 1024), -1):
            if data[back] != 0:
                continue
            cand = back + 1
            if cand >= len(data):
                continue
            p2, tok_cnt = cand, 0
            for _ in range(500):
                if p2 >= len(data) or (data[p2] > 0x7E or data[p2] < 0x20) and data[p2] != 0:
                    p2 += 1
                    continue
                if data[p2] == 0:
                    p2 += 1
                    continue
                start2 = p2
                while p2 < len(data) and data[p2] != 0:
                    if data[p2] > 0x7E or data[p2] < 0x20:
                        break
                    p2 += 1
                if p2 < len(data) and data[p2] == 0:
                    p2 += 1
                    tok_cnt += 1
                else:
                    break
            if tok_cnt > best_count:
                best_count = tok_cnt
                best_start = cand
    return best_start


def find_token_index(data, tok_start):
    """Find token_index: 256 x u16 offsets into token table.
    
    Search from tok_start forward for 256 consecutive u16 values that
    all reference offsets within the nearby token table region.
    """
    # Walk tokens to estimate token table size
    p, tok_count = tok_start, 0
    while p < len(data) and tok_count < 500:
        if data[p] == 0 or data[p] > 0x7E or data[p] < 0x20:
            p += 1
            continue
        while p < len(data) and data[p] != 0:
            if data[p] > 0x7E or data[p] < 0x20:
                break
            p += 1
        if p < len(data) and data[p] == 0:
            tok_count += 1
            p += 1
        else:
            break

    # Search for 256 valid u16 values starting from tok_start onward
    # Use generous size estimate to cover variations
    search_end = min(p + 0x20000, len(data))
    for pos in range(tok_start + 4, search_end, 2):
        ok = True
        max_idx = 0
        for i in range(256):
            if pos + i * 2 + 2 > len(data):
                ok = False
                break
            v = struct.unpack_from('<H', data, pos + i * 2)[0]
            max_idx = max(max_idx, v)
            if v > 0x8000:  # generous max token table size
                ok = False
                break
        if ok and max_idx > 0 and max_idx < pos - tok_start + 0x2000:
            return pos
    return 0


def walk_names(data, names_start, num_syms):
    """Walk kallsyms_names entries and count symbols."""
    count = 0
    pos = names_start
    while pos < len(data) and count < num_syms:
        first = data[pos]
        if first == 0 or first > 200:
            break
        count += 1
        pos += first + 1
    return count


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        return

    kernel_path = sys.argv[1]
    search_name = sys.argv[2] if len(sys.argv) > 2 else None

    with open(kernel_path, 'rb') as f:
        data = f.read()

    print(f"Kernel size: {len(data):#x}")

    # Step 1: find kallsyms_offsets
    offsets_start, offsets_count = find_offsets(data)
    print(f"kallsyms_offsets at {offsets_start:#010x}, {offsets_count} entries")

    names_start = offsets_start + offsets_count * 4
    # Scan for first valid name entry: byte 1-200, <=100 for first entries,
    # and the following entry also has a valid length.
    best_ns, best_walked = names_start, 0
    for drift in range(48):
        ns_cand = names_start + drift
        if ns_cand + 1 >= len(data):
            break
        first = data[ns_cand]
        if first == 0 or first > 200:
            continue
        if first > 100:   # first symbol typically short, reject likely misalignment
            continue
        walk_pos, walked = ns_cand, 0
        for _ in range(10000):
            if walk_pos >= len(data):
                break
            f = data[walk_pos]
            if f == 0 or f > 200:
                break
            walked += 1
            walk_pos += f + 1
        if walked > best_walked:
            best_walked = walked
            best_ns = ns_cand
    names_start = best_ns
    print(f"kallsyms_names at {names_start:#010x}")

    # Step 3: count symbols
    num_syms = walk_names(data, names_start, 300000)
    print(f"Symbols: {num_syms}")

    # Step 4: find token table (after names)
    tok_pos = find_token_table(data, names_start)
    if not tok_pos:
        print("ERROR: Could not find token table")
        return
    tok_end = tok_pos
    # Count tokens to find end (same logic as find_token_index)
    p = tok_pos
    for _ in range(500):
        if p >= len(data):
            break
        if data[p] == 0 or data[p] > 0x7E or data[p] < 0x20:
            p += 1
            continue
        while p < len(data) and data[p] != 0:
            if data[p] > 0x7E or data[p] < 0x20:
                break
            p += 1
        if p < len(data) and data[p] == 0:
            p += 1
        else:
            break
    tok_end = p
    print(f"Token table: {tok_pos:#010x}, ends {tok_end:#010x}")

    # Step 5: find token index
    ti_start = find_token_index(data, tok_pos)
    if not ti_start:
        print("ERROR: Could not find token index")
        return
    token_index = [struct.unpack_from('<H', data, ti_start + i * 2)[0] for i in range(256)]
    print(f"Token index at {ti_start:#010x}")

    if not search_name:
        print("\nReady. Run again with a symbol name to search:")
        print(f"  python {sys.argv[0]} {kernel_path} <symbol>")
        return

    # Step 6: search for symbol
    pos = names_start
    for idx in range(num_syms):
        if pos >= len(data):
            break
        first = data[pos]
        if first == 0 or first > 200:
            break

        token_bytes = data[pos + 1:pos + 1 + first]
        result = []
        skipped_first = False
        for b in token_bytes:
            offset = token_index[b]
            tok_addr = tok_pos + offset
            end = data.index(0, tok_addr) if 0 in data[tok_addr:tok_addr + 50] else tok_addr + 50
            token = data[tok_addr:end].decode('ascii', errors='replace')
            if not skipped_first:
                token = token[1:]  # skip first char of first token (kallsyms convention)
                skipped_first = True
            result.append(token)

        name = ''.join(result)
        if name == search_name:
            file_offset = struct.unpack_from('<I', data, offsets_start + idx * 4)[0]
            pa = file_offset + PHYS_BASE
            print(f"\n  {search_name}:")
            print(f"    kallsyms index: {idx}")
            print(f"    FILE_OFFSET:   {file_offset:#010x}")
            print(f"    PA:            {pa:#018x}")
            return

        pos += first + 1

    print(f"\n  {search_name}: NOT FOUND")
    print("  Try checking /proc/kallsyms to confirm symbol exists.")


if __name__ == '__main__':
    main()
