"""查找 kallsyms token table（kallsyms_names 之后的密集 ASCII 字符串块）。"""
import struct

with open('path/to/kernel', 'rb') as f:
    data = f.read()

names_end = 0x01268743
best_count = 0
best_pos = 0

for pos in range(names_end, min(names_end + 0x80000, len(data))):
    if pos + 3 > len(data):
        break
    
    tlen = data[pos]
    if tlen < 1 or tlen > 20:
        continue
    
    ok = True
    for j in range(tlen):
        if pos + 1 + j >= len(data):
            ok = False
            break
        b = data[pos + 1 + j]
        if b < 0x20 or b > 0x7E:
            ok = False
            break
    if not ok:
        continue
    
    next_pos = pos + 1 + tlen
    if next_pos + 2 >= len(data):
        continue
    
    next_len = data[next_pos]
    if next_len < 1 or next_len > 20:
        continue
    
    count = 2
    p = next_pos
    while p < len(data) and count < 200:
        tlen = data[p]
        if tlen < 1 or tlen > 20:
            break
        ok = True
        for j in range(tlen):
            if p + 1 + j >= len(data):
                ok = False
                break
            if data[p + 1 + j] < 0x20 or data[p + 1 + j] > 0x7E:
                ok = False
                break
        if not ok:
            break
        count += 1
        p += 1 + tlen
    
    if count > best_count:
        best_count = count
        best_pos = pos
        if count >= 30:
            tokens = []
            p = pos
            for _ in range(min(count, 30)):
                tlen = data[p]
                tok = bytes(data[p+1:p+1+tlen]).decode('ascii')
                tokens.append(tok)
                p += 1 + tlen
            print(f'{count} tokens at {pos:#010x}: {tokens[:15]}')
            if count >= 100:
                print(f'\n!!! 可能是 TOKEN TABLE，位置 {pos:#010x}，{count} 条目')
                break

print(f'\n最佳: {best_count} tokens at {best_pos:#010x}')

# 展示 token table 数据
if best_count >= 100:
    print(f'\nToken table 前 200 字节:')
    for i in range(best_pos, best_pos + 200, 16):
        chunk = data[i:i+16]
        h = ' '.join(f'{b:02x}' for b in chunk)
        a = ''.join(chr(b) if 32 <= b < 127 else '.' for b in chunk)
        print(f'  {i:#010x}: {h}  {a}')
