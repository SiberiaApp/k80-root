"""查找 kallsyms_token_index：kallsyms_names 之后 256 个有序 u16 偏移。"""
import struct

with open('path/to/kernel', 'rb') as f:
    data = f.read()

names_end = 0x01268743
search_start = names_end
search_end = min(names_end + 0x200000, len(data))

best_count = 0
best_pos = 0

for pos in range(search_start, search_end, 2):
    if pos + 2 * 256 > len(data):
        break
    
    # 检查是否为有序 u16 序列
    prev = struct.unpack_from('<H', data, pos)[0]
    
    # 跳过太大值（token table 偏移不会超过 50000）
    if prev > 50000:
        continue
    
    count = 1
    valid = True
    for j in range(1, 256):
        curr = struct.unpack_from('<H', data, pos + j * 2)[0]
        if curr >= prev and curr < prev + 100:  # token 偏移小幅递增
            count += 1
            prev = curr
        else:
            valid = False
            break
    
    if count > best_count:
        best_count = count
        best_pos = pos
        if count >= 200:
            entries = [struct.unpack_from('<H', data, pos + j * 2)[0] for j in range(min(count, 15))]
            print(f'{count} sorted u16s at {pos:#010x}: first={entries}')
            if count >= 250:
                print(f'\n!!! TOKEN INDEX at {pos:#010x}')
                # 展示所有条目
                for j in range(0, 256, 32):
                    entries = [struct.unpack_from('<H', data, pos + (j+i) * 2)[0] for i in range(min(32, 256-j))]
                    print(f'  [{j:3d}]: {entries}')
                break

print(f'\nBest: {best_count} sorted u16s at {best_pos:#010x}')
