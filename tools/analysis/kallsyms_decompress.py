"""解压所有 kallsyms 符号，找到 selinux_state。"""
import struct

with open('path/to/kernel', 'rb') as f:
    data = f.read()

offsets_start = 0x0108E664
names_start = 0x010F3938
token_table = 0x012B4BB8
token_index_start = 0x012B4F3A

# 读 token_index（256 个 u16）
token_index = [struct.unpack_from('<H', data, token_index_start + i * 2)[0] for i in range(256)]

# 读 token table 字符串
token_strings = []
tok_pos = token_table
while tok_pos < token_index_start:
    end = data.index(0, tok_pos) if 0 in data[tok_pos:tok_pos + 50] else tok_pos + 1
    token = data[tok_pos:end].decode('ascii', errors='replace')
    token_strings.append(token)
    tok_pos = end + 1

print(f'Tokens: {len(token_strings)}')
print(f'Token index entries: {len(token_index)}')

# 解压单个符号
def decompress_symbol(idx):
    """解压指定索引的符号，返回 (name, next_offset)。"""
    # 在 kallsyms_names 中定位条目
    pos = names_start
    for i in range(idx):
        if pos >= len(data):
            return None, -1
        first = data[pos]
        pos += first + 1
    
    # pos 现在指向该条目
    first = data[pos]
    entry_len = first
    token_bytes = data[pos + 1:pos + 1 + entry_len]
    
    # 用 token 构建符号名
    result = []
    skipped_first = False
    
    for b in token_bytes:
        offset = token_index[b]
        # 找到该 offset 对应的 token
        tok_addr = token_table + offset
        end = data.index(0, tok_addr) if 0 in data[tok_addr:tok_addr + 50] else tok_addr + 50
        token = data[tok_addr:end].decode('ascii', errors='replace')
        
        if not skipped_first:
            # 跳过第一个 token 的首字符（kallsyms 约定）
            token = token[1:]
            skipped_first = True
        
        result.append(token)
    
    name = ''.join(result)
    next_pos = pos + first + 1
    return name, next_pos

# 统计总符号数，同时找 selinux_state
total = 0
pos = names_start
while pos < len(data) and total < 103600:
    first = data[pos]
    if first == 0 or first > 200:
        break
    total += 1
    pos += first + 1

print(f'Total symbols: {total}')

# 搜索 selinux_state
found_idx = -1
pos = names_start
for idx in range(total):
    if pos >= len(data):
        break
    first = data[pos]
    if first == 0 or first > 200:
        break
    
    token_bytes = data[pos + 1:pos + 1 + first]
    
    # 构建名字并搜索
    result = []
    skipped_first = False
    for b in token_bytes:
        offset = token_index[b]
        tok_addr = token_table + offset
        end = data.index(0, tok_addr) if 0 in data[tok_addr:tok_addr + 50] else tok_addr + 50
        token = data[tok_addr:end].decode('ascii', errors='replace')
        if not skipped_first:
            token = token[1:] if len(token) > 0 else ''
            skipped_first = True
        result.append(token)
    
    name = ''.join(result)
    if name == 'selinux_state':
        found_idx = idx
        file_offset = struct.unpack_from('<I', data, offsets_start + idx * 4)[0]
        pa = file_offset + 0xA8000000
        print(f'\n!!! 找到 selinux_state，索引 {idx}')
        print(f'  file_offset = {file_offset:#010x}')
        print(f'  PA = {pa:#018x}')
        break
    
    pos += first + 1
    
    if idx % 20000 == 0:
        print(f'  已搜索 {idx} 个符号... 最近: {name}')

if found_idx == -1:
    print('selinux_state 未找到')
else:
    print(f'\nselinux_state PA = {file_offset + 0xA8000000:#018x}')
    print(f'KASLR 偏移后: VA = PA - 0xA8000000 + 0xFFFFFFC00A000000 + KASLR_SLIDE')
