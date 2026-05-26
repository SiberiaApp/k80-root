"""通过解压符号名查找 selinux_state。"""
import struct

VA_BASE = 0xFFFFFFC00A000000
PHYS_BASE = 0xA8000000

with open('path/to/kernel', 'rb') as f:
    data = f.read()

# kallsyms_offsets @ 0x0108E664，紧随 kallsyms_names
# offsets 值域 [0, 内核镜像大小]

offsets_start = 0x0108E664
offsets_end_candidates = []

# 搜索 offsets 末尾（值超出 kernel 镜像范围时切换到 kallsyms_names）

for off in range(offsets_start + 4, min(offsets_start + 0x100000, len(data)), 4):
    v = struct.unpack_from('<I', data, off)[0]
    if v >= 0x2370000 or v == 0:
        # 可能是 offsets 的末尾，检查后续字节是否像 kallsyms_names
        next_bytes = data[off:off+20]
        if len(next_bytes) >= 4:
            b0, b1, b2, b3 = next_bytes[0], next_bytes[1], next_bytes[2], next_bytes[3]
            # kallsyms_names 条目以小长度字节开头（1-127）或 token 索引
            if b0 < 128 and b1 < 128:
                offsets_end_candidates.append((off, v))

print('可能的 offsets 末尾候选:')
for off, final_v in offsets_end_candidates[:15]:
    num_syms = (off - offsets_start) // 4
    kallsyms_names_start = off
    # 打印后续字节
    ns_bytes = data[off:off+24]
    hex_str = ' '.join(f'{b:02x}' for b in ns_bytes)
    # 解析第一个条目
    if ns_bytes[0] > 0 and ns_bytes[0] < 128:
        first_name_len = ns_bytes[0]
        first_literal = data[off+1:off+1+first_name_len]
        try:
            lit_str = first_literal.decode('ascii')
        except:
            lit_str = repr(first_literal)
        tokens = data[off+1+first_name_len:off+16]
        print(f'  end={off:#010x} num_syms={num_syms} final_val={final_v:#010x}')
        print(f'    kallsyms_names starts: {hex_str}')
        print(f'    first entry: literal="{lit_str}" tokens={tokens.hex()}')
        print()

# 检查 .rodata 末尾（kallsyms_token_table 通常在这里，__end_rodata 之前）
print('.data 段之前的最后非零数据 (0x20A7000 区域):')
for off in range(0x020A6000, 0x020A7000, 4):
    v = struct.unpack_from('<I', data, off)[0]
    if v != 0:
        print(f'  {off:#010x}: {v:#010x}')

# 搜索 kallsyms_token_table 模式：256 个 u16 索引，指向紧凑字符串块
