# 工具说明

## 一、找地址（`analysis/`）

手动定位 kallsyms 四大结构的脚本，是实际找到 PA 的完整过程：

1. `find_token_table.py` → 定位 token_table（密集 ASCII 字符串块）
2. `find_token_index.py` → 定位 token_index（256×u16 数组）
3. `kallsyms_decompress.py` → 把上面找到的地址硬编码进去，解压全部符号名找目标
4. `find_ksym.py` → 搜索单个符号
5. `find_kallsyms_selinux.py` → 上述过程的早期版本，保留作参考

> 自动化脚本 `kallsyms/kallsyms_parser.py` 适配过 Qualcomm 魔改内核但大概率失败。正规流程是跑上面这套手动脚本。

## 二、离线 kallsyms 解析（`kallsyms/`、自动尝试）

### kallsyms_parser.py
```bash
python tools/kallsyms/kallsyms_parser.py kernel selinux_state
```

### find_bss_vars.py
通过 ADRP 指令引用频次找 BSS 段被频繁访问的变量。

## 三、固件解析（`firmware/`）

| 脚本 | 功能 |
|------|------|
| `fv_parser.py` | 解析 UEFI Firmware Volume (ABL 等) |
| `lzma_decompress.py` | 解压 LZMA 压缩的固件模块 |
| `elf_info.py` | 显示 ELF 文件结构 |

## 四、提取 kernel 文件

从 Fastboot 线刷包的 `images/boot.img` 解包得到 `kernel`：
```bash
unpack_bootimg --boot_img images/boot.img --out boot_extracted
# 或
magiskboot unpack images/boot.img
```
