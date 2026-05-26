"""Parse UEFI Firmware Volume (FV) and extract FFS files from abl.elf."""
import struct
import os
from pathlib import Path
from uuid import UUID

# FFS File Types
FFS_TYPE_RAW = 0x01
FFS_TYPE_FREEFORM = 0x02
FFS_TYPE_SECURITY_CORE = 0x03
FFS_TYPE_PEI_CORE = 0x04
FFS_TYPE_DXE_CORE = 0x05
FFS_TYPE_PEIM = 0x06
FFS_TYPE_DRIVER = 0x07
FFS_TYPE_COMBINED_PEIM_DRIVER = 0x08
FFS_TYPE_APPLICATION = 0x09
FFS_TYPE_SMM = 0x0A
FFS_TYPE_FIRMWARE_VOLUME_IMAGE = 0x0B
FFS_TYPE_COMBINED_SMM_DXE = 0x0C
FFS_TYPE_SMM_CORE = 0x0D

FFS_TYPE_NAMES = {
    0x01: 'RAW',
    0x02: 'FREEFORM',
    0x03: 'SECURITY_CORE',
    0x04: 'PEI_CORE',
    0x05: 'DXE_CORE',
    0x06: 'PEIM',
    0x07: 'DRIVER',
    0x08: 'COMBINED_PEIM_DRIVER',
    0x09: 'APPLICATION',
    0x0A: 'SMM',
    0x0B: 'FV_IMAGE',
    0x0C: 'COMBINED_SMM_DXE',
    0x0D: 'SMM_CORE',
    0xF0: 'FFS_PAD',
}

# Known fastboot-related GUIDs
KNOWN_GUIDS = {
    # Qualcomm OEM fastboot
    'a547b8fa-5899-4b8d-9c51-d84db9de88b5': 'QcomFastbootProtocol',
    '8d92ee7e-f3ce-4940-8bba-2815a441cfb1': 'QcomFastbootApp',
    # Xiaomi custom
    'e29a60f1-3eba-49fc-84bd-0c52c1cd0a6c': 'XiaomiOemProtocol',
    # UEFI standard
    '8c8ce578-8a3d-4f1c-9935-896185c32dd3': 'EFI_FIRMWARE_FILE_SYSTEM2_GUID',
    '54760a7b-17eb-4554-91c6-57076a56d89a': 'EFI_FIRMWARE_FILE_SYSTEM3_GUID',
    '7a9354d9-0468-444a-81ce-0bf617d890df': 'EFI_FIRMWARE_FILE_SYSTEM_GUID',
    'd4d2e100-afec-4f38-94c3-17c8f5c1491c': 'EFI_FV_BLOCK_MAP_ENTRY_GUID',
}

def read_fv_header(data, base_offset=0):
    """Parse EFI_FIRMWARE_VOLUME_HEADER."""
    if base_offset + 0x28 + 4 > len(data):
        return None

    sig = data[base_offset+0x28:base_offset+0x2C]
    if sig != b'_FVH':
        # Search for _FVH signature
        idx = data.find(b'_FVH', base_offset)
        if idx < 0:
            return None
        base_offset = idx - 0x28

    zero_vector = data[base_offset:base_offset+16]
    fs_guid_bytes = data[base_offset+0x10:base_offset+0x20]
    fs_guid = UUID(bytes_le=fs_guid_bytes)
    fv_length = struct.unpack('<Q', data[base_offset+0x20:base_offset+0x28])[0]
    attributes = struct.unpack('<I', data[base_offset+0x2C:base_offset+0x30])[0]
    header_len = struct.unpack('<H', data[base_offset+0x30:base_offset+0x32])[0]
    checksum = struct.unpack('<H', data[base_offset+0x32:base_offset+0x34])[0]
    ext_header_off = struct.unpack('<H', data[base_offset+0x34:base_offset+0x36])[0]
    revision = data[base_offset+0x37]

    return {
        'base': base_offset,
        'fs_guid': str(fs_guid),
        'fs_guid_name': KNOWN_GUIDS.get(str(fs_guid), ''),
        'fv_length': fv_length,
        'attributes': attributes,
        'header_len': header_len,
        'checksum': checksum,
        'ext_header_off': ext_header_off,
        'revision': revision,
    }

def parse_ffs_header(data, offset):
    """Parse EFI_FFS_FILE_HEADER at given offset."""
    if offset + 24 > len(data):
        return None

    name_guid_bytes = data[offset:offset+16]
    name_guid = UUID(bytes_le=name_guid_bytes)

    # Integrity check - depends on attributes
    integrity_check = struct.unpack('<H', data[offset+16:offset+18])[0]
    file_type = data[offset+18]
    attributes = data[offset+19]
    # Size is 24-bit little-endian
    size_bytes = data[offset+20:offset+23] + b'\x00'
    size = struct.unpack('<I', size_bytes)[0]
    state = data[offset+23]

    # Ensure size is reasonable
    if size == 0 or size > 50 * 1024 * 1024:
        return None

    # Get section data
    # FFS header is 24 bytes, but alignment may add padding
    # The actual section starts after alignment
    header_size = 24  # Standard FFS header size

    # Check for extended header (if state has FFS_ATTRIB_LARGE_FILE or similar)
    # For now use standard 24-byte header

    return {
        'offset': offset,
        'name_guid': str(name_guid),
        'name_guid_name': KNOWN_GUIDS.get(str(name_guid), ''),
        'integrity_check': integrity_check,
        'type': file_type,
        'type_name': FFS_TYPE_NAMES.get(file_type, f'UNKNOWN(0x{file_type:02X})'),
        'attributes': attributes,
        'size': size,
        'state': state,
    }

def parse_fv(data, base_offset=0):
    """Parse a Firmware Volume and extract all FFS files."""
    fv = read_fv_header(data, base_offset)
    if not fv:
        return None, []

    header_end = fv['base'] + fv['header_len']
    fv_end = fv['base'] + fv['fv_length']

    files = []
    offset = header_end

    # Align to 8-byte boundary
    if offset % 8 != 0:
        offset += 8 - (offset % 8)

    while offset < fv_end - 24:
        ffs = parse_ffs_header(data, offset)
        if not ffs or ffs['size'] == 0:
            offset += 8  # Skip and try next alignment
            continue

        if ffs['type'] == 0xF0:  # PAD file
            offset += ffs['size']
            continue

        # Extract the file body (after header)
        # For standard FFS, body starts at offset + 24
        body_offset = offset + 24
        body_size = ffs['size'] - 24
        if body_offset + body_size <= len(data):
            ffs['body_offset'] = body_offset
            ffs['body_size'] = body_size

            # Check for PE32+ magic (UEFI executable)
            pe_magic = data[body_offset:body_offset+2]
            ffs['is_pe'] = (pe_magic == b'MZ')
            if pe_magic == b'MZ':
                # Read PE optional header to get machine type
                pe_offset = struct.unpack('<I', data[body_offset+0x3C:body_offset+0x40])[0]
                if body_offset + pe_offset + 4 <= len(data):
                    pe_sig = data[body_offset+pe_offset:body_offset+pe_offset+4]
                    if pe_sig == b'PE\x00\x00':
                        machine = struct.unpack('<H', data[body_offset+pe_offset+4:body_offset+pe_offset+6])[0]
                        ffs['pe_machine'] = machine
                        ffs['pe_machine_name'] = {0x014C:'i386', 0x8664:'x64', 0xAA64:'AArch64', 0x01C4:'ARM'}.get(machine, f'0x{machine:04X}')

        files.append(ffs)
        offset += ffs['size']

        # Align to 8-byte boundary
        if offset % 8 != 0:
            offset += 8 - (offset % 8)

    return fv, files

def extract_files(data, files, output_dir):
    """Extract FFS file bodies to disk."""
    os.makedirs(output_dir, exist_ok=True)
    extracted = []
    for f in files:
        if 'body_offset' not in f:
            continue
        body = data[f['body_offset']:f['body_offset']+f['body_size']]
        guid_short = f['name_guid'][:8]
        fname = f'{f["offset"]:06X}_{guid_short}_{f["type_name"]}.bin'
        if f['is_pe']:
            fname = f'{f["offset"]:06X}_{guid_short}_{f["type_name"]}_{f.get("pe_machine_name","PE")}.efi'
        fpath = os.path.join(output_dir, fname)
        with open(fpath, 'wb') as out:
            out.write(body)
        extracted.append((fpath, f))
    return extracted

def print_fv_report(fv, files, indent=0):
    prefix = '  ' * indent
    print(f"\n{prefix}{'='*70}")
    print(f"{prefix}UEFI Firmware Volume Analysis (level {indent})")
    print(f"{prefix}{'='*70}")
    print(f"{prefix}FV Base:       0x{fv['base']:X}")
    print(f"{prefix}FV Length:     {fv['fv_length']:,} bytes ({fv['fv_length']/1024:.1f} KB)")
    print(f"{prefix}Header Size:   {fv['header_len']} bytes")
    print(f"{prefix}FS GUID:       {fv['fs_guid']}")
    print(f"{prefix}FFS Files:     {len(files)}")

    type_counts = {}
    for f in files:
        tn = f['type_name']
        type_counts[tn] = type_counts.get(tn, 0) + 1
    print(f"\n{prefix}File types:")
    for tn, count in sorted(type_counts.items()):
        print(f"{prefix}  {tn}: {count}")

    print(f"\n{prefix}{'─'*70}")
    print(f"{prefix}{'Offset':<10} {'Size':<10} {'Type':<24} {'PE':<8} {'Name GUID'}")
    print(f"{prefix}{'─'*70}")

    for f in files:
        pe_info = f.get('pe_machine_name', '') if f.get('is_pe') else '-'
        body_sz = f.get('body_size', f['size']-24)
        guid_str = f['name_guid']
        known = f['name_guid_name']
        label = f'{guid_str}'
        if known:
            label = f'{guid_str}  [{known}]'
        print(f"{prefix}0x{f['offset']:06X}  {body_sz:>8,}  {f['type_name']:<24} {pe_info:<8} {label}")

    return files

def recursively_parse_fv(data, base_offset, indent=0, max_depth=5):
    """Recursively parse FV files, including nested FV_IMAGE files."""
    if max_depth <= 0:
        return

    fv, files = parse_fv(data, base_offset)
    if not fv:
        return

    print_fv_report(fv, files, indent)

    for f in files:
        if f['type'] == FFS_TYPE_FIRMWARE_VOLUME_IMAGE and 'body_offset' in f:
            prefix = '  ' * indent
            print(f"\n{prefix}  -> Nested FV at 0x{f['body_offset']:X} (GUID: {f['name_guid']})")
            # Check if compressed (look for compression GUID)
            compressed = False
            # Try to find _FVH in the body
            body = data[f['body_offset']:f['body_offset']+f['body_size']]
            if body[:4] != b'_FVH' and b'_FVH' in body[:256]:
                fvh_pos = body.find(b'_FVH')
                print(f"{prefix}  -> _FVH found at body+0x{fvh_pos:X}")
                recursively_parse_fv(data, f['body_offset'] + fvh_pos - 0x28, indent + 1, max_depth - 1)
            elif body[:4] == b'_FVH':
                recursively_parse_fv(data, f['body_offset'], indent + 1, max_depth - 1)
            else:
                print(f"{prefix}  -> No direct _FVH found, may be compressed/encapsulated")
                # Check for section headers
                if len(body) >= 4:
                    section_size = struct.unpack('<I', body[:3] + b'\x00')[0]
                    section_type = body[3]
                    print(f"{prefix}  -> First bytes: size={section_size}, type=0x{section_type:02X}")
                    # Try common section types
                    if section_type == 0x01:  # EFI_SECTION_COMPRESSION
                        print(f"{prefix}  -> Compressed section detected")
                        # Skip section header and try parsing
                    elif section_type == 0x02:  # EFI_SECTION_GUID_DEFINED
                        print(f"{prefix}  -> GUID-defined section (possibly compressed)")

def main():
    abl_path = Path(r'E:\develop\k80_reverse\firmware\extracted\v3.0.302.0\abl.elf')
    data = open(abl_path, 'rb').read()

    out_dir = Path(r'E:\develop\k80_reverse\firmware\extracted\v3.0.302.0') / 'fv_extracted'
    os.makedirs(out_dir, exist_ok=True)

    # Parse outer FV
    fv, files = parse_fv(data)
    if fv:
        print_fv_report(fv, files)

        # Extract outer FV files
        extracted = extract_files(data, files, str(out_dir))
        print(f"\n  Extracted {len(extracted)} outer files to: {out_dir}")

        # Recursively parse nested FVs
        print(f"\n{'='*70}")
        print("Recursively parsing nested FVs...")
        print(f"{'='*70}")
        for f in files:
            if f['type'] == FFS_TYPE_FIRMWARE_VOLUME_IMAGE and 'body_offset' in f:
                body = data[f['body_offset']:f['body_offset']+f['body_size']]
                # Search for _FVH signature
                fvh_offsets = []
                pos = 0
                while True:
                    idx = body.find(b'_FVH', pos)
                    if idx < 0:
                        break
                    fvh_offsets.append(idx - 0x28)
                    pos = idx + 4

                print(f"\n  FV_IMAGE at 0x{f['body_offset']:X} ({f['body_size']:,} bytes)")
                print(f"  GUID: {f['name_guid']}")
                print(f"  Found {len(fvh_offsets)} _FVH signature(s)")

                for fvh_pos in fvh_offsets:
                    if fvh_pos >= 0:
                        print(f"  Parsing FV at body+0x{fvh_pos:X}...")
                        recursively_parse_fv(data, f['body_offset'] + fvh_pos, indent=1, max_depth=3)

if __name__ == '__main__':
    main()
