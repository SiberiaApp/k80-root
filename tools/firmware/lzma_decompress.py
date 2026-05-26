"""Decompress Qualcomm LZMA-compressed UEFI Firmware Volume from ABL."""
import struct
import lzma
import os
from pathlib import Path
from uuid import UUID

class FVDecompressor:
    """Extract and decompress Qualcomm LZMA-encapsulated FV from ABL."""

    # Known GUIDs
    GUID_LZMA_CUSTOM = UUID('{EE4E5898-3914-4259-9D6E-DC7BD79403CF}')
    GUID_LZMA_STD = UUID('{D42AE6BD-1352-4BFA-909A-CA23A4AF25B8}')
    COMPRESSION_GUIDS = {GUID_LZMA_CUSTOM, GUID_LZMA_STD}

    def __init__(self, data, base=0):
        self.data = data
        self.base = base

    def read24(self, offset):
        return self.data[offset] | (self.data[offset+1] << 8) | (self.data[offset+2] << 16)

    def parse_section_header(self, offset):
        """Parse EFI_COMMON_SECTION_HEADER (4 bytes)."""
        if offset + 4 > len(self.data):
            return None
        size = self.read24(offset)
        stype = self.data[offset + 3]
        return {'offset': offset, 'size': size, 'type': stype}

    def decompress_guid_defined(self, section_off):
        """Decompress a GUID_DEFINED section (type 0x02)."""
        hdr = self.parse_section_header(section_off)
        if not hdr or hdr['type'] != 0x02:
            return None

        # Parse GUID
        guid_bytes = self.data[section_off+4:section_off+20]
        guid = UUID(bytes_le=guid_bytes)

        # DataOffset (from section start)
        data_offset = struct.unpack('<H', self.data[section_off+20:section_off+22])[0]
        attributes = struct.unpack('<H', self.data[section_off+22:section_off+24])[0]

        print(f'  GUID_DEFINED at 0x{section_off:X}')
        print(f'    GUID: {guid}')
        print(f'    DataOffset: {data_offset}')
        print(f'    Attributes: 0x{attributes:04X}')

        payload_start = section_off + data_offset
        payload_size = hdr['size'] - data_offset

        if guid == self.GUID_LZMA_CUSTOM or guid == self.GUID_LZMA_STD:
            return self._decompress_lzma(payload_start, payload_size)
        else:
            print(f'    Unknown compression GUID, trying raw LZMA...')
            return self._decompress_lzma(payload_start, payload_size)

    def _decompress_lzma(self, offset, size):
        """Try to decompress LZMA data at offset."""
        if offset + 5 > len(self.data):
            return None

        # LZMA header: properties (1 byte) + dictionary size (4 bytes LE)
        # Qualcomm sometimes has an 8-byte uncompressed size before the LZMA stream
        compressed = self.data[offset:offset+size]

        # Try standard LZMA (properties + dict_size + compressed data)
        # LZMA prop: first byte
        lc = self.data[offset] % 9
        lp = (self.data[offset] // 9) % 5
        pb = self.data[offset] // 45
        dict_size = struct.unpack('<I', self.data[offset+1:offset+5])[0]

        print(f'    LZMA properties: lc={lc} lp={lp} pb={pb} dict_size={dict_size}')

        # Try to decompress
        filters = [{'id': lzma.FILTER_LZMA1,
                     'lc': lc, 'lp': lp, 'pb': pb,
                     'dict_size': dict_size if dict_size > 0 else 0x100000}]

        # The LZMA data starts after the 5-byte header
        lzma_data = compressed[5:]

        # For Qualcomm custom LZMA, they sometimes include uncompressed size
        # before the LZMA stream. Check if first 8 bytes look like a size.
        potential_size = struct.unpack('<Q', lzma_data[:8])[0]
        if 0 < potential_size < 100 * 1024 * 1024:  # reasonable uncompressed size
            uncompressed_size = potential_size
            real_lzma = lzma_data[8:]
            print(f'    Detected uncompressed size prefix: {uncompressed_size} bytes')
        else:
            uncompressed_size = lzma.FORMAT_AUTO
            real_lzma = lzma_data

        try:
            decompressor = lzma.LZMADecompressor(format=lzma.FORMAT_RAW, filters=filters)
            result = decompressor.decompress(real_lzma)
            print(f'    Decompressed: {len(result)} bytes')
            return result
        except Exception as e:
            print(f'    LZMA1 raw decompression failed: {e}')

        # Try with FORMAT_ALONE (has header)
        try:
            result = lzma.decompress(compressed, format=lzma.FORMAT_ALONE)
            print(f'    LZMA alone decompressed: {len(result)} bytes')
            return result
        except Exception as e:
            print(f'    LZMA alone failed: {e}')

        # Try skipping the Qualcomm custom header (try different offsets)
        for skip in range(0, min(32, len(compressed) - 5)):
            try:
                lc = compressed[skip] % 9
                lp = (compressed[skip] // 9) % 5
                pb = compressed[skip] // 45
                if lc > 8 or lp > 4 or pb > 4:
                    continue
                dict_sz = struct.unpack('<I', compressed[skip+1:skip+5])[0]
                if dict_sz == 0 or dict_sz > 256 * 1024 * 1024:
                    continue
                filters = [{'id': lzma.FILTER_LZMA1,
                             'lc': lc, 'lp': lp, 'pb': pb,
                             'dict_size': dict_sz}]
                decompressor = lzma.LZMADecompressor(format=lzma.FORMAT_RAW, filters=filters)
                result = decompressor.decompress(compressed[skip+5:])
                print(f'    Decompressed at skip={skip}: {len(result)} bytes')
                return result
            except:
                pass

        print('    All decompression attempts failed')
        return None


def main():
    base = Path(r'E:\develop\k80_reverse')
    src = base / 'firmware' / 'extracted' / 'v3.0.302.0' / 'abl.elf'
    out_dir = base / 'firmware' / 'extracted' / 'v3.0.302.0' / 'fv_decompressed'
    os.makedirs(out_dir, exist_ok=True)

    with open(src, 'rb') as f:
        data = f.read()

    # The FV_IMAGE file body starts at 0x1060
    # The GUID_DEFINED section header is at the body start
    decompressor = FVDecompressor(data)
    result = decompressor.decompress_guid_defined(0x1060)

    if result:
        out_path = out_dir / 'inner_fv.bin'
        with open(out_path, 'wb') as f:
            f.write(result)
        print(f'\nDecompressed FV saved to: {out_path}')
        print(f'Size: {len(result):,} bytes ({len(result)/1024:.1f} KB)')

        # Check if result is a Firmware Volume
        fvh = result.find(b'_FVH')
        if fvh >= 0:
            print(f'  _FVH found at offset 0x{fvh:X}')
            print(f'  This is a valid Firmware Volume!')
        else:
            print(f'  No _FVH found - may need additional parsing')
            # Show first bytes
            for i in range(4):
                off = i * 16
                hex_str = ' '.join('{:02x}'.format(b) for b in result[off:off+16])
                print(f'  {off:04x}: {hex_str}')
    else:
        print('Decompression failed')

if __name__ == '__main__':
    main()
