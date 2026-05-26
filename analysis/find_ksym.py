import struct

with open('path/to/kernel', 'rb') as f:
    data = f.read()

search_start = 0x10F3930

count = 0
for pos in range(search_start, search_start + 0x180000):
    if pos + 6 > len(data):
        break
    if data[pos] == 4 and data[pos+1:pos+5] == b'init':
        end = data.index(0, pos + 5) if 0 in data[pos+5:pos+30] else -1
        if end != -1:
            count += 1
            tokens = data[pos+5:end]
            print(f"{pos:#010x}: len=4 init tokens={tokens.hex()}")
            if count >= 20:
                print("...stopping")
                break

print(f"\nTotal: {count}")
