#!/usr/bin/env python3
"""
PG 纹理文件解密工具 — 两层解密方案

加密方案：
  第1层 (DeEncrypt): 文件头部 XOR 0x18
    - 密钥来源: 'a'^'b'^'c'^'d'^'u'^'i' = 0x18
    - 函数: libcocos2djs.so @ 0x858268 (DeEncrypt)
    - 对于仅第1层的文件: 全文件 XOR 0x18 即可得到有效 PNG

  第2层 (PVR): IDAT 压缩数据 XOR 128-bit 密钥
    - ccSetPvrEncryptionKey(key0, key1, key2, key3) @ 0x3F6A0C
    - 16 字节 XOR 密钥由 4 个 uint32 组成 (little-endian)
    - 已确认: key[0] = key[1] = 0x18 (前 2 字节)
    - 剩余 14 字节未知 → 1742 个文件暂无法完全解密

  文件统计:
    - 467 个文件 (21.1%): 仅第1层加密 → 可直接解密为 PNG
    - 1742 个文件 (78.9%): 双层加密 → 需要 PVR 密钥

用法:
    python pg_decrypt.py <input.pg> [output.png]     # 解密单个文件
    python pg_decrypt.py <input_dir> [output_dir]    # 批量解密目录
    python pg_decrypt.py --check <file.pg>            # 检查文件加密类型
    python pg_decrypt.py --info <file.pg>             # 显示文件加密详情
"""

import os
import sys
import struct
import zlib

XOR_KEY = 0x18
PNG_HEADER = b'\x89PNG\r\n\x1a\n'

# PVR 密钥已确认部分
PVR_KNOWN_KEY = bytes([0x18, 0x18])  # key[0], key[1]


def find_idat_boundary(data):
    """在 .pg 数据中找到 IDAT chunk 的起始偏移。

    XOR 0x18 只应用于文件的前 min(1000, datalen) 字节。
    如果 IDAT chunk 起始位置 < 1000，则 chunk header 被 XOR 过；
    如果 >= 1000，则 chunk header 是 plain 的。

    返回 (offset, length) 或 (-1, 0)。
    """
    datalen = len(data)
    xor_limit = min(1000, datalen)

    # 先部分解密：XOR bytes 0 到 xor_limit-1
    partial = bytes(b ^ XOR_KEY if i < xor_limit else b
                    for i, b in enumerate(data))

    # 搜索 IDAT（现在应该可读了）
    idat_pos = partial.find(b'IDAT')
    if idat_pos < 0:
        return -1, 0
    chunk_start = idat_pos - 4
    if chunk_start < 0:
        return -1, 0
    length = struct.unpack('>I', partial[chunk_start:idat_pos])[0]
    if length > 100 * 1024 * 1024:
        return -1, 0
    return chunk_start, length


def collect_idat_chunks(data):
    """从已解密（部分或全部）的 PNG 数据中收集所有 IDAT chunk 数据。

    PNG 中 IDAT 可能分多个 chunk 存储，需要全部拼接再解压。
    返回所有 IDAT chunk 数据的拼接结果。
    """
    if data[:8] != PNG_HEADER:
        return b''

    pos = 8
    idat_parts = []
    while pos + 8 <= len(data):
        if pos + 4 > len(data):
            break
        length = struct.unpack('>I', data[pos:pos+4])[0]
        if length > 100 * 1024 * 1024 or pos + 4 + 4 + length + 4 > len(data):
            break
        chunk_type = data[pos+4:pos+8]
        if chunk_type == b'IDAT':
            idat_parts.append(data[pos+8:pos+8+length])
        elif chunk_type == b'IEND':
            break
        pos += 4 + 4 + length + 4

    return b''.join(idat_parts)


def is_valid_png(data):
    """检查数据是否为有效 PNG（能解析 chunk 且 IDAT 可解压）。"""
    idat_combined = collect_idat_chunks(data)
    if not idat_combined:
        return False

    try:
        zlib.decompress(idat_combined)
        return True
    except zlib.error:
        return False


def decrypt_pg_file(input_path):
    """解密 .pg 文件。

    加密方案:
    1. DeEncrypt XOR 0x18 作用于前 min(1000, datalen) 字节
    2. PVR 密钥（如果设置）作用于 IDAT 数据部分

    返回 (png_data, is_pvr_encrypted) 元组。
    """
    with open(input_path, 'rb') as f:
        raw = f.read()

    if bytes(b ^ XOR_KEY for b in raw[:8]) != PNG_HEADER:
        raise ValueError(f"Not a valid PG file: {input_path}")

    # 找到 IDAT chunk
    idat_chunk_start, idat_len = find_idat_boundary(raw)
    if idat_chunk_start < 0:
        raise ValueError(f"No IDAT chunk found in: {input_path}")

    # DeEncrypt XOR 0x18: 只作用前 min(1000, len(raw)) 字节
    xor_limit = min(1000, len(raw))
    png_data = bytes(b ^ XOR_KEY if i < xor_limit else b
                      for i, b in enumerate(raw))

    if is_valid_png(png_data):
        return png_data, False

    return png_data, True


def get_pg_status(input_path):
    """检查 .pg 文件的加密状态。"""
    try:
        _, is_pvr = decrypt_pg_file(input_path)
        return 'pvr' if is_pvr else 'plain'
    except ValueError:
        return 'invalid'


def decrypt_pg(input_path, output_path):
    """解密单个 .pg 文件（仅适用于 plain 类型）。"""
    png_data, is_pvr = decrypt_pg_file(input_path)

    if is_pvr:
        raise ValueError(f"PVR-encrypted file, cannot decrypt yet: {input_path}")

    os.makedirs(os.path.dirname(output_path) or '.', exist_ok=True)
    with open(output_path, 'wb') as f:
        f.write(png_data)
    return len(png_data)


def batch_decrypt(input_dir, output_dir):
    """批量解密目录下所有可解密的 .pg 文件。"""
    total = plain_count = pvr_count = errors = 0

    for root, dirs, files in os.walk(input_dir):
        for fname in files:
            if not fname.endswith('.pg'):
                continue
            filepath = os.path.join(root, fname)
            rel_path = os.path.relpath(filepath, input_dir)
            out_path = os.path.join(output_dir, rel_path[:-3] + '.png')

            total += 1
            try:
                png_data, is_pvr = decrypt_pg_file(filepath)

                if is_pvr:
                    pvr_count += 1
                    print(f"  [{total}] PVR    {rel_path} ({len(png_data):,}B)")
                else:
                    plain_count += 1
                    os.makedirs(os.path.dirname(out_path), exist_ok=True)
                    with open(out_path, 'wb') as f:
                        f.write(png_data)
                    print(f"  [{total}] PLAIN  {rel_path} ({len(png_data):,}B)")

            except ValueError as e:
                errors += 1
                print(f"  [{total}] ERROR  {rel_path}: {e}")
            except Exception as e:
                errors += 1
                print(f"  [{total}] ERROR  {rel_path}: {e}")

    return total, plain_count, pvr_count, errors


def get_pg_info(filepath):
    """显示 .pg 文件的加密详细信息。"""
    with open(filepath, 'rb') as f:
        raw = f.read()

    # 第1层验证：头部 XOR 0x18 检查
    header_check = bytes(b ^ XOR_KEY for b in raw[:8])
    png_ok = header_check == PNG_HEADER

    print(f"File: {filepath} ({len(raw):,} bytes)")
    print(f"  PNG header check: {'OK' if png_ok else 'FAIL'}")

    if not png_ok:
        return

    # 找到 IDAT 位置（在部分解密后）
    idat_start, idat_len = find_idat_boundary(raw)
    if idat_start < 0:
        print("  No IDAT chunk found")
        return

    # 第1层部分解密（匹配 DeEncrypt 行为）
    xor_limit = min(1000, len(raw))
    partial = bytes(b ^ XOR_KEY if i < xor_limit else b
                    for i, b in enumerate(raw))

    print(f"  DeEncrypt XOR limit: {xor_limit} bytes")
    print(f"  First IDAT chunk: offset={idat_start}, data_len={idat_len}")

    # 收集所有 IDAT chunk 数据（可能有多个 IDAT chunk 分片）
    all_idat = collect_idat_chunks(partial)
    print(f"  Total IDAT data: {len(all_idat):,} bytes across all IDAT chunks")
    idat_data = all_idat

    print(f"  IDAT[0:16]: {idat_data[:16].hex() if idat_data else 'N/A'}")

    # 检查 IDAT 是否为有效 zlib
    if idat_data:
        try:
            zlib.decompress(idat_data)
            print(f"  IDAT: PLAIN zlib (fully decryptable)")
        except zlib.error:
            print(f"  IDAT: PVR ENCRYPTED (needs 128-bit XOR key)")
            print(f"  Known key bytes: {PVR_KNOWN_KEY.hex()} (key[0], key[1])")
            print(f"  Unknown: 14 bytes remaining")

            # 检查 zlib 头期望值
            expected_first = 0x78
            key_first_byte = idat_data[0] ^ expected_first
            print(f"  PVR key[0] (from zlib header check): 0x{key_first_byte:02x}")

    # 显示 chunk 结构（从部分解密的数据中解析）
    print(f"  Chunk structure (partially XOR 0x18 decrypted):")
    pos = 8
    while pos + 8 <= len(partial) and pos < 2000:
        length = struct.unpack('>I', partial[pos:pos+4])[0]
        if length > 100 * 1024 * 1024:
            print(f"    (corrupt length at pos {pos})")
            break
        chunk_type = partial[pos+4:pos+8]
        display_type = chunk_type.decode('ascii', errors='replace')
        print(f"    pos={pos:5d}  {display_type:5s}  {length:8,} bytes")
        if chunk_type == b'IEND':
            break
        pos += 4 + 4 + length + 4
        if pos > len(partial):
            break




def main():
    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(1)

    if sys.argv[1] == '--check':
        if len(sys.argv) < 3:
            print("Usage: python pg_decrypt.py --check <file.pg>")
            sys.exit(1)
        status = get_pg_status(sys.argv[2])
        labels = {'plain': 'PLAIN (fully decryptable)', 'pvr': 'PVR (needs key)',
                   'invalid': 'INVALID'}
        print(f"{labels.get(status, status)}: {sys.argv[2]}")
        return

    if sys.argv[1] == '--info':
        if len(sys.argv) < 3:
            print("Usage: python pg_decrypt.py --info <file.pg>")
            sys.exit(1)
        get_pg_info(sys.argv[2])
        return

    input_path = sys.argv[1]

    if os.path.isfile(input_path):
        output_path = sys.argv[2] if len(sys.argv) > 2 else input_path[:-3] + '.png'
        try:
            size = decrypt_pg(input_path, output_path)
            print(f"Decrypted: {input_path} -> {output_path} ({size:,} bytes)")
        except ValueError as e:
            print(f"Error: {e}")
            sys.exit(1)

    elif os.path.isdir(input_path):
        output_dir = sys.argv[2] if len(sys.argv) > 2 else input_path + '_decrypted'
        print(f"Batch decrypt: {input_path} -> {output_dir}")
        print(f"Layer 1: XOR 0x{XOR_KEY:02X}")
        print(f"Layer 2: PVR 128-bit key (known: key[0]=key[1]=0x18, 14 bytes unknown)")
        print()
        total, plain, pvr, errors = batch_decrypt(input_path, output_dir)
        print(f"\nResults: {total} files total")
        print(f"  Plain (decrypted): {plain} ({plain/total*100:.1f}%)" if total else "")
        print(f"  PVR (need key):    {pvr} ({pvr/total*100:.1f}%)" if total else "")
        print(f"  Errors:            {errors}" if errors else "")

    else:
        print(f"Error: '{input_path}' not found")
        sys.exit(1)


if __name__ == '__main__':
    main()
