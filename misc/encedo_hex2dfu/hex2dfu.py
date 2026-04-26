#!/usr/bin/env python3

import argparse
import binascii
import struct
import sys
from pathlib import Path


TARGET_NAME_ENCEDO = "EncedoKey"


def parse_int(value: str) -> int:
    return int(value, 0)


def get32le(buf: bytes, offset: int) -> int:
    return struct.unpack_from("<I", buf, offset)[0]


def set32le(buf: bytearray, offset: int, value: int) -> None:
    struct.pack_into("<I", buf, offset, value & 0xFFFFFFFF)


def parse_ihex(path: Path) -> tuple[int, bytearray]:
    start_address = None
    upper = 0
    image = bytearray()
    total = 0

    with path.open("r", encoding="ascii", newline="") as handle:
        for line_no, raw_line in enumerate(handle, start=1):
            line = raw_line.strip()
            if not line:
                continue
            if not line.startswith(":"):
                continue

            try:
                record = bytes.fromhex(line[1:])
            except ValueError as exc:
                raise ValueError(f"{path}:{line_no}: invalid hex record") from exc

            if (sum(record) & 0xFF) != 0:
                raise ValueError(f"{path}:{line_no}: checksum mismatch")

            count = record[0]
            address = (record[1] << 8) | record[2]
            record_type = record[3]
            data = record[4:4 + count]

            if record_type == 0x04:
                if count != 2:
                    raise ValueError(f"{path}:{line_no}: invalid extended linear address record")
                upper = ((data[0] << 8) | data[1]) << 16
            elif record_type == 0x01:
                break
            elif record_type == 0x00:
                absolute = upper + address
                if start_address is None:
                    start_address = absolute

                relative = absolute - start_address
                needed = relative + count
                if needed > len(image):
                    image.extend(b"\x00" * (needed - len(image)))

                image[relative:relative + count] = data
                total = max(total, needed)

    if start_address is None:
        raise ValueError(f"{path}: no Intel HEX data records found")

    return start_address, image[:total]


def apply_openblt_vector_crc(image: bytearray, offset: int) -> None:
    if offset + 4 > len(image):
        raise ValueError(f"OpenBLT CRC position {offset:#x} outside image of {len(image)} bytes")

    checksum = 0
    for vector_offset in range(0, 0x1C, 4):
        checksum = (checksum + get32le(image, vector_offset)) & 0xFFFFFFFF

    checksum = (~checksum + 1) & 0xFFFFFFFF
    set32le(image, offset, checksum)


def apply_crc_metadata(image: bytearray, absolute_address: int, start_address: int) -> bool:
    if absolute_address <= 0:
        return False

    relative = absolute_address - start_address
    if relative < 0 or absolute_address >= (start_address + len(image) - 256):
        return False

    if relative + 8 > len(image):
        raise ValueError(f"CRC metadata position {absolute_address:#x} outside image")

    struct.pack_into("<I", image, relative + 4, len(image))
    crc = binascii.crc32(image[:relative]) & 0xFFFFFFFF
    crc = binascii.crc32(image[relative + 4:], crc) & 0xFFFFFFFF
    struct.pack_into("<I", image, relative, crc)
    return True


def write_binary(path: Path, payload: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(payload)


def build_dfu(images: list[tuple[int, bytes]], target_label: str | None, vid: int, pid: int, version: int) -> bytes:
    total_len = sum(len(image) for _, image in images)
    image_count = len(images)
    dfu_len = 11 + 274 + (8 * image_count) + total_len + 16

    dfu = bytearray(dfu_len)
    dfu[0:5] = b"DfuSe"
    dfu[5] = 0x01
    struct.pack_into("<I", dfu, 6, dfu_len - 0x10)
    dfu[10] = 1

    offset = 11
    dfu[offset:offset + 6] = b"Target"
    offset += 6
    dfu[offset] = 0x00
    label = (target_label or TARGET_NAME_ENCEDO).encode("ascii", errors="ignore")[:254]
    dfu[offset + 1] = 0x01
    dfu[offset + 4:offset + 4 + len(label)] = label
    offset += 259

    struct.pack_into("<I", dfu, offset, (8 * image_count) + total_len)
    offset += 4
    struct.pack_into("<I", dfu, offset, image_count)
    offset += 4

    for start_address, image in images:
        struct.pack_into("<I", dfu, offset, start_address)
        offset += 4
        struct.pack_into("<I", dfu, offset, len(image))
        offset += 4
        dfu[offset:offset + len(image)] = image
        offset += len(image)

    suffix_offset = dfu_len - 16
    struct.pack_into("<H", dfu, suffix_offset + 0, version & 0xFFFF)
    struct.pack_into("<H", dfu, suffix_offset + 2, pid & 0xFFFF)
    struct.pack_into("<H", dfu, suffix_offset + 4, vid & 0xFFFF)
    dfu[suffix_offset + 6:suffix_offset + 8] = b"\x1A\x01"
    dfu[suffix_offset + 8:suffix_offset + 11] = b"UFD"
    dfu[suffix_offset + 11] = 16

    dfu_crc = (-binascii.crc32(dfu[:suffix_offset + 12])) & 0xFFFFFFFF
    struct.pack_into("<I", dfu, suffix_offset + 12, dfu_crc)
    return bytes(dfu)


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("-h", action="store_true")
    parser.add_argument("-J", action="store_true")
    parser.add_argument("-e", action="store_true")
    parser.add_argument("-i", action="append", dest="inputs")
    parser.add_argument("-o", dest="dfu_output")
    parser.add_argument("-b", dest="bin_output")
    parser.add_argument("-l", dest="label")
    parser.add_argument("-p", dest="pid", type=parse_int, default=0xDF11)
    parser.add_argument("-v", dest="vid", type=parse_int, default=0x0483)
    parser.add_argument("-d", dest="version", type=parse_int, default=0xFFFF)
    parser.add_argument("-c", dest="crc_address", type=parse_int, default=0)
    parser.add_argument("-C", action="append", dest="vector_crc_offsets", type=parse_int)

    args, unknown = parser.parse_known_args(argv)

    if args.h:
        print("STM32 hex2dfu Python replacement")
        print("Usage: hex2dfu.py -i infile.hex [-i second.hex] [-c addr] [-C offset] [-b out.bin] [-o out.dfu]")
        return 0

    unsupported = [item for item in unknown if item not in ("-S", "-P")]
    if unsupported:
        print(f"Unsupported arguments: {' '.join(unsupported)}", file=sys.stderr)
        return 1

    if not args.inputs:
        print("No input file(s) specified.", file=sys.stderr)
        return 1

    if not args.bin_output and not args.dfu_output:
        print("At least one of -b or -o is required.", file=sys.stderr)
        return 1

    vector_crc_offsets = args.vector_crc_offsets or []
    if vector_crc_offsets and len(vector_crc_offsets) > len(args.inputs):
        print("More -C offsets than input images.", file=sys.stderr)
        return 1

    images: list[tuple[int, bytearray]] = []
    crc_image_index = -1
    for index, input_name in enumerate(args.inputs):
        start_address, image = parse_ihex(Path(input_name))

        if index < len(vector_crc_offsets):
            apply_openblt_vector_crc(image, vector_crc_offsets[index])

        if apply_crc_metadata(image, args.crc_address, start_address):
            crc_image_index = index

        images.append((start_address, image))

    if args.bin_output:
        bin_index = crc_image_index if crc_image_index >= 0 else len(images) - 1
        write_binary(Path(args.bin_output), bytes(images[bin_index][1]))

    if args.dfu_output:
        dfu = build_dfu([(start, bytes(image)) for start, image in images], args.label, args.vid, args.pid, args.version)
        write_binary(Path(args.dfu_output), dfu)

    if args.J:
        first_start, first_image = images[0]
        meta_address = args.crc_address if args.crc_address else 0
        print(
            f'{{"code_address":"0x{first_start:08x}","code_length":"0x{len(first_image):08x}","meta_address":"0x{meta_address:08x}"}}'
        )

    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
