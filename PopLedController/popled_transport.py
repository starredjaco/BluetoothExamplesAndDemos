#!/usr/bin/env python
'''
Transport protocol.
Frames structure:
AA 55 FF FF [LEN u16le] [SNO u16le] [FLAGS] [TYPE] [PAYLOAD] [CHECKSUM u16le if FLAGS bit7]
LEN = (len(PAYLOAD) + len(CHECKSUM)) + 4
'''

from enum import IntEnum


def u16le(n: int) -> bytes:
    return bytes((n & 0xFF, (n >> 8) & 0xFF))


def read_u16le(b: bytes, off: int) -> int:
    return b[off] | (b[off + 1] << 8)


class TransportFrameType(IntEnum):
    TLV = 0x02
    UNK = 0x06
    STATUS = 0x82


class TransportFrameStatus(IntEnum):
    OK = 0


def transport_frame_build(payload: bytes, sno: int, flags: int = 0xC1, type: TransportFrameType = TransportFrameType.TLV) -> bytes:
    has_checksum = (flags >> 7) == 1
    checksum_len = 2 if has_checksum else 0
    length_field = (len(payload) + checksum_len) + 4
    total_len = length_field + 6

    out = bytearray(total_len)
    out[0:4] = bytes([0xAA, 0x55, 0xFF, 0xFF])
    out[4:6] = u16le(length_field)
    out[6:8] = u16le(sno & 0xFFFF)
    out[8] = flags & 0xFF
    out[9] = type & 0xFF
    out[10:10 + len(payload)] = payload

    if has_checksum:
        s = sum(out[:-2]) & 0xFFFF
        out[-2:] = u16le(s)

    return bytes(out)


def transport_frames_parse(buf: bytearray):
    """
    Extracts complete frames from a buffer
    Takes into account that there could be fragmentation
    Returns a list of (frame, sno, flags, unk, payload)
    """
    frames = []
    while True:
        # Look for the AA55FFFF header
        start = buf.find(b"\xAA\x55\xFF\xFF")
        if start < 0:
            buf.clear()
            break
        if start > 0:
            del buf[:start]

        # Check for min size
        if len(buf) < 10:
            break

        # Read real len
        length_field = read_u16le(buf, 4)
        total_len = length_field + 6
        if total_len < 10 or total_len > 65535:
            # Invalid len, discard a byte and retry
            del buf[0:1]
            continue

        # Check if we need to await for more data
        if len(buf) < total_len:
            break

        # Parse the frame
        frame = bytes(buf[:total_len])
        del buf[:total_len]

        #print(f"[FRAME PARSE] frame={frame}")

        sno = read_u16le(frame, 6)
        flags = frame[8]
        type = TransportFrameType(frame[9])
        has_checksum = (flags >> 7) == 1
        checksum_len = 2 if has_checksum else 0
        payload_len = total_len - 10 - checksum_len
        payload = frame[10:10 + payload_len]

        # Validate checksum
        if has_checksum:
            got = read_u16le(frame, total_len - 2)
            calc = sum(frame[:-2]) & 0xFFFF
            if got != calc:
                # Invalid checksum, ignore
                continue

        frames.append((frame, sno, flags, type, payload))

    return frames
