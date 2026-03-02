#!/usr/bin/env python

from enum import IntEnum
from typing import List, Tuple


class TlvTag(IntEnum):
    POWER = 0x04
    BRIGHTNESS = 0x06
    INFO = 0x0A
    PARAMS = 0x1B
    ROTATE = 0x2F
    PROGRAM_PLAY = 0x36


def tlv_build(tag: TlvTag, value: bytes) -> bytes:
    """
    TLV with BER len:
      - <128: 1 byte
      - <256: 0x81 + 1 byte
      - >=256: 0x82 + 2 bytes (LE)
    """
    L = len(value)
    if L < 128:
        len_bytes = bytes([L])
    elif L < 256:
        len_bytes = bytes([0x81, L])
    else:
        len_bytes = bytes([0x82, L & 0xFF, (L >> 8) & 0xFF])
    return bytes([tag]) + len_bytes + value


def tlv_parse(payload: bytes) -> List[Tuple[TlvTag, bytes]]:
    tlvs = []
    i = 0
    while i < len(payload):
        tag = TlvTag(payload[i])
        i += 1
        if i >= len(payload):
            break

        lb = payload[i]
        i += 1

        if lb < 0x80:
            L = lb
        elif lb == 0x81:
            if i >= len(payload):
                break
            L = payload[i]
            i += 1
        elif lb == 0x82:
            if i + 1 >= len(payload):
                break
            L = payload[i] | (payload[i + 1] << 8)
            i += 2
        else:
            # What?
            break

        if i + L > len(payload):
            break

        val = payload[i:i + L]
        i += L
        tlvs.append((tag, val))
    return tlvs

