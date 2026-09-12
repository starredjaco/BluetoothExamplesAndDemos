"""Realtek vendor-specific chip information (USB VID 0x0BDA).

Realtek has no dedicated "read version" VSC; the firmware-ID string lives in
controller RAM and is read out word-by-word with the 0xFC61 memory-read VSC
(scapy.contrib.bluetooth_vsc_realtek). The readable window is
0x80000000..0x8013FFFF (above it reads back the 0xDEADBEEF locked sentinel).
"""

from common import Vendor, command_complete

try:
    from scapy.contrib.bluetooth_vsc_realtek import (
        HCI_Cmd_VSC_Realtek_Read_Mem,
        HCI_Cmd_Complete_VSC_Realtek_Read_Mem,
    )
    _AVAILABLE = True
except ImportError:
    _AVAILABLE = False

MEM_BASE = 0x80000000
LOCKED_SENTINEL = bytes.fromhex("efbeadde")   # 0xDEADBEEF, little-endian
FW_ID_ADDR = 0x8007AF4A   # 'RTK_BT_5.0' signature (course RTL8761B build)


def _read_mem(socket, addr: int, nwords: int = 1):
    """Read ``nwords`` 32-bit words from controller RAM via the 0xFC61 VSC.

    Returns the concatenated little-endian bytes, or None if any read fails."""
    out = bytearray()
    for i in range(nwords):
        resp = command_complete(socket, HCI_Cmd_VSC_Realtek_Read_Mem(address=addr + 4 * i))
        if resp is None or HCI_Cmd_Complete_VSC_Realtek_Read_Mem not in resp:
            return None
        out += bytes(resp[HCI_Cmd_Complete_VSC_Realtek_Read_Mem].data)
    return bytes(out)


class RealtekVendor(Vendor):
    vendor_id = 0x0BDA
    title = "Realtek chip information"
    available = _AVAILABLE

    def gather(self, socket) -> dict:
        info = {}

        # Confirm the (unauthenticated) memory-read VSC works and the RAM window
        # is live rather than reading back the 0xDEADBEEF locked sentinel.
        base = _read_mem(socket, MEM_BASE)
        if base is None:
            return {}
        if base == LOCKED_SENTINEL:
            info["Memory read (0xFC61)"] = "responds, but RAM window reads locked (0xDEADBEEF)"
            return info
        info["Memory read (0xFC61)"] = "available (unauthenticated RAM/ROM read)"

        # Pull the firmware-ID string out of RAM. Read a word-aligned block and
        # search for the ASCII signature so a small offset shift still decodes.
        aligned = FW_ID_ADDR & ~3
        block = _read_mem(socket, aligned, 4)
        if block:
            idx = block.find(b"RTK")
            if idx != -1:
                end = block.find(b"\x00", idx)
                fw_id = block[idx:end if end != -1 else len(block)]
                info["Firmware ID"] = fw_id.decode("ascii", "replace")

        return info
