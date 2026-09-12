"""CSR/BlueCore vendor-specific chip information (USB VID 0x0A12).

CSR controllers expose chip and firmware details through the BCCMD channel
(scapy.contrib.bluetooth_vsc_csr): a GETREQ carrying a "varid" is answered with
a GETRESP that, unlike the other vendors here, rides the HCI *vendor event*
(code 0xFF) rather than a Command Complete -- so this module sends and polls for
that event itself instead of using the shared ``command_complete`` helper.

Many BlueCore parts (e.g. the common CSR8510 dongles) answer only ``buildid``
and ``chipver`` and silently drop every other varid; whatever does answer is
rendered, and an unanswered varid is simply omitted.
"""

from common import Vendor
from scapy.layers.bluetooth import HCI_Hdr, HCI_Command_Hdr

try:
    from scapy.contrib.bluetooth_vsc_csr import (
        HCI_Cmd_VSC_CSR_BCCMD,
        HCI_Event_VSC_CSR_BCCMD,
    )
    _AVAILABLE = True
except ImportError:
    _AVAILABLE = False

# Read-only chip/firmware identity varids (BlueZ csr.h). Deliberately limited to
# informational getters -- none of the action/reset/PS-clear classes are touched.
_INFO_VARIDS = [
    (0x2819, "Firmware build ID"),
    (0x281a, "Chip version"),
    (0x281b, "Chip revision"),
    (0x2825, "BCCMD interface version"),
    (0x2838, "Loader build ID"),
]


def _word(value: bytes):
    """First 16-bit little-endian word of a BCCMD value area, or None."""
    return int.from_bytes(value[:2], "little") if len(value) >= 2 else None


def _chip_name(ver: int, rev: int) -> str:
    """Decode (chipver, chiprev) into a BlueCore family name (BlueZ csr.c), or
    "" when the pair is not one of the documented combinations."""
    if ver == 0x00:
        return "BlueCore01a"
    if ver == 0x01:
        return "BlueCore01b (ES)" if rev == 0x64 else "BlueCore01b"
    if ver == 0x02:
        return {0x89: "BlueCore02-External (ES2)", 0x8a: "BlueCore02-External",
                0x28: "BlueCore02-ROM/Audio/Flash"}.get(rev, "BlueCore02")
    if ver == 0x03:
        return {0x43: "BlueCore3-MM", 0x15: "BlueCore3-ROM", 0xe2: "BlueCore3-Flash",
                0x26: "BlueCore4-External", 0x30: "BlueCore4-ROM"}.get(
                    rev, "BlueCore3 or BlueCore4")
    return ""


def _bccmd_get(socket, varid: int, seqno: int, attempts: int = 3):
    """Send a BCCMD GETREQ for ``varid`` and return the matching GETRESP
    (HCI_Event_VSC_CSR_BCCMD) with status 0, or None.

    Read-only: only GETREQ is ever issued. The response rides the 0xFF vendor
    event, so poll ``recv`` for it and match on the echoed varid (BlueCore
    silently drops varids it does not implement -- there is no error reply)."""
    socket.send(HCI_Hdr() / HCI_Command_Hdr() /
                HCI_Cmd_VSC_CSR_BCCMD(pdu_type="getreq", seqno=seqno, varid=varid))
    for _ in range(attempts):
        pkt = socket.recv()
        if pkt is None:
            continue
        if HCI_Event_VSC_CSR_BCCMD in pkt:
            resp = pkt[HCI_Event_VSC_CSR_BCCMD]
            if resp.varid == varid:
                return resp if resp.status == 0 else None
    return None


class CSRVendor(Vendor):
    vendor_id = 0x0A12
    title = "CSR/BlueCore chip information"
    available = _AVAILABLE

    def gather(self, socket) -> dict:
        info = {}
        words = {}
        for seqno, (varid, label) in enumerate(_INFO_VARIDS, start=1):
            resp = _bccmd_get(socket, varid, seqno)
            if resp is None:
                continue
            word = _word(bytes(resp.value))
            if word is None:
                continue
            words[varid] = word
            info[label] = f"0x{word:04x}"

        # Enrich the raw words where BlueZ gives them a friendlier form.
        if 0x2819 in words:
            info["Firmware build ID"] = f"{words[0x2819]} (0x{words[0x2819]:04x})"
        if 0x2838 in words:
            info["Loader build ID"] = f"{words[0x2838]} (0x{words[0x2838]:04x})"
        if 0x281a in words:
            name = _chip_name(words[0x281a], words.get(0x281b, -1))
            if name:
                info["BlueCore chip"] = name

        return info
