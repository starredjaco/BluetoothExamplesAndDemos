"""CSR/BlueCore vendor-specific chip information (USB VID 0x0A12).

CSR controllers (the legacy Cambridge Silicon Radio line Qualcomm bought in 2015)
expose chip and firmware details through the BCCMD channel
(scapy.contrib.bluetooth_vsc_csr): a GETREQ carrying a "varid" is answered with a
GETRESP that, unlike the other vendors here, rides the HCI *vendor event* (code
0xFF) rather than a Command Complete -- so this module sends and polls for that
event itself instead of using the shared ``command_complete`` helper.

Two kinds of read are used:
  * scalar info varids (build id, chip version, RNG, TX power, ...), and
  * the PS-key door (varid 0x7003), which reads the config store -- BD_ADDR,
    device name, USB VID/PID -- via the ``CSR_PS`` value structure.

A varid/PS key the firmware does not implement answers with a non-zero status
(NO_SUCH_VARID / ERROR); those are simply omitted. Coverage varies by part: a
genuine CSR8510 answers most of these, while heavily stubbed clones answer only
``buildid`` and ``chipver``.
"""

from common import Vendor
from scapy.layers.bluetooth import HCI_Hdr, HCI_Command_Hdr

try:
    from scapy.contrib.bluetooth_vsc_csr import (
        HCI_Cmd_VSC_CSR_BCCMD,
        HCI_Event_VSC_CSR_BCCMD,
        CSR_PS,
        CSR_PS_BDADDR,
    )
    _AVAILABLE = True
except ImportError:
    _AVAILABLE = False

_VARID_PS = 0x7003


def _value_bdaddr(value):
    """Decode an 8-byte PSKEY_BDADDR value (CSR NAP/UAP/LAP split) to a MAC."""
    b = CSR_PS_BDADDR(bytes(value))
    lap = (b.lap_hi << 16) | b.lap_lo
    return "%02x:%02x:%02x:%02x:%02x:%02x" % (
        (b.nap >> 8) & 0xFF, b.nap & 0xFF, b.uap & 0xFF,
        (lap >> 16) & 0xFF, (lap >> 8) & 0xFF, lap & 0xFF)


def _ps_read_cmd(pskey, nwords, seqno):
    """A BCCMD GETREQ reading ``pskey`` through the PS door (read-only)."""
    return HCI_Cmd_VSC_CSR_BCCMD(
        pdu_type="getreq", seqno=seqno, varid=_VARID_PS,
        value=bytes(CSR_PS(pskey=pskey, pslen=nwords, stores=0,
                           value=b"\x00" * (nwords * 2))))

# Read-only chip/firmware identity varids (BlueZ csr.h). Deliberately limited to
# informational getters -- none of the action/reset/PS-clear classes are touched.
_INFO_VARIDS = [
    (0x2819, "Firmware build ID"),
    (0x281a, "Chip version"),
    (0x281b, "Chip revision"),
    (0x2836, "Chip analog revision"),
    (0x2825, "BCCMD interface version"),
    (0x2838, "Loader build ID"),
    (0x282c, "Max crypt key length"),
    (0x282a, "RNG sample"),
    (0x6827, "Max TX power"),
    (0x682b, "Default TX power"),
]

# Config store (PS keys) read through varid 0x7003. (pskey, label, nwords).
_INFO_PSKEYS = [
    (0x0108, "Device name", 16),
    (0x02be, "USB vendor ID", 1),
    (0x02bf, "USB product ID", 1),
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


def _recv_bccmd(socket, want_varid: int, attempts: int = 3):
    """Poll ``recv`` for the GETRESP (HCI_Event_VSC_CSR_BCCMD) whose echoed varid
    is ``want_varid`` and status is 0, or None."""
    for _ in range(attempts):
        pkt = socket.recv()
        if pkt is None:
            continue
        if HCI_Event_VSC_CSR_BCCMD in pkt:
            resp = pkt[HCI_Event_VSC_CSR_BCCMD]
            if resp.varid == want_varid:
                return resp if resp.status == 0 else None
    return None


def _bccmd_get(socket, varid: int, seqno: int):
    """Send a BCCMD GETREQ for a scalar info ``varid`` and return the GETRESP.

    Read-only: only GETREQ is ever issued. BlueCore silently drops varids it does
    not implement, so match on the echoed varid."""
    socket.send(HCI_Hdr() / HCI_Command_Hdr() /
                HCI_Cmd_VSC_CSR_BCCMD(pdu_type="getreq", seqno=seqno, varid=varid))
    return _recv_bccmd(socket, varid)


def _ps_get(socket, pskey: int, nwords: int, seqno: int):
    """Read a PS key through the PS door (varid 0x7003); return its value bytes
    or None. Read-only (GETREQ)."""
    socket.send(HCI_Hdr() / HCI_Command_Hdr() / _ps_read_cmd(pskey, nwords, seqno))
    resp = _recv_bccmd(socket, _VARID_PS)
    if resp is None:
        return None
    ps = CSR_PS(bytes(resp.value))
    return bytes(ps.value) if ps.value else None


class CSRVendor(Vendor):
    vendor_id = 0x0A12
    title = "CSR/BlueCore chip information"
    available = _AVAILABLE

    def gather(self, socket) -> dict:
        info = {}
        words = {}
        seqno = 0
        for varid, label in _INFO_VARIDS:
            seqno += 1
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

        # Config store: BD_ADDR + identity, read through the PS-key door.
        seqno += 1
        addr_val = _ps_get(socket, 0x0001, 4, seqno)
        if addr_val and len(addr_val) >= 8:
            info["Stored BD_ADDR (PSKEY_BDADDR)"] = _value_bdaddr(addr_val)
        for pskey, label, nwords in _INFO_PSKEYS:
            seqno += 1
            val = _ps_get(socket, pskey, nwords, seqno)
            if not val:
                continue
            if pskey == 0x0108:
                info[label] = val.split(b"\x00", 1)[0].decode("latin1", "replace")
            else:
                info[label] = f"0x{int.from_bytes(val[:2], 'little'):04x}"

        return info
