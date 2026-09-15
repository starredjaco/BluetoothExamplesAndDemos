"""Change the BD_ADDR of a CSR / BlueCore controller (USB VID 0x0A12).

CSR chips (the legacy Cambridge Silicon Radio line Qualcomm bought in 2015) have
no simple "set address" command; the address lives in the persistent store as
PSKEY_BDADDR (0x0001) and is changed with the BCCMD (BlueCore Command) vendor
protocol carried over HCI opcode 0xFC00:

  1. SETREQ writing PSKEY_BDADDR through the PS door (varid 0x7003), and
  2. a COLD_RESET (varid 0x4001) so the controller reboots and loads it.

This is what BlueZ ``bdaddr`` / CSR PSTool do. The cold reset makes the
controller **re-enumerate** on USB, so this changer overrides ``change`` and
drives the whole flow itself (write -> reset -> re-find the dongle by its new
address -> verify).

The BCCMD framing comes from the packet definitions in
``scapy.contrib.bluetooth_vsc_csr`` (``HCI_Cmd_VSC_CSR_BCCMD``, the ``CSR_PS``
value structure and its ``CSR_PS_BDADDR`` sub-structure); this module composes
the GETREQ/SETREQ/reset commands from them and reads the response through the
registered ``HCI_Event_VSC_CSR_BCCMD`` handler.

Many cheap "CSR8510" dongles are clones whose PS door is **stubbed**: a write
returns a fake ``status=0x0000`` OK but persists nothing. This changer detects
that (the PS read returns a truncated echo instead of the real key) and reports
it instead of falsely claiming success.
"""

import time

import usbbluetooth
from rich.console import Console
from scapy_usbbluetooth import UsbBluetoothSocket
from scapy.layers.bluetooth import HCI_Hdr, HCI_Command_Hdr, HCI_Cmd_Reset

from common import Changer, read_bd_addr

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

_VENDOR_ID = 0x0A12
_VARID_PS = 0x7003
_VARID_COLD_RESET = 0x4001
_PSKEY_BDADDR = 0x0001


def _controllers():
    return [c for c in usbbluetooth.list_controllers() if c.vendor_id == _VENDOR_ID]


# --- BD_ADDR <-> PSKEY_BDADDR (CSR NAP/UAP/LAP split), via CSR_PS_BDADDR -------

def _bdaddr_value(mac):
    """'aa:bb:cc:dd:ee:ff' -> 8-byte PSKEY_BDADDR value (aa = NAP high byte)."""
    aa, bb, cc, dd, ee, ff = (int(x, 16) for x in mac.split(":"))
    return bytes(CSR_PS_BDADDR(lap_hi=dd, lap_lo=(ee << 8) | ff,
                               uap=cc, nap=(aa << 8) | bb))


def _value_bdaddr(value):
    """Inverse of :func:`_bdaddr_value`."""
    b = CSR_PS_BDADDR(bytes(value))
    lap = (b.lap_hi << 16) | b.lap_lo
    return "%02x:%02x:%02x:%02x:%02x:%02x" % (
        (b.nap >> 8) & 0xFF, b.nap & 0xFF, b.uap & 0xFF,
        (lap >> 16) & 0xFF, (lap >> 8) & 0xFF, lap & 0xFF)


# --- command construction from the packet definitions ------------------------

def _ps_read_cmd(pskey, nwords=4):
    return HCI_Cmd_VSC_CSR_BCCMD(
        pdu_type="getreq", varid=_VARID_PS,
        value=bytes(CSR_PS(pskey=pskey, pslen=nwords, stores=0,
                           value=b"\x00" * (nwords * 2))))


def _ps_write_bdaddr_cmd(mac):
    val = bytes(CSR_PS(pskey=_PSKEY_BDADDR, pslen=4, stores=0,
                       value=_bdaddr_value(mac)))
    return HCI_Cmd_VSC_CSR_BCCMD(pdu_type="setreq", seqno=0x4711,
                                 varid=_VARID_PS, value=val)


def _cold_reset_cmd():
    # Valueless action: the 8-byte value area makes the 9-word PDU BlueZ sends.
    return HCI_Cmd_VSC_CSR_BCCMD(pdu_type="setreq", varid=_VARID_COLD_RESET,
                                 value=b"\x00" * 8)


def _open(controller):
    sock = UsbBluetoothSocket(controller)
    sock.sr1(HCI_Hdr() / HCI_Command_Hdr() / HCI_Cmd_Reset(), verbose=0, timeout=3)
    return sock


def _bccmd(sock, cmd_layer, want_varid, attempts=8):
    """Send a BCCMD command layer and return the matching GETRESP/SETRESP vendor
    event (HCI_Event_VSC_CSR_BCCMD) whose varid echoes ``want_varid``, or None.
    The reply rides the 0xFF vendor event, so poll ``recv`` for it."""
    sock.send(HCI_Hdr() / HCI_Command_Hdr() / cmd_layer)
    for _ in range(attempts):
        pkt = sock.recv()
        if pkt is not None and HCI_Event_VSC_CSR_BCCMD in pkt:
            resp = pkt[HCI_Event_VSC_CSR_BCCMD]
            if resp.varid == want_varid:
                return resp
    return None


def _ps_read_addr(sock):
    """Read PSKEY_BDADDR through the PS door. Returns the decoded address, or
    None if the door is stubbed (truncated echo, no real key words)."""
    resp = _bccmd(sock, _ps_read_cmd(_PSKEY_BDADDR, nwords=4), 0x7003)
    if resp is None or resp.status != 0:
        return None
    ps = CSR_PS(bytes(resp.value))
    if len(ps.value) < 8:                 # stub returns only the echoed header
        return None
    return _value_bdaddr(ps.value)


def _find_by_addr(target, timeout_s=30):
    """After a re-enumeration, return an open socket to the CSR dongle now
    reporting ``target`` (retrying across the USB drop/re-add window)."""
    deadline = time.time() + timeout_s
    while time.time() < deadline:
        for c in _controllers():
            try:
                s = _open(c)
                addr = read_bd_addr(s)
            except Exception:
                continue                 # transient during re-enumeration
            if addr is not None and str(addr).lower() == target.lower():
                return s
            try:
                s.close()
            except Exception:
                pass
        time.sleep(1.5)
    return None


class CSRChanger(Changer):
    vendor_id = _VENDOR_ID
    name = "CSR/BlueCore (BCCMD PSKEY_BDADDR + cold reset)"
    available = _AVAILABLE

    def change(self, controller, new_addr: str, console: Console) -> bool:
        """Full CSR change flow (owns open/write/reset/re-enumerate/verify)."""
        new_addr = new_addr.lower()
        sock = _open(controller)
        try:
            before = read_bd_addr(sock)
            console.log(f"Current BD_ADDR (std read): {before}")

            if _ps_read_addr(sock) is None:
                console.log("[yellow]PS door is stubbed (clone firmware): PSKEY_BDADDR "
                            "is not really readable/writable, so the address cannot be "
                            "changed on this dongle.[/yellow]")
                return False

            console.log(f"Writing PSKEY_BDADDR = {new_addr} via BCCMD...")
            _bccmd(sock, _ps_write_bdaddr_cmd(new_addr), 0x7003)
            if str(_ps_read_addr(sock)).lower() != new_addr:
                console.log("[yellow]PSKEY_BDADDR write did not persist; aborting "
                            "(no reset issued).[/yellow]")
                return False

            console.log("Cold-resetting the controller to apply "
                        "(it will re-enumerate on USB)...")
            try:
                sock.send(HCI_Hdr() / HCI_Command_Hdr() / _cold_reset_cmd())
            except Exception:
                pass                      # the reset drops the USB endpoint
        finally:
            try:
                sock.close()
            except Exception:
                pass

        time.sleep(5)
        sock = _find_by_addr(new_addr)
        if sock is None:
            console.log(f"[yellow]PSKEY_BDADDR was written to {new_addr} but the "
                        f"controller was not seen with the new address after the reset; "
                        f"replug it to apply, then re-list.[/yellow]")
            return False
        try:
            after = read_bd_addr(sock)
        finally:
            sock.close()
        console.log(f"[green]BD_ADDR changed: {before} -> {after}[/green]")
        return True
