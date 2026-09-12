"""Change the BD_ADDR of a CSR / BlueCore controller (USB VID 0x0A12).

CSR chips have no simple "set address" command; the address lives in the
persistent store as PSKEY_BDADDR (0x0001) and is changed with the BCCMD
(BlueCore Command) vendor protocol carried over HCI opcode 0xFC00:

  1. SETREQ writing PSKEY_BDADDR through the PS door (varid 0x7003), and
  2. a COLD_RESET (varid 0x4001) so the controller reboots and loads it.

This is what BlueZ ``bdaddr`` / CSR PSTool do. The cold reset makes the
controller **re-enumerate** on USB, so this changer overrides ``change`` and
drives the whole flow itself (write -> reset -> re-find the dongle by its new
address -> verify).

Many cheap "CSR8510" dongles are clones whose PS door is **stubbed**: a write
returns a fake ``status=0x0000`` OK but persists nothing. This changer detects
that (the PS read returns a truncated echo instead of the real key) and reports
it instead of falsely claiming success.

The BCCMD framing is built inline here (it does not depend on
``scapy.contrib.bluetooth_vsc_csr``).
"""

import struct
import time

import usbbluetooth
from rich.console import Console
from scapy_usbbluetooth import UsbBluetoothSocket
from scapy.layers.bluetooth import HCI_Hdr, HCI_Command_Hdr, HCI_Cmd_Reset

from common import Changer, read_bd_addr

try:
    import usb.core
    _TIMEOUT_EXC = (usb.core.USBTimeoutError,)
except Exception:                       # pragma: no cover
    _TIMEOUT_EXC = ()

_VENDOR_ID = 0x0A12
_BCCMD_OPCODE = 0xFC00
_PDU_GETREQ = 0x0000
_PDU_SETREQ = 0x0002
_VARID_PS = 0x7003
_PSKEY_BDADDR = 0x0001


def _controllers():
    return [c for c in usbbluetooth.list_controllers() if c.vendor_id == _VENDOR_ID]


def _open(controller):
    sock = UsbBluetoothSocket(controller)
    sock.sr1(HCI_Hdr() / HCI_Command_Hdr() / HCI_Cmd_Reset(), verbose=0, timeout=3)
    return sock


def _send_pdu(sock, pdu, drains=8):
    """Send a raw BCCMD PDU (the 0xC2 channel byte is prepended) and return the
    first vendor (0xFF) event's value bytes, or None. Tolerates the pipe error a
    reset command provokes."""
    payload = b"\xc2" + pdu
    cmd = b"\x01" + struct.pack("<H", _BCCMD_OPCODE) + bytes([len(payload)]) + payload
    try:
        sock._dev.write(cmd)
    except Exception:
        return None                      # e.g. a reset that drops the device
    ep = sock._dev._event_reader.endpoint
    for _ in range(drains):
        try:
            d = bytes(ep.read(300, timeout=350))
        except _TIMEOUT_EXC:
            break
        except Exception:
            break
        if d and d[0] == 0xFF:
            rp = d[2:]
            if len(rp) >= 11 and rp[0] == 0xC2:
                return rp[11:]
    return None


def _ps_read_addr(sock):
    """Read PSKEY_BDADDR through the PS door. Returns the decoded address, or
    None if the door is stubbed (truncated echo, no real key words)."""
    hdr = struct.pack("<HHHHH", _PDU_GETREQ, 0x000c, 0x4712, _VARID_PS, 0x0000)
    body = struct.pack("<HHH", _PSKEY_BDADDR, 0x0004, 0x0000)
    value = _send_pdu(sock, hdr + body + b"\x00" * 8)
    if value is None or len(value) < 14:     # stub returns only the echoed header
        return None
    d = value[6:14]                          # the 4 BD_ADDR words
    return f"{d[7]:02x}:{d[6]:02x}:{d[4]:02x}:{d[0]:02x}:{d[3]:02x}:{d[2]:02x}"


def _ps_write_addr(sock, mac):
    p = [int(x, 16) for x in mac.split(":")]  # p[0] = most significant octet
    b = p[::-1]                               # BlueZ b[0] = least significant
    data = bytes([b[2], 0x00, b[0], b[1], b[3], 0x00, b[4], b[5]])
    hdr = struct.pack("<HHHHH", _PDU_SETREQ, 0x000c, 0x4711, _VARID_PS, 0x0000)
    body = struct.pack("<HHH", _PSKEY_BDADDR, 0x0004, 0x0000)
    _send_pdu(sock, hdr + body + data)


def _cold_reset(sock):
    # BlueZ csr_reset_device: SETREQ, len 9 words, varid 0x4001 (COLD_RESET).
    _send_pdu(sock, bytes.fromhex("020009000000014000000000000000000000"), drains=2)


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
    available = True   # inline BCCMD framing, no scapy contrib needed

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
            _ps_write_addr(sock, new_addr)
            if str(_ps_read_addr(sock)).lower() != new_addr:
                console.log("[yellow]PSKEY_BDADDR write did not persist; aborting "
                            "(no reset issued).[/yellow]")
                return False

            console.log("Cold-resetting the controller to apply "
                        "(it will re-enumerate on USB)...")
            _cold_reset(sock)
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
