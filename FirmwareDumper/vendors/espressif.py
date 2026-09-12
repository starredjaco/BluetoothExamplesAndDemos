"""Dump memory from a classic ESP32 controller via its ROM Read-Memory VSC.

Uses the legacy ROM ``Read Memory`` vendor command (0xFC01,
scapy.contrib.bluetooth_vsc_espressif): reads up to 128 bytes per call
(RivieraWaves ``dbg`` buffer). The controller is fingerprinted at runtime with the
ESP vendor ECHO command (0xFC81), so this works over any transport (UART /
USB-Serial/JTAG) rather than by USB VID.

**Availability.** 0xFC01 is one of the undocumented ESP32 ROM debug commands
(CVE-2025-27840): original ESP32 only (not the C/S/H series), and only on ESP-IDF
releases *before* the fix -- removed in v5.4.1 / v5.3.3 / v5.2.6 / v5.1.7 / v5.0.9
and v6.0+ (advisory AR2025-004), where it answers 0x01 Unknown HCI Command. Flash a
pre-fix IDF (e.g. v5.4.0) to use it.

Defaults dump the ESP32 internal ROM 0 (`0x40000000`, 400 KB), which holds the BT
controller ROM code. ``START`` / ``LENGTH`` / ``ACCESS_SIZE`` are overridden by the
tool from its ``--esp-*`` options before ``dump_firmware`` runs.
"""

from pathlib import Path
from rich.console import Console
from rich.progress import track
from scapy_usbbluetooth import UsbBluetoothSocket
from scapy.layers.bluetooth import (
    HCI_Hdr,
    HCI_Command_Hdr,
    HCI_Event_Command_Complete,
)

try:
    from scapy.contrib.bluetooth_vsc_espressif import (
        HCI_Cmd_VSC_Espressif_Common_Echo,
        HCI_Cmd_Complete_VSC_Espressif_Common_Echo,
        HCI_Cmd_VSC_Espressif_Rd_Mem,
    )
    AVAILABLE = True
except ImportError:
    AVAILABLE = False

NAME = "Espressif ESP32 (Read Memory 0xFC01, legacy ROM cmd; pre-fix IDF only)"
_ECHO_PROBE = 0x2A

# Dump region + access size; the tool overrides these from --esp-* before dumping.
START = 0x40000000        # ESP32 internal ROM 0 (BT controller ROM code)
LENGTH = 0x64000          # 400 KB
ACCESS_SIZE = 32          # 8/16/32-bit accesses; 32 suits word-aligned ROM/RAM
CHUNK = 128               # max bytes per 0xFC01 call (dbg buffer_tag data)
RETRIES = 3


def matches(socket: UsbBluetoothSocket) -> bool:
    """Fingerprint an Espressif controller via its vendor ECHO command."""
    if not AVAILABLE:
        return False
    resp = socket.sr1(
        HCI_Hdr() / HCI_Command_Hdr() / HCI_Cmd_VSC_Espressif_Common_Echo(echo=_ECHO_PROBE),
        verbose=0, timeout=3)
    return (resp is not None
            and HCI_Cmd_Complete_VSC_Espressif_Common_Echo in resp
            and resp[HCI_Event_Command_Complete].status == 0
            and resp[HCI_Cmd_Complete_VSC_Espressif_Common_Echo].echo == _ECHO_PROBE)


def read_chunk(console: Console, socket: UsbBluetoothSocket, addr: int, size: int):
    """Read ``size`` bytes (<=128) at ``addr`` with the Read-Memory VSC (0xFC01).
    Returns the bytes, or None on failure / a non-zero status (e.g. 0x01 on a
    patched IDF where the command was removed).

    The reply is parsed from the raw Command-Complete bytes rather than by scapy
    layer: several vendor contribs bind different meanings to the same OGF 0x3F
    opcodes (0xFC01 is also Zephyr's 'Read Version Info'), so with more than one
    vendor contrib loaded the auto-dissected layer can belong to another vendor.
    The wire event is 04 0E <plen> <ncmd> <op_lo> <op_hi> <status> <len> <data>."""
    for _ in range(RETRIES):
        pkt = HCI_Hdr() / HCI_Command_Hdr() / HCI_Cmd_VSC_Espressif_Rd_Mem(
            start_addr=addr, access_size=ACCESS_SIZE, length=size)
        resp = socket.sr1(pkt, verbose=0, timeout=3)
        if resp is None:
            continue
        raw = bytes(resp)
        if len(raw) < 8 or raw[0] != 0x04 or raw[1] != 0x0E:
            continue
        if (raw[4] | (raw[5] << 8)) != 0xFC01:
            continue
        status, length = raw[6], raw[7]
        if status != 0:
            return None  # e.g. 0x01 Unknown HCI Command on a patched IDF
        return raw[8:8 + length]
    return None


def dump_firmware(console: Console, socket: UsbBluetoothSocket, file: Path) -> int:
    """Dump [START, START+LENGTH) to ``file``. Returns bytes written."""
    console.log(f"Dumping {LENGTH} bytes from {START:#010x} via Read-Memory VSC "
                f"(0xFC01, {ACCESS_SIZE}-bit access)...")
    # Fail fast + clearly on a patched controller (0xFC01 removed -> no data).
    if read_chunk(console, socket, START, min(CHUNK, LENGTH)) is None:
        console.log("[yellow]0xFC01 Read-Memory returned no data. On a patched ESP-IDF "
                    "(v5.4.1 / v5.3.3 / ... / v6.0+) this command is removed; flash a "
                    "pre-fix build such as v5.4.0. Nothing dumped.[/yellow]")
        return 0
    written = 0
    with file.open("wb") as f:
        for addr in track(range(START, START + LENGTH, CHUNK),
                          description="Dumping...", console=console):
            size = min(CHUNK, START + LENGTH - addr)
            data = read_chunk(console, socket, addr, size)
            if data is None:
                console.log(f"Giving up on {addr:#010x} after {RETRIES} attempts; "
                            f"padding {size} bytes.")
                data = b"\x00" * size  # keep file offsets aligned to the address
            f.write(data)
            written += len(data)
    return written
