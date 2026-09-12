#!/usr/bin/env python

from pathlib import Path
from rich.console import Console
from rich.progress import track
from scapy_usbbluetooth import UsbBluetoothSocket
from scapy.layers.bluetooth import HCI_Hdr, HCI_Command_Hdr
from scapy.contrib.bluetooth_vsc_realtek import HCI_Cmd_VSC_Realtek_Read_Mem, HCI_Cmd_Complete_VSC_Realtek_Read_Mem

# Firmware lives in this word-aligned RAM window on Realtek controllers.
ADDR_BEGIN = 0x80000000
ADDR_END = 0x80140000
RETRIES = 5


def read_word(console: Console, socket: UsbBluetoothSocket, addr: int):
    """Read a single 4-byte word using the Realtek Read Memory VSC, retrying on failure."""
    for attempt in range(RETRIES):
        pkt = HCI_Hdr() / HCI_Command_Hdr() / HCI_Cmd_VSC_Realtek_Read_Mem(address=addr)
        resp = socket.sr1(pkt, verbose=0, timeout=3)
        if resp is None:
            console.log(f"No response at {addr:#010x}, attempt {attempt + 1}/{RETRIES}")
            continue
        if not resp.haslayer(HCI_Cmd_Complete_VSC_Realtek_Read_Mem):
            console.log(f"Unexpected response at {addr:#010x}: {resp.summary()}, attempt {attempt + 1}/{RETRIES}")
            continue
        return resp[HCI_Cmd_Complete_VSC_Realtek_Read_Mem].data
    return None


def dump_firmware(console: Console, socket: UsbBluetoothSocket, file: Path) -> int:
    """Dump the firmware of a Realtek controller to file. Returns bytes written."""
    console.log(f"Dumping firmware from {ADDR_BEGIN:#010x} to {ADDR_END:#010x}...")
    written = 0
    with file.open("wb") as f:
        for addr in track(range(ADDR_BEGIN, ADDR_END, 4), description="Dumping...", console=console):
            data = read_word(console, socket, addr)
            if data is None:
                console.log(f"Giving up on {addr:#010x} after {RETRIES} attempts.")
                continue
            f.write(data)
            f.flush()
            written += len(data)
    return written
