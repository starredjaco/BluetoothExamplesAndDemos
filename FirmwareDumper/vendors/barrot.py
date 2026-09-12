#!/usr/bin/env python

from pathlib import Path
from rich.console import Console
from rich.progress import track
from scapy_usbbluetooth import UsbBluetoothSocket
from scapy.layers.bluetooth import HCI_Hdr, HCI_Command_Hdr
from scapy.contrib.bluetooth_vsc_barrot import (
    HCI_Cmd_VSC_Barrot,
    HCI_Cmd_VSC_Barrot_Flash_Read,
    HCI_Cmd_Complete_VSC_Barrot_Flash_Read,
)

# Barrot controllers (BR8051, BR8551, ...) store their firmware in an external SPI flash.
# The Flash Read VSC reads it and a single request returns at most 0xF0 bytes.
# The BR8051 flash is 512 KB.
FLASH_BEGIN = 0x00000000
FLASH_END = 0x00080000
CHUNK = 0xF0
RETRIES = 5


def read_flash(console: Console, socket: UsbBluetoothSocket, addr: int, length: int):
    """Read up to 0xF0 bytes from flash using the Barrot Flash Read VSC, retrying on failure."""
    for attempt in range(RETRIES):
        pkt = (HCI_Hdr() / HCI_Command_Hdr() / HCI_Cmd_VSC_Barrot()
               / HCI_Cmd_VSC_Barrot_Flash_Read(address=addr, length=length))
        resp = socket.sr1(pkt, verbose=0, timeout=3)
        if resp is None:
            console.log(f"No response at {addr:#010x}, attempt {attempt + 1}/{RETRIES}")
            continue
        if not resp.haslayer(HCI_Cmd_Complete_VSC_Barrot_Flash_Read):
            console.log(f"Unexpected response at {addr:#010x}: {resp.summary()}, attempt {attempt + 1}/{RETRIES}")
            continue
        return bytes(resp[HCI_Cmd_Complete_VSC_Barrot_Flash_Read].data)
    return None


def dump_firmware(console: Console, socket: UsbBluetoothSocket, file: Path) -> int:
    """Dump the firmware (SPI flash) of a Barrot controller to file. Returns bytes written."""
    console.log(f"Dumping flash from {FLASH_BEGIN:#010x} to {FLASH_END:#010x}...")
    written = 0
    with file.open("wb") as f:
        for addr in track(range(FLASH_BEGIN, FLASH_END, CHUNK), description="Dumping...", console=console):
            length = min(CHUNK, FLASH_END - addr)
            data = read_flash(console, socket, addr, length)
            if data is None or len(data) != length:
                # Pad so the file offset keeps matching the flash offset.
                console.log(f"Giving up on {addr:#010x} after {RETRIES} attempts; padding with 0xFF.")
                data = b"\xff" * length
            f.write(data)
            f.flush()
            written += len(data)
    return written
