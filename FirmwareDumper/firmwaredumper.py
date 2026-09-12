#!/usr/bin/env python
"""
Dump the firmware of a Bluetooth controller over HCI vendor commands.
"""

import argparse

from pathlib import Path
from rich.console import Console
import usbbluetooth
from usbbluetooth import SerialController
from scapy_usbbluetooth import UsbBluetoothSocket
from scapy.layers.bluetooth import HCI_Hdr, HCI_Command_Hdr, HCI_Cmd_Reset
from vendors import DUMPERS, PROBE_DUMPERS, espressif


BANNER = r'''[bold green1]
 _______        __  ____                                   [spring_green2]
|  ___\ \      / / |  _ \ _   _ _ __ ___  _ __   ___ _ __  [spring_green3]
| |_   \ \ /\ / /  | | | | | | | '_ ` _ \| '_ \ / _ \ '__| [cyan2]
|  _|   \ V  V /   | |_| | |_| | | | | | | |_) |  __/ |    [cyan]
|_|      \_/\_/    |____/ \__,_|_| |_| |_| .__/ \___|_|    [dark_cyan]
                                         |_|   by Tarlogic Security
'''

def reset(socket: UsbBluetoothSocket):
    """Send HCI Reset and wait for the Command Complete."""
    pkt = HCI_Hdr() / HCI_Command_Hdr() / HCI_Cmd_Reset()
    _ = socket.sr1(pkt, verbose=0, timeout=3)


def controller_ids(controller) -> str:
    """A short identity for a controller: ``0xVID_0xPID`` for a USB device, or the
    serial port for an HCI-over-UART one (safe for use in a filename)."""
    vid = getattr(controller, "vendor_id", None)
    pid = getattr(controller, "product_id", None)
    if vid is not None and pid is not None:
        return f"0x{vid:04x}_0x{pid:04x}"
    port = getattr(controller, "_port", None)
    return str(port) if port else "controller"


def resolve_dumper(controller, socket):
    """Return ``(name, dump_firmware)`` for a controller: match on USB VID first,
    then fall back to the runtime ``matches`` probes. ``(None, None)`` if unknown."""
    dumper = DUMPERS.get(getattr(controller, "vendor_id", None))
    if dumper is not None:
        return dumper
    for module in PROBE_DUMPERS:
        try:
            if module.matches(socket):
                return module.NAME, module.dump_firmware
        except Exception:
            pass
    return None, None


def process_controller(console: Console, controller):
    """Detect the manufacturer of a controller and dump its firmware."""
    console.log(f"Using {controller}")
    file = Path(f"firmware_{controller_ids(controller)}.bin")
    try:
        socket = UsbBluetoothSocket(controller)
    except Exception as exc:
        console.log(f"[yellow]Cannot open {controller}: {exc}[/yellow]")
        return
    try:
        console.log("Resetting the controller...")
        reset(socket)
        name, dump_firmware = resolve_dumper(controller, socket)
        if dump_firmware is None:
            console.log(f"{controller_ids(controller)} is not supported for firmware dumping.")
            return
        console.log(f"Detected {name}.")
        written = dump_firmware(console, socket, file)
    finally:
        socket.close()
    if written:
        console.log(f"Firmware written to {file} ({written} bytes)")


def _serial_controller(spec: str) -> SerialController:
    """Build a SerialController from a ``--serial`` spec: ``PORT[,BAUD[,noflow]]``."""
    port, _, rest = spec.partition(",")
    baud_str, _, flow_str = rest.partition(",")
    baudrate = int(baud_str) if baud_str else 921600
    rtscts = flow_str.strip().lower() not in ("noflow", "off", "none", "0") if flow_str else True
    return SerialController(port, baudrate=baudrate, rtscts=rtscts)


def main():
    parser = argparse.ArgumentParser(
        description="Dump the firmware of a Bluetooth controller over HCI vendor commands.")
    parser.add_argument(
        "-s", "--serial", action="append", default=[], metavar="PORT[,BAUD[,noflow]]",
        help="also dump an HCI-over-UART controller (e.g. an ESP32). Repeatable.")
    parser.add_argument("--esp-start", type=lambda s: int(s, 0), default=espressif.START,
                        help=f"ESP32 dump start address (default {espressif.START:#010x})")
    parser.add_argument("--esp-length", type=lambda s: int(s, 0), default=espressif.LENGTH,
                        help=f"ESP32 dump length in bytes (default {espressif.LENGTH:#x})")
    parser.add_argument("--esp-access-size", type=int, choices=(8, 16, 32),
                        default=espressif.ACCESS_SIZE,
                        help=f"ESP32 memory access size in bits (default {espressif.ACCESS_SIZE})")
    args = parser.parse_args()

    # Apply the ESP32 dump options to the Espressif module.
    espressif.START = args.esp_start
    espressif.LENGTH = args.esp_length
    espressif.ACCESS_SIZE = args.esp_access_size

    console = Console()
    console.print(BANNER)

    controllers = list(usbbluetooth.list_controllers())
    controllers += [_serial_controller(s) for s in args.serial]
    if not controllers:
        console.log("No Bluetooth controllers found!")
        return
    for controller in controllers:
        process_controller(console, controller)


if __name__ == "__main__":
    main()
