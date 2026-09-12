#!/usr/bin/env python
"""
Read chip and firmware information from Bluetooth controllers.
"""

import argparse

import usbbluetooth
from usbbluetooth import SerialController
from scapy_usbbluetooth import UsbBluetoothSocket

from common import (
    console,
    reset,
    gather_standard_info,
    render_standard,
    render_table,
    controller_id,
    active_vsc_vendor,
)
from vendors import VENDORS

BANNER = r'''[bold cyan]
  ____            _             _ _             ___        __
 / ___|___  _ __ | |_ _ __ ___ | | | ___ _ __  |_ _|_ __  / _| ___
| |   / _ \| '_ \| __| '__/ _ \| | |/ _ \ '__|  | || '_ \| |_ / _ \
| |__| (_) | | | | |_| | | (_) | | |  __/ |     | || | | |  _| (_) |
 \____\___/|_| |_|\__|_|  \___/|_|_|\___|_|    |___|_| |_|_|  \___/
                                        by Tarlogic Security
'''


def process_controller(controller, vendors=VENDORS) -> None:
    """Open a controller, reset it and print its standard + vendor information."""
    console.log(f"Querying {controller}...")
    try:
        socket = UsbBluetoothSocket(controller)
    except Exception as exc:
        console.log(f"[yellow]Cannot open {controller}: {exc}[/yellow]")
        return
    try:
        reset(socket)
        standard = gather_standard_info(socket)

        matched = []
        for vendor in vendors:
            if vendor.available and vendor.matches(controller, socket):
                with active_vsc_vendor(vendor.contrib_name):
                    matched.append((vendor, vendor.gather(socket)))

        empty_note = None
        for vendor, info in matched:
            empty_note = vendor.empty_note(info, standard)
            if empty_note:
                break
        render_standard(controller, standard, empty_note)

        ids = controller_id(controller) or str(controller)
        for vendor, info in matched:
            render_table(f"{vendor.title} {ids}", info)
    finally:
        socket.close()


def _serial_controller(spec: str) -> SerialController:
    """
    Build a SerialController from a ``--serial`` spec: ``PORT[,BAUD[,noflow]]``.
    """
    port, _, rest = spec.partition(",")
    baud_str, _, flow_str = rest.partition(",")
    baudrate = int(baud_str) if baud_str else 921600
    rtscts = flow_str.strip().lower() not in ("noflow", "off", "none", "0") if flow_str else True
    return SerialController(port, baudrate=baudrate, rtscts=rtscts)


def main() -> None:
    parser = argparse.ArgumentParser(description="Print chip and firmware information about Bluetooth controllers.")
    parser.add_argument(
        "-s", "--serial", action="append", default=[], metavar="PORT[,BAUD[,noflow]]",
        help="also query an HCI-over-UART controller on a serial port. Repeatable. "
             "e.g. -s COM8 -s COM10,115200,noflow")
    args = parser.parse_args()

    console.print(BANNER)

    controllers = list(usbbluetooth.list_controllers())
    controllers += [_serial_controller(s) for s in args.serial]

    if not controllers:
        console.log("No Bluetooth controllers found!")
        return
    console.log(f"Found {len(controllers)} controller(s).")
    for controller in controllers:
        process_controller(controller)


if __name__ == "__main__":
    main()
