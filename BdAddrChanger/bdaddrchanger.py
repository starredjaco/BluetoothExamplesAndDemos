#!/usr/bin/env python
"""
List Bluetooth controllers and change their BD_ADDR via vendor commands.
"""

import argparse

import usbbluetooth
from usbbluetooth import SerialController
from rich import box
from rich.table import Table

from common import console, read_bd_addr, open_controller
from vendors import CHANGERS

BANNER = r'''
[bright_cyan]▄▄▄▄▄▄▄[/][white]   [/][bright_cyan]▄▄▄▄▄▄▄[/][white]         [/][bright_cyan]▄▄▄▄▄▄▄[/][white]  [/][bright_cyan]▄▄▄▄▄▄▄[/][white]   [/][bright_cyan]▄▄▄▄▄▄▄[/][white]   [/][bright_cyan]▄▄▄▄▄▄▄[/][white]  [/]
[bright_cyan on bright_cyan] [/][light_cyan1 on bright_cyan]▒░[/][bright_cyan]█████▄[/][white] [/][bright_cyan on bright_cyan] [/][light_cyan1 on bright_cyan]▒░[/][bright_cyan]█████▄[/][white]      [/][bright_cyan]█[/][light_cyan1 on bright_cyan]▒░[/][bright_cyan]██████[/][white] [/][bright_cyan on bright_cyan] [/][light_cyan1 on bright_cyan]▒░[/][bright_cyan]█████▄[/][white] [/][bright_cyan on bright_cyan] [/][light_cyan1 on bright_cyan]▒░[/][bright_cyan]█████▄[/][white] [/][bright_cyan]█[/][light_cyan1 on bright_cyan]▒░[/][bright_cyan]█████▄[/]
[bright_cyan]█[/][light_cyan1 on bright_cyan]░[/][bright_cyan]██[/][white] [/][bright_cyan]███▀[/][white] [/][bright_cyan]█[/][light_cyan1 on bright_cyan]░[/][bright_cyan]██[/][white] [/][bright_cyan]████[/][white]      [/][bright_cyan]█[/][light_cyan1 on bright_cyan]░[/][bright_cyan]██▄████[/][white] [/][bright_cyan]█[/][light_cyan1 on bright_cyan]░[/][bright_cyan]██[/][white] [/][bright_cyan]████[/][white] [/][bright_cyan]█[/][light_cyan1 on bright_cyan]░[/][bright_cyan]██[/][white] [/][bright_cyan]████[/][white] [/][bright_cyan]█[/][light_cyan1 on bright_cyan]░[/][bright_cyan]██▄████[/]
[bright_cyan]█▓██▀██▄[/][white]  [/][bright_cyan]█▓██[/][white] [/][bright_cyan]████[/][white]      [/][bright_cyan]█▓██▀█▓██[/][white] [/][bright_cyan]█▓██[/][white] [/][bright_cyan]████[/][white] [/][bright_cyan]█▓██[/][white] [/][bright_cyan]████[/][white] [/][bright_cyan]█▓████▓█▀[/]
[bright_cyan]█▒▓█████▀[/][white] [/][bright_cyan]█▒▓█████▀[/][white]      [/][bright_cyan]██▓█[/][white] [/][bright_cyan]█▒▓█[/][white] [/][bright_cyan]█▒▓█████▀[/][white] [/][bright_cyan]█▒▓█████▀[/][white] [/][bright_cyan]█▒▓█[/][white] [/][bright_cyan]█▒▓█[/]
[bright_cyan]▀▀▀▀▀▀▀[/][white]   [/][bright_cyan]▀▀▀▀▀▀▀[/][white]        [/][bright_cyan]▀▀▀▀[/][white] [/][bright_cyan]▀▀▀▀[/][white] [/][bright_cyan]▀▀▀▀▀▀▀[/][white]   [/][bright_cyan]▀▀▀▀▀▀▀[/][white]   [/][bright_cyan]▀▀▀▀[/][white] [/][bright_cyan]▀▀▀▀[/]
[white] [/][bright_cyan]▄▄▄▄▄▄[/][white]  [/][bright_cyan]▄▄▄▄[/][white] [/][bright_cyan]▄▄▄▄[/][white]  [/][bright_cyan]▄▄▄▄▄▄▄[/][white]  [/][bright_cyan]▄▄▄▄▄▄▄[/][white]    [/][bright_cyan]▄▄▄▄▄▄[/][white]  [/][bright_cyan]▄▄▄▄▄▄▄[/][white]  [/][bright_cyan]▄▄▄▄▄▄▄[/][white]  [/]
[bright_cyan]█[/][light_cyan1 on bright_cyan]▒░[/][bright_cyan]█████[/][white] [/][bright_cyan]█[/][light_cyan1 on bright_cyan]▒░[/][bright_cyan]█[/][white] [/][bright_cyan]████[/][white] [/][bright_cyan]█[/][light_cyan1 on bright_cyan]▒░[/][bright_cyan]██████[/][white] [/][bright_cyan on bright_cyan] [/][light_cyan1 on bright_cyan]▒░[/][bright_cyan]█████▄[/][white] [/][bright_cyan]█[/][light_cyan1 on bright_cyan]▒░[/][bright_cyan]█████[/][white] [/][bright_cyan]█[/][light_cyan1 on bright_cyan]▒░[/][bright_cyan]█████[/][white] [/][bright_cyan]█[/][light_cyan1 on bright_cyan]▒░[/][bright_cyan]█████▄[/]
[bright_cyan]█[/][light_cyan1 on bright_cyan]░[/][bright_cyan]██[/][white] [/][bright_cyan]▀▀▀[/][white] [/][bright_cyan]█[/][light_cyan1 on bright_cyan]░[/][bright_cyan]██▄████[/][white] [/][bright_cyan]█[/][light_cyan1 on bright_cyan]░[/][bright_cyan]██▄████[/][white] [/][bright_cyan]█[/][light_cyan1 on bright_cyan]░[/][bright_cyan]██[/][white] [/][bright_cyan]█▓██[/][white] [/][bright_cyan]█[/][light_cyan1 on bright_cyan]░[/][bright_cyan]██▄▄▄▄[/][white] [/][bright_cyan]█[/][light_cyan1 on bright_cyan]░[/][bright_cyan]██▄▄▄▄[/][white] [/][bright_cyan]█[/][light_cyan1 on bright_cyan]░[/][bright_cyan]██▄████[/]
[bright_cyan]█▓██[/][white] [/][bright_cyan]▄▄▄[/][white] [/][bright_cyan]█▓██▀█▓██[/][white] [/][bright_cyan]█▓██▀█▓██[/][white] [/][bright_cyan]█▒▓█[/][white] [/][bright_cyan]█▒▓█[/][white] [/][bright_cyan]█▓██[/][white] [/][bright_cyan]███[/][white] [/][bright_cyan]█▓██▀▀▀▀[/][white] [/][bright_cyan]█▓████▓█▀[/]
[bright_cyan]█▒▓█████[/][white] [/][bright_cyan]██▓█[/][white] [/][bright_cyan]█▒▓█[/][white] [/][bright_cyan]██▓█[/][white] [/][bright_cyan]█▒▓█[/][white] [/][bright_cyan]████[/][white] [/][bright_cyan]████[/][white] [/][bright_cyan]█▒▓█████[/][white] [/][bright_cyan]█▒▓█████[/][white] [/][bright_cyan]█▒▓█[/][white] [/][bright_cyan]█▒▓█[/]
[white] [/][bright_cyan]▀▀▀▀▀▀[/][white]  [/][bright_cyan]▀▀▀▀[/][white] [/][bright_cyan]▀▀▀▀[/][white] [/][bright_cyan]▀▀▀▀[/][white] [/][bright_cyan]▀▀▀▀[/][white] [/][bright_cyan]▀▀▀▀[/][white] [/][bright_cyan]▀▀▀▀[/][white]  [/][bright_cyan]▀▀▀▀▀▀▀[/][white] [/][bright_cyan]▀▀▀▀▀▀▀[/][white]  [/][bright_cyan]▀▀▀▀[/][white] [/][bright_cyan]▀▀▀▀[/]
'''


def controller_ids(controller) -> str:
    """A short identity for a controller: its ``0xVID:0xPID`` for a USB device,
    or the serial port for an HCI-over-UART one."""
    vid = getattr(controller, "vendor_id", None)
    pid = getattr(controller, "product_id", None)
    if vid is not None and pid is not None:
        return f"0x{vid:04x}:0x{pid:04x}"
    port = getattr(controller, "_port", None)
    return str(port) if port else str(controller)


def resolve_changer(controller, socket):
    """Return the first changer that claims ``controller`` -- by USB VID or by a
    runtime probe on the open ``socket`` -- or None if none applies."""
    for changer in CHANGERS:
        try:
            if changer.matches(controller, socket):
                return changer
        except Exception:
            pass
    return None


def list_controllers(controllers) -> None:
    """Print every controller with its current BD_ADDR and change support."""
    table = Table(box=box.ROUNDED, title="Bluetooth controllers")
    table.add_column("#", justify="right", style="cyan")
    table.add_column("Controller")
    table.add_column("Current BD_ADDR (std read)")
    table.add_column("Vendor change command")
    for index, controller in enumerate(controllers):
        try:
            socket = open_controller(controller)
            try:
                addr = read_bd_addr(socket) or "[yellow](no answer)[/yellow]"
                changer = resolve_changer(controller, socket)
            finally:
                socket.close()
        except Exception:
            addr = "[yellow](cannot open - wrong driver?)[/yellow]"
            changer = None
        support = changer.name if changer else "[dim]none known[/dim]"
        table.add_row(str(index), controller_ids(controller), str(addr), support)
    console.print(table)


def change_controller(controllers, index: int, new_addr: str) -> None:
    """Change one controller's BD_ADDR via its vendor changer."""
    if not 0 <= index < len(controllers):
        console.log(f"[red]Invalid controller index {index} "
                    f"(have 0..{len(controllers) - 1}).[/red]")
        return
    controller = controllers[index]

    # Open only to pick the changer (some are chosen by a runtime probe); the
    # changer then owns its own socket for the duration of change().
    try:
        socket = open_controller(controller)
    except Exception as exc:
        console.log(f"[red]Cannot open controller #{index}: {exc}[/red]")
        return
    try:
        changer = resolve_changer(controller, socket)
    finally:
        socket.close()

    if changer is None:
        console.log(f"[yellow]No vendor BD_ADDR-change command is known for "
                    f"{controller_ids(controller)}.[/yellow]")
        return

    console.log(f"Using controller #{index} ({controller_ids(controller)}) "
                f"via {changer.name}.")
    changer.change(controller, new_addr, console)


def _serial_controller(spec: str) -> SerialController:
    """Build a SerialController from a ``--serial`` spec: ``PORT[,BAUD[,noflow]]``.

    Baud defaults to 921600 and RTS/CTS flow control is on; append ``,noflow``
    (or ``,off``) to disable it -- e.g. for an ESP32-C3's USB-Serial/JTAG link."""
    port, _, rest = spec.partition(",")
    baud_str, _, flow_str = rest.partition(",")
    baudrate = int(baud_str) if baud_str else 921600
    rtscts = flow_str.strip().lower() not in ("noflow", "off", "none", "0") if flow_str else True
    return SerialController(port, baudrate=baudrate, rtscts=rtscts)


def main():
    parser = argparse.ArgumentParser(description="Change devices BD_ADDR via vendor commands.")
    parser.add_argument(
        "-s", "--serial", action="append", default=[], metavar="PORT[,BAUD[,noflow]]",
        help="also include an HCI-over-UART controller (e.g. an ESP32). Repeatable. "
             "e.g. -s COM8 -s COM10,115200,noflow")
    parser.add_argument("index", nargs="?", type=int, help="controller index to change")
    parser.add_argument("addr", nargs="?", help="new BD_ADDR, e.g. AA:BB:CC:DD:EE:FF")
    args = parser.parse_args()

    console.print(BANNER)

    controllers = list(usbbluetooth.list_controllers())
    controllers += [_serial_controller(s) for s in args.serial]
    if not controllers:
        console.log("No Bluetooth controllers found!")
        return

    if args.index is None:
        list_controllers(controllers)
        console.print("\nTo change an address: "
                      "[bold]python bdaddrchanger.py [-s PORT] <index> <AA:BB:CC:DD:EE:FF>[/bold]")
        return
    if args.addr is None:
        console.log("[red]Provide both an index and a new address "
                    "(e.g. 0 AA:BB:CC:DD:EE:FF).[/red]")
        return
    change_controller(controllers, args.index, args.addr)


if __name__ == "__main__":
    main()
