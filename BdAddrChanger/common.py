"""Shared helpers for the BdAddrChanger example.

Holds the rich ``console``, a small ``command_complete`` request/response helper,
an HCI ``reset`` / ``read_bd_addr`` (the standard, non-vendor way to read the
current Bluetooth device address), ``open_controller``, and the ``Changer`` base
class every vendor plug-in subclasses."""

from rich.console import Console
from scapy_usbbluetooth import UsbBluetoothSocket
from usbbluetooth import SerialController
from scapy.layers.bluetooth import (
    HCI_Hdr,
    HCI_Command_Hdr,
    HCI_Event_Command_Complete,
    HCI_Cmd_Reset,
    HCI_Cmd_Read_BD_Addr,
    HCI_Cmd_Complete_Read_BD_Addr,
)

console = Console()


def command_complete(socket, cmd, timeout: int = 3):
    """Send a command and return its Command Complete event, or None on failure
    (no response, no Command Complete, or a non-zero status)."""
    resp = socket.sr1(HCI_Hdr() / HCI_Command_Hdr() / cmd, verbose=0, timeout=timeout)
    if resp is None or HCI_Event_Command_Complete not in resp:
        return None
    if resp[HCI_Event_Command_Complete].status != 0:
        return None
    return resp


def reset(socket):
    """Send HCI Reset so the controller is in a known state (result ignored)."""
    return command_complete(socket, HCI_Cmd_Reset())


def read_bd_addr(socket):
    """Read the current BD_ADDR using the standard HCI Read_BD_ADDR command.

    Returns the address string, or None if the controller did not answer."""
    resp = command_complete(socket, HCI_Cmd_Read_BD_Addr())
    if resp is not None and HCI_Cmd_Complete_Read_BD_Addr in resp:
        return resp[HCI_Cmd_Complete_Read_BD_Addr].addr
    return None


def open_controller(controller) -> UsbBluetoothSocket:
    """Open a controller and put it in a known state (HCI Reset)."""
    socket = UsbBluetoothSocket(controller)
    reset(socket)
    return socket


# --- Vendor plug-in base -----------------------------------------------------

class Changer:
    """A per-vendor BD_ADDR changer, exposing one interface to the main program.

    Subclasses set ``vendor_id`` (the USB VID they handle; ``None`` for a
    probe-only changer), a display ``name``, and ``available`` (``False`` when the
    backing scapy contrib is missing, so the changer is skipped). The main program
    only ever calls ``matches`` then ``change`` -- it never inspects per-vendor
    attributes.

    Most changers just implement ``write_bd_addr`` (one VSC on an open socket) and
    inherit the default ``change`` flow: open, standard read-before, write,
    standard read-after, verify and report. A changer that must own the whole flow
    -- CSR re-enumerates on its cold reset -- overrides ``change`` instead.

    Every entry point receives a rich ``Console`` so changers can print progress
    and vendor-specific notes."""

    vendor_id = None
    name = "unknown"
    available = True

    def matches(self, controller, socket) -> bool:
        """Whether this changer applies to ``controller``.

        Default: match on the Bluetooth chip's USB vendor id. A serial
        controller's vendor id is that of its USB-serial bridge, not the chip, so
        USB-VID changers never match there. A changer that fingerprints the chip
        at runtime (e.g. with a vendor command) overrides this to probe the live
        ``socket`` regardless of transport."""
        if (not self.available or self.vendor_id is None
                or isinstance(controller, SerialController)):
            return False
        return getattr(controller, "vendor_id", None) == self.vendor_id

    def write_bd_addr(self, socket, addr: str, console: Console) -> bool:
        """Issue the vendor's set-address command on the open ``socket`` and return
        True on success. Implemented by changers that use the default ``change``
        flow; unused when ``change`` is overridden."""
        raise NotImplementedError

    def change(self, controller, new_addr: str, console: Console) -> bool:
        """Change ``controller``'s BD_ADDR, reporting progress via ``console``.
        Returns True on success.

        Default flow: open the controller, standard read-before, ``write_bd_addr``,
        standard read-after, then verify and report."""
        new_addr = new_addr.lower()
        try:
            socket = open_controller(controller)
        except Exception as exc:
            console.log(f"[red]Cannot open the controller: {exc}[/red]")
            return False
        try:
            before = read_bd_addr(socket)
            console.log(f"Current BD_ADDR (std read): {before}")
            console.log(f"Writing {new_addr}...")
            ok = self.write_bd_addr(socket, new_addr, console)
            after = read_bd_addr(socket)
        finally:
            socket.close()

        if ok and str(after).lower() == new_addr:
            console.log(f"[green]BD_ADDR changed: {before} -> {after}[/green]")
            return True
        if ok:
            console.log(f"[yellow]Vendor command reported success but the standard "
                        f"read returned {after} (expected {new_addr}). It may need a "
                        f"controller reset / power cycle to take effect.[/yellow]")
            return True
        console.log(f"[red]Vendor command failed; BD_ADDR is still {after}.[/red]")
        return False
