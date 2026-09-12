"""
Shared helpers for the controller-info tool.
"""

from contextlib import contextmanager

from rich import box
from rich.console import Console
from rich.table import Table
from usbbluetooth import SerialController
from scapy.packet import bind_layers, split_layers
from scapy.layers.bluetooth import (
    HCI_Hdr,
    HCI_Command_Hdr,
    HCI_Event_Command_Complete,
    HCI_Cmd_Reset,
    HCI_Cmd_Read_BD_Addr,
    HCI_Cmd_Complete_Read_BD_Addr,
    HCI_Cmd_Read_Local_Name,
    HCI_Cmd_Complete_Read_Local_Name,
    HCI_Cmd_Read_Local_Version_Information,
    HCI_Cmd_Complete_Read_Local_Version_Information,
    HCI_Cmd_Read_Local_Extended_Features,
    HCI_Cmd_Complete_Read_Local_Extended_Features,
    _bluetooth_core_specification_versions,
    BLUETOOTH_CORE_COMPANY_IDENTIFIERS,
)

console = Console()


# --- Vendor VSC binding activation (opcode-collision workaround) --------------
# Several vendors number different commands at the same OGF 0x3F / OCF -- e.g.
# Zephyr "Read Version Info" and Espressif "Read Memory" are both 0xFC01 -- and a
# VSC frame carries no vendor tag, so scapy's global dissection table can only map
# each opcode to one class. With more than one vendor contrib loaded, the first
# one loaded wins and the others' replies mis-dissect. Each vendor plugin
# registers its colliding bindings; ``active_vsc_vendor(name)`` unloads every
# registered colliding binding and (re)loads only ``name``'s for the duration of
# that vendor's query, so replies auto-dissect to the right vendor, then restores
# the full set on exit.

_vsc_bindings = {}  # vendor name -> [(lower, upper, fval_dict), ...]


def register_vsc_bindings(name, bindings):
    """A vendor plugin registers the VSC bindings it shares an opcode with another
    vendor. ``bindings`` is a list of ``(lower, upper, fval)`` matching the
    ``bind_layers`` call in the scapy contrib (e.g. ``(HCI_Command_Hdr, cls,
    {"ogf": 0x3f, "ocf": 0x001})``)."""
    _vsc_bindings[name] = list(bindings)


def _apply_bindings(bindings, remove):
    for lower, upper, fval in bindings:
        try:
            (split_layers if remove else bind_layers)(lower, upper, **fval)
        except Exception:
            pass


@contextmanager
def active_vsc_vendor(name):
    """Make ``name``'s colliding VSC bindings the only ones in scapy's dissection
    table for the duration of the block, restoring all bindings on exit. A no-op
    when nothing is registered or ``name`` is falsy."""
    everything = [b for group in _vsc_bindings.values() for b in group]
    active = _vsc_bindings.get(name, [])
    if not everything or not name:
        yield
        return
    _apply_bindings(everything, remove=True)   # unload all colliding bindings
    _apply_bindings(active, remove=False)       # load only this vendor's
    try:
        yield
    finally:
        _apply_bindings(active, remove=True)    # unload this vendor's
        _apply_bindings(everything, remove=False)  # restore the full set


# --- HCI request/response ----------------------------------------------------

def command_complete(socket, cmd, timeout: int = 3):
    """Send a command and return its Command Complete event, or None on
    failure (no response, no Command Complete, or a non-zero status)."""
    resp = socket.sr1(HCI_Hdr() / HCI_Command_Hdr() / cmd, verbose=0, timeout=timeout)
    if resp is None or HCI_Event_Command_Complete not in resp:
        return None
    if resp[HCI_Event_Command_Complete].status != 0:
        return None
    return resp


def reset(socket):
    """Send HCI Reset so the controller is in a known state (result ignored:
    not every controller needs it and reading works regardless)."""
    return command_complete(socket, HCI_Cmd_Reset())


# --- Standard (non-vendor) HCI information -----------------------------------

def spec_version(value: int) -> str:
    return _bluetooth_core_specification_versions.get(value, f"0x{value:02x}")


def company_name(identifier: int) -> str:
    name = BLUETOOTH_CORE_COMPANY_IDENTIFIERS.get(identifier)
    return f"{name} (0x{identifier:04x})" if name else f"Unknown (0x{identifier:04x})"


def gather_standard_info(socket) -> dict:
    """Query a controller with common HCI informational commands."""
    info = {}

    resp = command_complete(socket, HCI_Cmd_Read_BD_Addr())
    if resp is not None and HCI_Cmd_Complete_Read_BD_Addr in resp:
        info["BD_ADDR"] = resp[HCI_Cmd_Complete_Read_BD_Addr].addr

    resp = command_complete(socket, HCI_Cmd_Read_Local_Name())
    if resp is not None and HCI_Cmd_Complete_Read_Local_Name in resp:
        raw_name = bytes(resp[HCI_Cmd_Complete_Read_Local_Name].local_name)
        name = raw_name.split(b"\x00", 1)[0].decode("utf-8", "replace")
        info["Local name"] = name if name else "(empty)"

    resp = command_complete(socket, HCI_Cmd_Read_Local_Version_Information())
    if resp is not None and HCI_Cmd_Complete_Read_Local_Version_Information in resp:
        version = resp[HCI_Cmd_Complete_Read_Local_Version_Information]
        info["HCI version"] = f"{spec_version(version.hci_version)} (revision 0x{version.hci_subversion:04x})"
        info["LMP/PAL version"] = f"{spec_version(version.lmp_version)} (subversion 0x{version.lmp_subversion:04x})"
        info["Manufacturer"] = company_name(version.company_identifier)

    resp = command_complete(socket, HCI_Cmd_Read_Local_Extended_Features(page_number=0))
    if resp is not None and HCI_Cmd_Complete_Read_Local_Extended_Features in resp:
        features = resp[HCI_Cmd_Complete_Read_Local_Extended_Features]
        info["LMP features (page 0)"] = f"0x{features.extended_features:016x}"
        info["Extended feature pages"] = str(features.max_page)

    return info


# --- Rendering ---------------------------------------------------------------

def _kv_table(title: str) -> Table:
    table = Table(box=box.ROUNDED, show_header=False, title_style="bold cyan", title=title)
    table.add_column("Property", style="cyan", no_wrap=True)
    table.add_column("Value", style="white")
    return table


def controller_id(controller) -> str:
    """Return a controller's ``0xVID:0xPID`` string, or None if the ids are
    unknown (e.g. a serial port with no resolvable USB bridge)."""
    vid = getattr(controller, "vendor_id", None)
    pid = getattr(controller, "product_id", None)
    if vid is None or pid is None:
        return None
    return f"0x{vid:04x}:0x{pid:04x}"


def render_standard(controller, info: dict, empty_note: str = None) -> None:
    """Pretty print the standard HCI information in a table.

    ``empty_note`` overrides the default message shown when no standard HCI
    information could be read (e.g. to explain a bootloader-mode controller)."""
    ident = controller_id(controller)
    table = _kv_table(f"Controller {ident}" if ident else f"Controller {controller}")
    if ident is not None:
        table.add_row("USB vendor:product", ident)
    # SerialController exposes the port/baud it was opened with.
    port = getattr(controller, "_port", None)
    if port is not None:
        baud = getattr(controller, "_baudrate", None)
        table.add_row("Serial port", f"{port} @ {baud}" if baud else str(port))
    if not info:
        table.add_row("HCI", f"[yellow]{empty_note or 'no information could be read'}[/yellow]")
    for key, value in info.items():
        table.add_row(key, str(value))
    console.print(table)


def render_table(title: str, info: dict) -> None:
    """Pretty print a vendor's key/value information (nothing if empty)."""
    if not info:
        return
    table = _kv_table(title)
    for key, value in info.items():
        table.add_row(key, str(value))
    console.print(table)


# --- Vendor plug-in base -----------------------------------------------------

class Vendor:
    """A per-vendor chip/firmware information provider.

    Subclasses set ``vendor_id`` (USB VID they handle), a table ``title``, and
    ``available`` (False when the backing scapy contrib layer is missing, so
    the vendor is skipped). ``gather`` returns a {property: value} dict. A
    vendor may override ``empty_note`` to explain an otherwise-empty standard
    table (e.g. an Intel controller stuck in bootloader mode)."""

    vendor_id = None
    title = "Vendor chip information"
    available = True
    # Name under which this vendor registered colliding VSC bindings (see
    # register_vsc_bindings); set when the vendor shares an OGF 0x3F opcode with
    # another vendor, so process_controller can activate the right bindings while
    # this vendor's info is gathered. None = no colliding opcodes.
    contrib_name = None

    def matches(self, controller, socket) -> bool:
        """Whether this vendor applies to ``controller``.

        Default: match on the Bluetooth chip's USB vendor id. A serial
        controller's vendor id is that of its USB-serial bridge, not the chip,
        so USB-VID vendors never match there. A vendor that can fingerprint the
        chip at runtime (e.g. with a vendor command) overrides this to probe the
        live ``socket`` regardless of transport."""
        if self.vendor_id is None or isinstance(controller, SerialController):
            return False
        return getattr(controller, "vendor_id", None) == self.vendor_id

    def gather(self, socket) -> dict:
        return {}

    def empty_note(self, info: dict, standard: dict):
        return None
