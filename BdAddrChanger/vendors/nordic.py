"""Change the BD_ADDR of a Nordic/Zephyr controller.

Uses the Zephyr Write BD_ADDR vendor command (0xFC06,
scapy.contrib.bluetooth_vsc_zephyr). Targets a controller running Zephyr's
hci_usb sample (e.g. an nRF52840 dongle, USB VID 0x2FE3). The written address is
the controller public address and survives an HCI Reset (until a power cycle)."""

from rich.console import Console
from scapy.layers.bluetooth import (
    HCI_Hdr,
    HCI_Command_Hdr,
    HCI_Event_Command_Complete,
)

from common import Changer

try:
    from scapy.contrib.bluetooth_vsc_zephyr import HCI_Cmd_VSC_Zephyr_Write_BD_Addr
    AVAILABLE = True
except ImportError:
    AVAILABLE = False


class NordicChanger(Changer):
    vendor_id = 0x2FE3
    name = "Nordic/Zephyr (Write BD_ADDR 0xFC06)"
    available = AVAILABLE

    def write_bd_addr(self, socket, addr: str, console: Console) -> bool:
        """Write ``addr`` using the Zephyr Write BD_ADDR VSC. Returns True on a
        successful Command Complete."""
        pkt = HCI_Hdr() / HCI_Command_Hdr() / HCI_Cmd_VSC_Zephyr_Write_BD_Addr(bd_addr=addr)
        resp = socket.sr1(pkt, verbose=0, timeout=3)
        return (resp is not None
                and HCI_Event_Command_Complete in resp
                and resp[HCI_Event_Command_Complete].status == 0)
