"""Change the BD_ADDR of a Barrot controller.

Uses the Barrot BD Param vendor command (VSC 0xFC80, sub-command 0x05,
scapy.contrib.bluetooth_vsc_barrot). Targets Barrot controllers (USB VID
0x33FA). The command sets the address and the controller answers with the
address now in effect."""

from rich.console import Console
from scapy.layers.bluetooth import (
    HCI_Hdr,
    HCI_Command_Hdr,
    HCI_Event_Command_Complete,
)

from common import Changer

try:
    from scapy.contrib.bluetooth_vsc_barrot import (
        HCI_Cmd_VSC_Barrot,
        HCI_Cmd_VSC_Barrot_Bd_Param,
    )
    AVAILABLE = True
except ImportError:
    AVAILABLE = False


class BarrotChanger(Changer):
    vendor_id = 0x33FA
    name = "Barrot (BD Param cmd 0x05)"
    available = AVAILABLE

    def write_bd_addr(self, socket, addr: str, console: Console) -> bool:
        """Write ``addr`` using the Barrot BD Param VSC. Returns True on a
        successful Command Complete."""
        pkt = (HCI_Hdr() / HCI_Command_Hdr()
               / HCI_Cmd_VSC_Barrot() / HCI_Cmd_VSC_Barrot_Bd_Param(bd_addr=addr))
        resp = socket.sr1(pkt, verbose=0, timeout=3)
        return (resp is not None
                and HCI_Event_Command_Complete in resp
                and resp[HCI_Event_Command_Complete].status == 0)
