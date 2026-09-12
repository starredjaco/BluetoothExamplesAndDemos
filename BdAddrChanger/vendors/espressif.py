"""Change the BD_ADDR of a classic ESP32 controller.

Uses the legacy ROM SET_BD_ADDR vendor command (0xFC32,
``HCI_DBG_SET_BD_ADDR_CMD_OPCODE``; scapy.contrib.bluetooth_vsc_espressif): a
6-byte little-endian address, returns status only.

**Dual-mode caveat.** 0xFC32 calls ``llm_util_set_public_addr`` -- it sets the
**BLE public address**. On a dual-mode (BR/EDR + BLE) controller the standard
``Read_BD_ADDR`` (0x1009) returns the separate **BR/EDR** device address, so the
change is real but is *not* reflected by ``Read_BD_ADDR``. Verified live on
v5.4.0 by writing a unique address and finding it in controller RAM via the
Read-Memory VSC. To see the change through ``Read_BD_ADDR``, run a BLE-only
controller (``ESP_BT_MODE_BLE``).

Unlike the USB-VID changers here, an ESP32 speaks HCI over a UART (or the C3's
native USB-Serial/JTAG), so it is fingerprinted at runtime with the ESP vendor
ECHO command (0xFC81) rather than by USB VID. Only the classic ESP32 has ROM
debug commands, so ``matches`` will still return True on a C3 (ECHO works there)
but the actual Set-MAC write will fail on anything that lacks 0xFC32.

**Availability.** 0xFC32 is one of the undocumented ESP32 debug commands
(CVE-2025-27840). It exists only on the ORIGINAL ESP32 and only on ESP-IDF
releases *before* the fix; it was removed in v5.4.1 / v5.3.3 / v5.2.6 / v5.1.7 /
v5.0.9 and v6.0+ (advisory AR2025-004), where it answers 0x01 Unknown HCI
Command. To exercise this changer, flash the ESP32 with a pre-fix IDF
(e.g. v5.4.0, or any v5.3.2 / v5.2.5 / v5.1.6 / v5.0.8 or earlier, or v4.x).
"""

from rich.console import Console
from scapy.layers.bluetooth import (
    HCI_Hdr,
    HCI_Command_Hdr,
    HCI_Event_Command_Complete,
)

from common import Changer

try:
    from scapy.contrib.bluetooth_vsc_espressif import (
        HCI_Cmd_VSC_Espressif_Common_Echo,
        HCI_Cmd_Complete_VSC_Espressif_Common_Echo,
        HCI_Cmd_VSC_Espressif_Set_Mac,
    )
    AVAILABLE = True
except ImportError:
    AVAILABLE = False

# Arbitrary non-zero byte used to prove the ECHO round-trip.
_ECHO_PROBE = 0x2A


class EspressifChanger(Changer):
    # Detected at runtime via the ECHO probe, not by USB vendor id.
    vendor_id = None
    name = "Espressif ESP32 (SET_BD_ADDR 0xFC32 -> BLE public addr; pre-fix IDF only)"
    available = AVAILABLE

    def matches(self, controller, socket) -> bool:
        """Fingerprint an Espressif controller via its vendor ECHO command."""
        if not self.available:
            return False
        resp = socket.sr1(
            HCI_Hdr() / HCI_Command_Hdr()
            / HCI_Cmd_VSC_Espressif_Common_Echo(echo=_ECHO_PROBE),
            verbose=0, timeout=3)
        return (resp is not None
                and HCI_Cmd_Complete_VSC_Espressif_Common_Echo in resp
                and resp[HCI_Event_Command_Complete].status == 0
                and resp[HCI_Cmd_Complete_VSC_Espressif_Common_Echo].echo == _ECHO_PROBE)

    def write_bd_addr(self, socket, addr: str, console: Console) -> bool:
        """Write ``addr`` using the ESP32 Set-MAC ROM VSC (0xFC32). Returns True on
        a successful Command Complete (status 0). Answers 0x01 -> False on any IDF
        that has the fix, or on a non-ESP32 chip that never had the command."""
        console.log("[dim]0xFC32 sets the BLE public address; on a dual-mode build "
                    "the standard Read_BD_ADDR still returns the BR/EDR address, so "
                    "the change may not be visible below.[/dim]")
        pkt = HCI_Hdr() / HCI_Command_Hdr() / HCI_Cmd_VSC_Espressif_Set_Mac(bd_addr=addr)
        resp = socket.sr1(pkt, verbose=0, timeout=3)
        return (resp is not None
                and HCI_Event_Command_Complete in resp
                and resp[HCI_Event_Command_Complete].status == 0)
