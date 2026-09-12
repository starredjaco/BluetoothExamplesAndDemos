"""Espressif ESP32-family vendor chip information.

Unlike the other vendors here, an Espressif HCI controller cannot be recognised
by its USB vendor id: these boards speak HCI over a UART (or the ESP32-C3's
native USB-Serial/JTAG), so the enumerated VID belongs to the USB-serial bridge,
not the chip -- and even by LMP company id the classic ESP32 reports RivieraWaves
(0x0060), not Espressif. Instead we fingerprint the chip at runtime with the
Espressif vendor ECHO command (0xFC81): the controller echoes the payload byte
back. This works for the classic ESP32 (dual-mode) and the BLE-only ESP32-C3,
over any transport.

The ECHO command -- and the rest of the VS set -- is only registered when the
firmware enables Espressif's vendor commands; a stock controller-only HCI-UART
build leaves them dormant (every OGF 0x3F opcode answers 0x01). See
``vendors/espressif/esp-hci-uart-vsc-enablement.md`` for how they are enabled.

Reads (all unauthenticated), when the VS set is enabled:
  - ECHO (0xFC81)                     -> fingerprint / liveness of the VS path
  - RD_NEW_CONN_TX_PWR_LVL (0xFD92)  \
  - RD_PAGE_TX_PWR_LVL     (0xFD94)   } BR/EDR TX-power levels (classic ESP32);
  - RD_PSCAN_TX_PWR_LVL    (0xFD96)   } their presence also tells a dual-mode
  - RD_INQ_TX_PWR_LVL      (0xFD98)  /  ESP32 from the BLE-only C3.
"""

from common import Vendor, command_complete, register_vsc_bindings
from scapy.layers.bluetooth import HCI_Command_Hdr, HCI_Event_Command_Complete

try:
    from scapy.contrib.bluetooth_vsc_espressif import (
        HCI_Cmd_VSC_Espressif_Common_Echo,
        HCI_Cmd_Complete_VSC_Espressif_Common_Echo,
        HCI_Cmd_VSC_Espressif_Rd_New_Conn_Tx_Pwr_Lvl,
        HCI_Cmd_Complete_VSC_Espressif_Rd_New_Conn_Tx_Pwr_Lvl,
        HCI_Cmd_VSC_Espressif_Rd_Page_Tx_Pwr_Lvl,
        HCI_Cmd_Complete_VSC_Espressif_Rd_Page_Tx_Pwr_Lvl,
        HCI_Cmd_VSC_Espressif_Rd_Pscan_Tx_Pwr_Lvl,
        HCI_Cmd_Complete_VSC_Espressif_Rd_Pscan_Tx_Pwr_Lvl,
        HCI_Cmd_VSC_Espressif_Rd_Inq_Tx_Pwr_Lvl,
        HCI_Cmd_Complete_VSC_Espressif_Rd_Inq_Tx_Pwr_Lvl,
        HCI_Cmd_VSC_Espressif_Rd_Mem,
        HCI_Cmd_Complete_VSC_Espressif_Rd_Mem,
        HCI_Cmd_VSC_Espressif_Wr_Mem,
    )
    _AVAILABLE = True
    # Read/Write Memory (0xFC01/0xFC02) share their opcodes with Zephyr's Read
    # Version Info / Read Supported Commands. This plugin doesn't read them, but
    # importing the contrib registers the bindings that would shadow Zephyr, so
    # register them for active_vsc_vendor to swap out while querying a Nordic.
    register_vsc_bindings("espressif", [
        (HCI_Command_Hdr, HCI_Cmd_VSC_Espressif_Rd_Mem, {"ogf": 0x3F, "ocf": 0x001}),
        (HCI_Event_Command_Complete, HCI_Cmd_Complete_VSC_Espressif_Rd_Mem,
         {"opcode": 0xFC01}),
        (HCI_Command_Hdr, HCI_Cmd_VSC_Espressif_Wr_Mem, {"ogf": 0x3F, "ocf": 0x002}),
    ])
except ImportError:
    _AVAILABLE = False

# Arbitrary non-zero byte used to prove the ECHO round-trip.
_ECHO_PROBE = 0x2A


class EspressifVendor(Vendor):
    vendor_id = None  # not identifiable by USB VID -- detected via the ECHO probe
    title = "Espressif ESP32 chip information"
    available = _AVAILABLE
    contrib_name = "espressif"

    def matches(self, controller, socket) -> bool:
        """Fingerprint via the ESP vendor ECHO command (any transport)."""
        if not self.available:
            return False
        resp = command_complete(socket, HCI_Cmd_VSC_Espressif_Common_Echo(echo=_ECHO_PROBE))
        return (resp is not None
                and HCI_Cmd_Complete_VSC_Espressif_Common_Echo in resp
                and resp[HCI_Cmd_Complete_VSC_Espressif_Common_Echo].echo == _ECHO_PROBE)

    def gather(self, socket) -> dict:
        info = {"Vendor ECHO (0xFC81)": f"0x{_ECHO_PROBE:02x} echoed back "
                                        "(Espressif VS commands enabled)"}

        # The BR/EDR TX-power reads exist only on the classic (dual-mode) ESP32;
        # the BLE-only C3 answers 0x01 to them, so their presence reports the
        # controller class. tx_power values are Espressif power-level indices.
        power = {}
        resp = command_complete(socket, HCI_Cmd_VSC_Espressif_Rd_New_Conn_Tx_Pwr_Lvl())
        if resp is not None and HCI_Cmd_Complete_VSC_Espressif_Rd_New_Conn_Tx_Pwr_Lvl in resp:
            p = resp[HCI_Cmd_Complete_VSC_Espressif_Rd_New_Conn_Tx_Pwr_Lvl]
            power["New-connection TX power (level)"] = f"min {p.tx_power_min}, max {p.tx_power_max}"

        for cmd, complete, label in [
            (HCI_Cmd_VSC_Espressif_Rd_Page_Tx_Pwr_Lvl,
             HCI_Cmd_Complete_VSC_Espressif_Rd_Page_Tx_Pwr_Lvl, "Page TX power (level)"),
            (HCI_Cmd_VSC_Espressif_Rd_Pscan_Tx_Pwr_Lvl,
             HCI_Cmd_Complete_VSC_Espressif_Rd_Pscan_Tx_Pwr_Lvl, "Page-scan TX power (level)"),
            (HCI_Cmd_VSC_Espressif_Rd_Inq_Tx_Pwr_Lvl,
             HCI_Cmd_Complete_VSC_Espressif_Rd_Inq_Tx_Pwr_Lvl, "Inquiry TX power (level)"),
        ]:
            resp = command_complete(socket, cmd())
            if resp is not None and complete in resp:
                power[label] = str(resp[complete].tx_power)

        info["Controller class"] = ("dual-mode (BR/EDR + BLE)" if power
                                    else "BLE-only (no BR/EDR VS reads)")
        info.update(power)
        return info
