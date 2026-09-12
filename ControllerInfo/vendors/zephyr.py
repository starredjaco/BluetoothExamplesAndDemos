"""Zephyr / Nordic vendor-specific chip information (USB VID 0x2FE3).

Targets a controller running the **Zephyr** ``bluetooth: hci_usb`` sample -- e.g.
an nRF52840 dongle, which enumerates as USB 2FE3:000B and reports LMP company id
0x05F1 ("The Linux Foundation"). Its vendor commands are the Zephyr VS HCI set
(scapy.contrib.bluetooth_vsc_zephyr); a Nordic SoftDevice-Controller build would
use a different opcode map and is not handled here.

Reads, all unauthenticated:
  - Read Version Info (0xFC01)  -> hardware platform/variant, firmware build
  - Read Build Info   (0xFC08)  -> the Zephyr build string
  - Read Static Addrs (0xFC09)  -> static random address + Identity Root (IR)
  - Read Key Roots    (0xFC0A)  -> Identity Root (IR) + Encryption Root (ER)

The last two disclose the seeds of the BLE key hierarchy to any local HCI client.
"""

from common import Vendor, command_complete, register_vsc_bindings
from scapy.layers.bluetooth import HCI_Command_Hdr, HCI_Event_Command_Complete

try:
    from scapy.contrib.bluetooth_vsc_zephyr import (
        HCI_Cmd_VSC_Zephyr_Read_Version_Info,
        HCI_Cmd_Complete_VSC_Zephyr_Read_Version_Info,
        HCI_Cmd_VSC_Zephyr_Read_Build_Info,
        HCI_Cmd_Complete_VSC_Zephyr_Read_Build_Info,
        HCI_Cmd_VSC_Zephyr_Read_Static_Addresses,
        HCI_Cmd_Complete_VSC_Zephyr_Read_Static_Addresses,
        HCI_Cmd_VSC_Zephyr_Read_Key_Hierarchy_Roots,
        HCI_Cmd_Complete_VSC_Zephyr_Read_Key_Hierarchy_Roots,
    )
    _AVAILABLE = True
    # Read Version Info (0xFC01) shares its opcode with Espressif Read Memory;
    # register it so active_vsc_vendor("zephyr") can make it win while gathering.
    register_vsc_bindings("zephyr", [
        (HCI_Command_Hdr, HCI_Cmd_VSC_Zephyr_Read_Version_Info,
         {"ogf": 0x3F, "ocf": 0x001}),
        (HCI_Event_Command_Complete, HCI_Cmd_Complete_VSC_Zephyr_Read_Version_Info,
         {"opcode": 0xFC01}),
    ])
except ImportError:
    _AVAILABLE = False


def _enum(pkt, field: str) -> str:
    """Render an enum field as 'name (0xNNNN)'."""
    value = getattr(pkt, field)
    name = pkt.get_field(field).i2repr(pkt, value)
    return f"{name} (0x{value:04x})"


class ZephyrVendor(Vendor):
    vendor_id = 0x2FE3
    title = "Zephyr / Nordic chip information"
    available = _AVAILABLE
    contrib_name = "zephyr"

    def gather(self, socket) -> dict:
        info = {}

        resp = command_complete(socket, HCI_Cmd_VSC_Zephyr_Read_Version_Info())
        if resp is not None and HCI_Cmd_Complete_VSC_Zephyr_Read_Version_Info in resp:
            v = resp[HCI_Cmd_Complete_VSC_Zephyr_Read_Version_Info]
            info["HW platform"] = _enum(v, "hw_platform")
            info["HW variant"] = _enum(v, "hw_variant")
            info["FW variant"] = _enum(v, "fw_variant")
            info["FW version"] = f"{v.fw_version}.{v.fw_revision} (build {v.fw_build})"

        resp = command_complete(socket, HCI_Cmd_VSC_Zephyr_Read_Build_Info())
        if resp is not None and HCI_Cmd_Complete_VSC_Zephyr_Read_Build_Info in resp:
            build = bytes(resp[HCI_Cmd_Complete_VSC_Zephyr_Read_Build_Info].build_info)
            info["Build info"] = build.split(b"\x00", 1)[0].decode("utf-8", "replace")

        resp = command_complete(socket, HCI_Cmd_VSC_Zephyr_Read_Static_Addresses())
        if resp is not None and HCI_Cmd_Complete_VSC_Zephyr_Read_Static_Addresses in resp:
            sa = resp[HCI_Cmd_Complete_VSC_Zephyr_Read_Static_Addresses]
            for i, entry in enumerate(sa.addrs):
                suffix = f" #{i}" if len(sa.addrs) > 1 else ""
                info[f"Static address{suffix}"] = entry.addr
                info[f"Identity Root (IR){suffix}"] = bytes(entry.ir).hex()

        resp = command_complete(socket, HCI_Cmd_VSC_Zephyr_Read_Key_Hierarchy_Roots())
        if resp is not None and HCI_Cmd_Complete_VSC_Zephyr_Read_Key_Hierarchy_Roots in resp:
            kr = resp[HCI_Cmd_Complete_VSC_Zephyr_Read_Key_Hierarchy_Roots]
            info["Identity Root (roots)"] = bytes(kr.ir).hex()
            info["Encryption Root (ER)"] = bytes(kr.er).hex()

        return info
