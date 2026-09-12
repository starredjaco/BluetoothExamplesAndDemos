"""Barrot vendor-specific chip information (USB VID 0x33FA).

Uses scapy.contrib.bluetooth_vsc_barrot; if that contrib is unavailable the
vendor reports ``available = False`` and is skipped.
"""

from common import Vendor, command_complete

try:
    from scapy.contrib.bluetooth_vsc_barrot import (
        HCI_Cmd_VSC_Barrot,
        HCI_Cmd_VSC_Barrot_Read_Chip_Version,
        HCI_Cmd_Complete_VSC_Barrot_Read_Chip_Version,
        HCI_Cmd_VSC_Barrot_Read_Signature,
        HCI_Cmd_Complete_VSC_Barrot_Read_Signature,
    )
    _AVAILABLE = True
except ImportError:
    _AVAILABLE = False


def _fw_date(value: int) -> str:
    """Decode the Barrot firmware date (decimal YYMMDDHHmm) into a readable
    string, falling back to 'unknown' if it is not a valid date."""
    minute, value = value % 100, value // 100
    hour, value = value % 100, value // 100
    day, value = value % 100, value // 100
    month, value = value % 100, value // 100
    year = 2000 + value % 100
    if 1 <= month <= 12 and 1 <= day <= 31 and hour < 24 and minute < 60:
        return f"{year:04d}-{month:02d}-{day:02d} {hour:02d}:{minute:02d}"
    return "unknown"


class BarrotVendor(Vendor):
    vendor_id = 0x33FA
    title = "Barrot chip information"
    available = _AVAILABLE

    def gather(self, socket) -> dict:
        info = {}

        resp = command_complete(socket, HCI_Cmd_VSC_Barrot() / HCI_Cmd_VSC_Barrot_Read_Chip_Version())
        if resp is not None and HCI_Cmd_Complete_VSC_Barrot_Read_Chip_Version in resp:
            version = resp[HCI_Cmd_Complete_VSC_Barrot_Read_Chip_Version]
            info["Chip model"] = f"BR{version.version:X}"
            info["Config type"] = f"0x{version.config_type:02x}"
            info["Firmware date"] = f"0x{version.fw_date:08x} ({_fw_date(version.fw_date)})"
            info["Flash id"] = f"0x{version.flash_id:04x}"
            info["Features"] = f"0x{version.features:08x}"

        resp = command_complete(socket, HCI_Cmd_VSC_Barrot() / HCI_Cmd_VSC_Barrot_Read_Signature())
        if resp is not None and HCI_Cmd_Complete_VSC_Barrot_Read_Signature in resp:
            info["Signature"] = bytes(resp[HCI_Cmd_Complete_VSC_Barrot_Read_Signature].signature).hex()

        return info
