"""Intel vendor-specific chip information (USB VID 0x8087).

Uses scapy.contrib.bluetooth_vsc_intel Read Version (0xFC05, TLV form). An
Intel controller in bootloader/ROM mode answers Read Version but rejects the
standard HCI info commands, so ``empty_note`` explains an empty standard table.
"""

from common import Vendor, command_complete

try:
    from scapy.contrib.bluetooth_vsc_intel import (
        HCI_Cmd_VSC_Intel_Read_Version,
        HCI_Cmd_Complete_VSC_Intel_Read_Version,
        _intel_hw_variant,
        _intel_image_type,
    )
    _AVAILABLE = True
except ImportError:
    _AVAILABLE = False


def _le_int(value: bytes) -> int:
    return int.from_bytes(value, "little") if value else 0


def _bd_addr(value: bytes) -> str:
    return ":".join(f"{b:02x}" for b in reversed(value)) if value else "(unset)"


def _lock_state(value: bytes) -> str:
    return "yes" if value == b"\x01" else "no"


def _decode_tlv(complete) -> dict:
    tl = {t.type: bytes(t.value) for t in complete.tlvs}
    info = {}

    # The hardware variant lives in bits 16..21 of cnvi_bt (TLV 0x12).
    cnvi_bt = _le_int(tl.get(0x12))
    if cnvi_bt:
        hw_variant = (cnvi_bt >> 16) & 0x3f
        name = _intel_hw_variant.get(hw_variant, f"0x{hw_variant:02x}")
        info["Hardware variant"] = f"{name} (0x{hw_variant:02x})"

    if 0x10 in tl:
        info["CNVi TOP"] = f"0x{_le_int(tl[0x10]):08x}"
    if 0x11 in tl:
        info["CNVr TOP"] = f"0x{_le_int(tl[0x11]):08x}"

    if 0x1c in tl:
        img = tl[0x1c][0]
        info["Image type"] = f"{_intel_image_type.get(img, 'unknown')} (0x{img:02x})"

    # Firmware build: timestamp (year.week), then build type and number.
    if 0x1d in tl:
        ts = _le_int(tl[0x1d])
        info["FW timestamp"] = f"{2000 + (ts >> 8)}-ww{ts & 0xff:02d}"
    if 0x1e in tl and 0x1f in tl:
        info["FW build"] = f"type {tl[0x1e][0]}, build {_le_int(tl[0x1f])}"

    if 0x30 in tl:
        info["OTP BD_ADDR"] = _bd_addr(tl[0x30])

    # Secure-boot / lock posture (secure_boot, otp_lock, api_lock, debug_lock).
    posture = [f"{label}={_lock_state(tl[type_id])}"
               for type_id, label in ((0x28, "secure boot"), (0x2a, "OTP lock"),
                                       (0x2b, "API lock"), (0x2c, "debug lock"))
               if type_id in tl]
    if posture:
        info["Lock posture"] = ", ".join(posture)

    return info


class IntelVendor(Vendor):
    vendor_id = 0x8087
    title = "Intel chip information"
    available = _AVAILABLE

    def gather(self, socket) -> dict:
        resp = command_complete(socket, HCI_Cmd_VSC_Intel_Read_Version())
        if resp is None:
            return {}
        if HCI_Cmd_Complete_VSC_Intel_Read_Version in resp:
            return _decode_tlv(resp[HCI_Cmd_Complete_VSC_Intel_Read_Version])
        return {}

    def empty_note(self, info: dict, standard: dict):
        if not standard and "bootloader" in info.get("Image type", ""):
            return ("Controller is in bootloader/ROM mode. Standard HCI "
                    "information is only available once operational firmware "
                    "has been loaded.")
        return None
