"""Per-vendor firmware-dump routines.

Each module exposes ``dump_firmware(console, socket, file) -> int`` (the number of
bytes written). Vendors identifiable by USB vendor id are registered in
``DUMPERS``; vendors that must fingerprint the chip at runtime -- a serial
controller's USB VID is its USB-serial bridge's, not the chip's -- expose
``AVAILABLE``/``matches(socket)``/``NAME`` and are listed in ``PROBE_DUMPERS``.

To add a vendor, create ``vendors/<name>.py`` and register it below.
"""

from . import barrot, espressif, realtek

# USB vendor id -> (display name, dump routine).
DUMPERS = {
    0x0bda: ("Realtek", realtek.dump_firmware),
    0x33fa: ("Barrot", barrot.dump_firmware),
}

# Dumpers that can't be recognised by USB VID and instead fingerprint the chip at
# runtime with a ``matches(socket)`` probe. Espressif uses its vendor ECHO command.
PROBE_DUMPERS = [module for module in (espressif,) if module.AVAILABLE]
